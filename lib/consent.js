// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const qstamp = require('@quantovainc/qstamp');
const native = require('./native');
const F = require('./format');

function requireProvingQstamp() {
  const dir = path.dirname(require.resolve('@quantovainc/qstamp/package.json'));
  const [major, minor] = String(require(path.join(dir, 'package.json')).version).split('.').map((n) => parseInt(n, 10));
  const released = major > 0 || (major === 0 && minor >= 3);
  const staged = fs.existsSync(path.join(dir, 'lib', 'deadline.js')) && fs.existsSync(path.join(dir, 'lib', 'finality.js'));
  if (typeof qstamp.isProven !== 'function' || !(released || staged)) {
    throw new Error('the installed Qstamp is older than 0.3.0 and cannot prove anchors');
  }
}
requireProvingQstamp();

function own(value) {
  if (value === undefined || value === null) return Object.create(null);
  if (typeof value !== 'object' || Array.isArray(value) || ArrayBuffer.isView(value) || value instanceof ArrayBuffer) F.reject('the options are a plain object');
  return Object.assign(Object.create(null), value);
}

function requireSeed(key) {
  if (!((ArrayBuffer.isView(key) && key instanceof Uint8Array) && key.length === 32 && key.buffer instanceof ArrayBuffer)) {
    F.reject('a signing key is a 32 byte Uint8Array seed, kept by its holder and wiped with fill(0) after use');
  }
  if (new Set(key).size < 13) F.reject('a signing key made of too few different byte values is refused, draw one with generateKey');
  return key;
}

function randomHex(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return Buffer.from(b).toString('hex');
}

const HIDDEN = 'SecretKey [hidden]';

class SecretKey extends Uint8Array {
  static get [Symbol.species]() {
    return Uint8Array;
  }

  toJSON() {
    return HIDDEN;
  }

  toString() {
    return HIDDEN;
  }

  toLocaleString() {
    return HIDDEN;
  }

  [require('util').inspect.custom]() {
    return HIDDEN;
  }
}

function generateKey() {
  const seed = new SecretKey(32);
  globalThis.crypto.getRandomValues(seed);
  if (seed.every((b) => b === 0)) throw new Error('the secure random source returned only zeros');
  return seed;
}

function publicKey(key) {
  return native.publicKey(requireSeed(key));
}

function keyId(key) {
  return F.keyIdOf(publicKey(key));
}

function describeKey(key) {
  const pk = publicKey(key);
  return { format: 'qconsent-key/1', algorithm: F.ALGORITHM, id: F.keyIdOf(pk), publicKey: Buffer.from(pk).toString('base64') };
}

function keyIdOf(party, what) {
  if (typeof party === 'string' && /^[0-9a-f]{64}$/.test(party)) return party;
  if ((ArrayBuffer.isView(party) && party instanceof Uint8Array)) return F.keyIdOf(party);
  if (party && typeof party === 'object' && party.format === 'qconsent-key/1' && typeof party.publicKey === 'string') {
    const raw = Buffer.from(party.publicKey, 'base64');
    if (raw.toString('base64') !== party.publicKey) F.reject('the ' + what + ' public key is not canonical base64');
    const id = F.keyIdOf(raw);
    if (party.id !== id) F.reject('the ' + what + ' key description names an id that does not match its public key');
    return id;
  }
  F.reject(what + ' is a qconsent-key/1 description, a public key or a 64 character key id');
}

function subjectRef(secret, identity) {
  return F.subjectRefOf(secret, identity);
}

function nowIso() {
  return new Date().toISOString();
}

function seal(type, key, statement) {
  const pk = publicKey(key);
  const id = F.keyIdOf(pk);
  let plain;
  try {
    plain = F.plainCopy(statement);
  } catch (e) {
    F.reject('the statement is not plain data');
  }
  const problem = F.statementProblem(type, plain);
  if (problem) F.reject(problem);
  const message = F.payload(type, plain);
  const rnd = new Uint8Array(32);
  globalThis.crypto.getRandomValues(rnd);
  let signature;
  try {
    signature = native.sign(key, message, rnd);
  } finally {
    rnd.fill(0);
  }
  if (!native.verify(pk, message, signature)) throw new Error('the new signature did not verify, nothing was produced');
  return {
    format: F.FORMAT,
    type,
    algorithm: F.ALGORITHM,
    signer: { id, publicKey: Buffer.from(pk).toString('base64') },
    statement: JSON.parse(JSON.stringify(plain)),
    signature: Buffer.from(signature).toString('base64'),
  };
}

function grant(options) {
  if (!options || typeof options !== 'object') F.reject('grant needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.validUntil === undefined) F.reject('validUntil is required, a consent never lasts indefinitely');
  if (options.grantee === undefined) F.reject('grantee is required, the key of the party the patient is granting access to');
  if (!Array.isArray(options.purposes)) F.reject('purposes is a list of the reasons the data may be used');
  if (!Array.isArray(options.categories)) F.reject('categories is a list of the kinds of data covered');
  const statement = {
    consentId: randomHex(16),
    subjectRef: options.subjectRef === undefined ? '' : options.subjectRef,
    patientKeyId: keyId(options.key),
    granteeKeyId: keyIdOf(options.grantee, 'grantee'),
    granteeLabel: options.granteeLabel === undefined ? '' : options.granteeLabel,
    purposes: options.purposes,
    categories: options.categories,
    validFrom: options.validFrom === undefined ? nowIso() : options.validFrom,
    validUntil: options.validUntil,
    grantedAt: nowIso(),
    note: options.note === undefined ? '' : options.note,
  };
  return seal('consent', options.key, statement);
}

function badConsent(message) {
  const e = new Error(message);
  e.code = 'QCONSENT_INVALID_CONSENT';
  throw e;
}

function consentOf(envelope) {
  const p = F.parse(envelope);
  if (p.type !== 'consent') badConsent('the envelope is not a consent');
  if (p.signerId !== F.keyIdOf(p.publicKey) || p.signerId !== p.statement.patientKeyId) badConsent('the consent is not signed by the patient it names');
  if (!native.verify(p.publicKey, F.encoded(p), p.signature)) badConsent('the consent signature does not verify');
  return p;
}

function acknowledge(options) {
  if (!options || typeof options !== 'object') F.reject('acknowledge needs options');
  options = own(options);
  requireSeed(options.key);
  const c = consentOf(options.consent);
  const granteeKeyId = keyId(options.key);
  if (granteeKeyId !== c.statement.granteeKeyId) F.reject('only the grantee named in the consent can acknowledge it');
  return seal('acknowledge', options.key, {
    consentId: c.statement.consentId,
    consentRef: F.refOf(c),
    granteeKeyId,
    acknowledgedAt: options.acknowledgedAt === undefined ? nowIso() : options.acknowledgedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

function revoke(options) {
  if (!options || typeof options !== 'object') F.reject('revoke needs options');
  options = own(options);
  requireSeed(options.key);
  const c = consentOf(options.consent);
  const patientKeyId = keyId(options.key);
  if (patientKeyId !== c.statement.patientKeyId) F.reject('only the patient that granted the consent can revoke it');
  return seal('revoke', options.key, {
    consentId: c.statement.consentId,
    consentRef: F.refOf(c),
    patientKeyId,
    revokedAt: options.revokedAt === undefined ? nowIso() : options.revokedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

function revokedBy(c, revocations) {
  if (revocations === undefined) return null;
  if (!Array.isArray(revocations) || revocations.length > 500) F.reject('revocations is a list of at most 500 envelopes');
  const ref = F.refOf(c);
  for (const env of revocations) {
    let r;
    try {
      r = F.parse(env);
    } catch (e) {
      continue;
    }
    if (r.type !== 'revoke' || r.statement.consentId !== c.statement.consentId || r.statement.consentRef !== ref) continue;
    if (r.statement.patientKeyId !== c.statement.patientKeyId || r.signerId !== c.statement.patientKeyId || r.signerId !== F.keyIdOf(r.publicKey)) continue;
    if (native.verify(r.publicKey, F.encoded(r), r.signature)) return r.statement.revokedAt;
  }
  return null;
}

const CLOCK_SKEW_MS = 5 * 60 * 1000;
const ENDPOINT_OPTIONS = ['network', 'rpc', 'client', 'clients', 'trustSingleEndpoint', 'trustCustomEndpoints', 'allowLoopback', 'endpointAllowList', 'clockSlackMs'];
const DEADLINE_HORIZON_S = 3600;
const DEADLINE_STEPS_S = [3600, 600, 60];
const DEADLINE_MARGIN_S = 300;

function strictOf(opts) {
  if (opts.strict === undefined) return true;
  if (typeof opts.strict !== 'boolean') F.reject('strict is true or false');
  return opts.strict;
}

function endpointOptions(opts) {
  const out = Object.create(null);
  for (const k of ENDPOINT_OPTIONS) if (opts[k] !== undefined) out[k] = opts[k];
  return out;
}

async function chainClock(opts, strict) {
  if (strict !== false && strictOf(opts) && opts.trustSingleEndpoint === true) {
    F.reject('strict mode takes the time of the chain only from at least two independent endpoints and refuses trustSingleEndpoint, set strict to false to rely on one endpoint');
  }
  try {
    return await qstamp.chainTime(endpointOptions(opts));
  } catch (e) {
    const err = new Error('the chain time could not be established, so no decision was made, ' + ((e && e.message) || 'unknown error'));
    err.code = 'QCONSENT_NO_CHAIN_TIME';
    throw err;
  }
}

function decide(c, when, revokedAt, grantee) {
  const reasons = [];
  const st = c.statement;
  if (Math.min(when.early, when.claimed) < Date.parse(st.validFrom)) reasons.push('the consent is not yet in force');
  if (Math.max(when.late, when.claimed) > Date.parse(st.validUntil)) reasons.push('the consent has expired');
  if (revokedAt !== null && revokedAt !== undefined && Date.parse(revokedAt) <= when.claimed) reasons.push('the patient has revoked this consent');
  if (grantee !== undefined && grantee !== st.granteeKeyId) reasons.push('this consent was granted to a different grantee');
  return { active: reasons.length === 0, reasons };
}

async function status(consent, options) {
  const opts = own(options);
  const c = consentOf(consent);
  if (opts.at !== undefined) {
    const tp = F.timeProblem(opts.at, 'at');
    if (tp) F.reject(tp);
  }
  let grantee;
  if (opts.granteeKeyId !== undefined) grantee = keyIdOf(opts.granteeKeyId, 'granteeKeyId');
  const clock = await chainClock(opts);
  let at = new Date(clock.chainMs).toISOString();
  let when = { early: clock.early, late: clock.late, claimed: clock.chainMs };
  if (opts.at !== undefined) {
    const ms = Date.parse(opts.at);
    if (ms < clock.early - CLOCK_SKEW_MS || ms > clock.late + CLOCK_SKEW_MS) {
      F.reject('at must be within five minutes of the time of the chain, ' + at + ', a decision is never made for another time');
    }
    at = opts.at;
    when = { early: Math.min(clock.early, ms), late: Math.max(clock.late, ms), claimed: ms };
  }
  const revokedAt = revokedBy(c, opts.revocations);
  const out = decide(c, when, revokedAt, grantee);
  return Object.assign(out, {
    consentId: c.statement.consentId,
    consentRef: F.refOf(c),
    patientKeyId: c.statement.patientKeyId,
    granteeKeyId: c.statement.granteeKeyId,
    purposes: c.statement.purposes.slice(),
    categories: c.statement.categories.slice(),
    validFrom: c.statement.validFrom,
    validUntil: c.statement.validUntil,
    revokedAt: revokedAt === null ? null : revokedAt,
    at,
    atSupplied: opts.at !== undefined,
    chainTime: new Date(clock.chainMs).toISOString(),
  });
}

function untilOf(c) {
  return Math.floor(Date.parse(c.statement.validUntil) / 1000);
}

function deadlineFor(expiry, nowS) {
  const grid = Math.ceil((nowS + DEADLINE_HORIZON_S) / DEADLINE_HORIZON_S) * DEADLINE_HORIZON_S;
  if (grid <= expiry) return grid;
  for (const step of DEADLINE_STEPS_S) {
    const d = Math.floor(expiry / step) * step;
    if (d >= nowS + DEADLINE_MARGIN_S) return d;
  }
  return expiry;
}

function anchorBatch(envelopes) {
  const list = Array.isArray(envelopes) ? envelopes : [envelopes];
  if (list.length === 0) F.reject('anchor needs at least one envelope');
  const parsed = list.map((e) => {
    const p = F.parse(e);
    if (p.anchor !== undefined) F.reject('an envelope is already anchored');
    if (p.signerId !== F.keyIdOf(p.publicKey)) F.reject('an envelope names a signer id that does not match its public key');
    if (!native.verify(p.publicKey, F.encoded(p), p.signature)) F.reject('an envelope carries a signature that does not verify');
    return p;
  });
  const consents = parsed.filter((p) => p.type === 'consent');
  const until = consents.length === parsed.length && consents.length > 0 ? Math.min(...consents.map(untilOf)) : undefined;
  return { list, parsed, until };
}

function attach(list, receipts) {
  if (!Array.isArray(receipts) || receipts.length !== list.length) throw new Error('the anchoring returned an unexpected number of receipts');
  return list.map((e, i) => Object.assign({}, e, { anchor: receipts[i] }));
}

async function anchor(envelopes, options) {
  if (!options || typeof options !== 'object') F.reject('anchor needs the stamping options of a funded Quantova account');
  options = own(options);
  const { list, parsed, until } = anchorBatch(envelopes);
  const records = parsed.map((p) => ({ alg: 'sha3-256', digest: F.anchorDigest(p) }));
  const stampOptions = Object.assign(own(options), { records, kind: F.KIND });
  delete stampOptions.strict;
  if (until !== undefined) {
    const clock = await chainClock(options, false);
    stampOptions.until = deadlineFor(until, Math.ceil(clock.late / 1000));
  } else {
    delete stampOptions.until;
  }
  return attach(list, await qstamp.stamp(stampOptions));
}

async function complete(envelopes, pending, options) {
  const opts = own(options);
  const plain = (Array.isArray(envelopes) ? envelopes : [envelopes]).map((e) => {
    let c;
    try {
      c = F.plainCopy(e);
    } catch (err) {
      return F.reject('an envelope is not plain data');
    }
    if (c && typeof c === 'object' && !Array.isArray(c)) delete c.anchor;
    return c;
  });
  const { list, parsed, until } = anchorBatch(plain);
  let p;
  try {
    p = F.plainCopy(pending);
  } catch (e) {
    F.reject('the pending stamp is not plain data');
  }
  if (!p || typeof p !== 'object' || !Array.isArray(p.records) || p.records.length !== parsed.length || String(p.kind) !== String(F.KIND)) {
    F.reject('the pending stamp does not belong to these envelopes');
  }
  if (until === undefined ? p.until !== undefined : (!Number.isSafeInteger(p.until) || p.until > until)) {
    F.reject('the pending stamp does not carry a deadline at or before the expiry of the consents these records rely on');
  }
  parsed.forEach((c, i) => {
    const r = p.records[i];
    if (!r || r.alg !== 'sha3-256' || r.digest !== F.anchorDigest(c).toString('hex')) F.reject('the pending stamp does not belong to these envelopes, or they are in another order');
  });
  const completeOptions = own(opts);
  delete completeOptions.strict;
  return attach(list, await qstamp.complete(p, completeOptions));
}

const OPTIONS_OF = {
  grant: ['key', 'grantee', 'granteeLabel', 'purposes', 'categories', 'validFrom', 'validUntil', 'subjectRef', 'note'],
  acknowledge: ['key', 'consent', 'acknowledgedAt', 'note'],
  revoke: ['key', 'consent', 'revokedAt', 'note'],
  status: ['at', 'granteeKeyId', 'revocations', 'network', 'rpc', 'client', 'clients', 'trustSingleEndpoint', 'trustCustomEndpoints', 'allowLoopback', 'endpointAllowList', 'clockSlackMs', 'strict'],
  anchor: ['allowLoopback', 'client', 'clients', 'clockSlackMs', 'deadlineMs', 'endpointAllowList', 'index', 'maxFee', 'meter', 'network', 'onPending', 'rpc', 'seed', 'signal', 'strict', 'timeoutMs', 'trustCustomEndpoints', 'trustSingleEndpoint', 'until'],
};

function onlyKnown(name, options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options) || ArrayBuffer.isView(options)) return;
  const unknown = Object.keys(options).find((k) => !OPTIONS_OF[name].includes(k));
  if (unknown !== undefined) F.reject('the option ' + unknown.replace(/[^A-Za-z0-9_]/g, '?').slice(0, 40) + ' is not an option of ' + name + ', so nothing was signed');
}

function strict(name, fn, at, isAsync) {
  return function strictly(...args) {
    try {
      onlyKnown(name, args[at]);
    } catch (e) {
      if (isAsync) return Promise.reject(e);
      throw e;
    }
    return fn.apply(this, args);
  };
}

module.exports = {
  own, generateKey, publicKey, keyId, describeKey, subjectRef, grant, acknowledge, revoke, consentOf, status, anchor, complete, untilOf, chainClock, endpointOptions, strictOf, deadlineFor,
};
Object.assign(module.exports, {
  grant: strict('grant', grant, 0, false),
  acknowledge: strict('acknowledge', acknowledge, 0, false),
  revoke: strict('revoke', revoke, 0, false),
  status: strict('status', status, 1, true),
  anchor: strict('anchor', anchor, 1, true),
});
