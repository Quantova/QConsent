// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const { performance } = require('perf_hooks');
const qstamp = require('@quantovainc/qstamp');
const native = require('./native');
const F = require('./format');
const { own, untilOf, chainClock, strictOf } = require('./consent');

const CLOCK_SKEW_MS = 5 * 60 * 1000;
const LIST_MAX = 500;
const PASS = ['rpc', 'client', 'clients', 'contract', 'trustCustomContract', 'trustSingleEndpoint', 'trustCustomEndpoints', 'allowLoopback', 'endpointAllowList', 'expectedSender'];
const CLAIMED_TIME = { consent: 'grantedAt', acknowledge: 'acknowledgedAt', revoke: 'revokedAt' };

function plain(text) {
  return String(text).replace(/:\s+/g, ', ').replace(/;\s*/g, ', ').slice(0, 300);
}

function statusOf(checks) {
  const open = checks.filter((c) => !c.ok);
  if (open.some((c) => !c.transport && !c.indeterminate && !c.unproven)) return 'invalid';
  if (open.some((c) => c.transport || c.indeterminate)) return 'indeterminate';
  if (open.length) return 'unproven';
  return 'valid';
}

function recorder() {
  const checks = [];
  const add = (name, ok, detail, transport, indeterminate, unproven) => checks.push({ name, ok: !!ok, detail: plain(detail), transport: !!transport, indeterminate: !!indeterminate, unproven: !!unproven });
  return { checks, add };
}

function provenOf(result) {
  if (!result || (result.status !== 'valid' && result.status !== 'unproven')) return false;
  return typeof qstamp.isProven === 'function' && qstamp.isProven(result) === true;
}

function finish(checks, extra) {
  const status = statusOf(checks);
  return Object.assign({ valid: status === 'valid', status }, extra, { checks: checks.map((c) => Object.assign({}, c)) }, { valid: status === 'valid', status });
}

function anchorOptions(opts) {
  const out = Object.create(null);
  for (const k of PASS) if (opts[k] !== undefined) out[k] = opts[k];
  return out;
}

function networkProblem(opts) {
  if (opts.network === 'custom') return opts.trustCustomEndpoints === true ? null : 'network custom needs trustCustomEndpoints, it accepts anchors on any chain the endpoints name';
  if (typeof opts.network !== 'string' || !Object.prototype.hasOwnProperty.call(qstamp.NETWORKS, opts.network)) return 'network is required and names the network the records were anchored on, one of ' + Object.keys(qstamp.NETWORKS).concat(['custom']).join(', ');
  return null;
}

function onNetwork(receipt, opts) {
  if (opts.network === 'custom') return true;
  const net = qstamp.NETWORKS[opts.network];
  return !!receipt.chain && receipt.chain.id === net.chainId && receipt.chain.genesis === net.genesis;
}

function clockOptions(opts) {
  if (opts.network !== 'custom') return opts;
  const out = Object.assign(Object.create(null), opts);
  delete out.network;
  return out;
}

function signatureOk(p) {
  return p.signerId === F.keyIdOf(p.publicKey) && native.verify(p.publicKey, F.encoded(p), p.signature);
}

function identity(p) {
  return F.anchorDigest(p).toString('hex');
}

function strictlyAfter(a, b) {
  if (a.chain === b.chain) {
    if (a.height !== b.height) return a.height > b.height;
    return a.tx === b.tx && a.index > b.index;
  }
  return a.ms > b.ms;
}

function earlier(a, b) {
  if (!a) return b;
  if (!b) return a;
  return strictlyAfter(a, b) ? b : a;
}

function iso(pos) {
  return new Date(pos.ms).toISOString();
}

const NET = Symbol('endpoints');
const DEADLINE = Symbol('deadline');
const DEFAULT_ANCHOR_DELAY_S = 24 * 60 * 60;
const ANCHOR_DELAY_MAX_S = 366 * 24 * 60 * 60;
const DEFAULT_DEADLINE_MS = 120000;
const DEADLINE_MAX_MS = 600000;

function deadlineOf(opts) {
  if (opts.deadlineMs === undefined) return DEFAULT_DEADLINE_MS;
  const v = opts.deadlineMs;
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 1 || v > DEADLINE_MAX_MS) F.reject('deadlineMs is a whole number of milliseconds from 1 to ' + DEADLINE_MAX_MS);
  return v;
}

function timeUp(opts) {
  return opts[DEADLINE] !== undefined && performance.now() >= opts[DEADLINE];
}

function delayOf(opts) {
  if (opts.maxAnchorDelay === undefined) return DEFAULT_ANCHOR_DELAY_S * 1000;
  const v = opts.maxAnchorDelay;
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 60 || v > ANCHOR_DELAY_MAX_S) F.reject('maxAnchorDelay is a whole number of seconds from 60 to ' + ANCHOR_DELAY_MAX_S);
  return v * 1000;
}

function noteEndpoints(opts, result) {
  const net = opts[NET];
  if (!net || !(result.endpoints || []).length) return;
  for (const e of result.endpoints) net.endpoints.add(e);
  net.official = net.official !== false && result.officialEndpoints === true;
}

async function checkAnchor(p, opts, add, label, until) {
  const receipt = p.anchor;
  if (receipt === undefined) return null;
  try {
    if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) {
      add(label, false, 'the anchor is not a Qstamp receipt');
      return null;
    }
    if (until !== undefined && (!Number.isSafeInteger(receipt.until) || receipt.until > until)) {
      add(label, false, 'the consent was not anchored through the stamp entry that makes the chain refuse it after the consent expires');
      return null;
    }
    if (receipt.kind !== String(F.KIND)) {
      add(label, false, 'the anchor was not recorded under the QConsent record kind');
      return null;
    }
    if (!onNetwork(receipt, opts)) {
      add(label, false, 'the anchor was recorded on another network than ' + opts.network);
      return null;
    }
    if (timeUp(opts)) {
      add(label + ' confirmed', false, 'the anchor was not checked, the verification reached its time limit, so it is treated as not anchored', true, true);
      return null;
    }
    const result = await qstamp.verify(receipt, Object.assign(anchorOptions(opts), { digest: F.anchorDigest(p) }));
    noteEndpoints(opts, result);
    const confirmed = result.status === 'valid' || result.status === 'unproven';
    const proven = provenOf(result);
    for (const c of result.checks) {
      if (proven && !c.ok) continue;
      add(label + ' ' + c.name, c.ok, c.detail, confirmed ? false : c.transport, false, confirmed && !c.ok);
    }
    if (!confirmed) {
      if (result.status === 'invalid') {
        if (!result.checks.some((c) => !c.ok && !c.transport)) add(label, false, 'the anchor was refuted');
      } else {
        add(label + ' confirmed', false, 'the anchor was neither confirmed nor refuted, so it is treated as not anchored', true, true);
      }
      return null;
    }
    if (!proven) {
      const strict = strictOf(opts);
      if (!result.checks.some((c) => !c.ok)) add(label + ' proof', false, 'the anchor was confirmed only by endpoints that are not pinned independent operators of the network, so it is not proven' + (strict ? ' and is treated as not anchored' : ''), false, false, true);
      if (strict) return null;
    }
    const position = {
      ms: receipt.anchor.time * 1000,
      height: receipt.anchor.height,
      tx: receipt.anchor.tx,
      index: receipt.proof.index,
      chain: receipt.chain.id + '/' + receipt.chain.genesis,
    };
    const claimed = Date.parse(p.statement[CLAIMED_TIME[p.type]]);
    if (claimed > position.ms + CLOCK_SKEW_MS) {
      add(label + ' time', false, 'the claimed time is later than the anchor time ' + iso(position));
      return null;
    }
    const delayMs = delayOf(opts);
    if (position.ms - claimed > delayMs) {
      add(label + ' time', false, 'anchored at ' + iso(position) + ', more than ' + Math.round(delayMs / 3600000) + ' hours after its claimed time, so the claimed time is not proven', false, true);
      return position;
    }
    if (opts.at !== undefined && position.ms > Date.parse(opts.at)) {
      add(label + ' time', false, 'anchored at ' + iso(position) + ', after the time given for verification, so it was not proven at that time', false, true);
      return position;
    }
    add(label + ' time', true, 'recorded by ' + iso(position));
    return position;
  } catch (e) {
    add(label, false, 'the anchor could not be checked, ' + ((e && e.message) || 'unknown error'));
    return null;
  }
}

async function earliestOf(copies, opts) {
  let best = null;
  const seen = new Set();
  for (const c of copies) {
    if (c.anchor === undefined) continue;
    const key = JSON.stringify(c.anchor);
    if (seen.has(key)) continue;
    seen.add(key);
    const sub = recorder();
    const pos = await checkAnchor(c, opts, sub.add, 'copy');
    if (pos) best = earlier(best, pos);
  }
  return best;
}

function groupByIdentity(list) {
  const groups = new Map();
  for (const p of list) {
    const id = identity(p);
    if (!groups.has(id)) groups.set(id, []);
    groups.get(id).push(p);
  }
  return groups;
}

function listOption(opts, name) {
  const list = opts[name];
  if (list === undefined) return undefined;
  if (!Array.isArray(list) || list.length > LIST_MAX) F.reject(name + ' is a list of at most ' + LIST_MAX + ' envelopes');
  return list;
}

function expectedParty(opts, name, keyIdName, publicKeyName, required) {
  if (opts[keyIdName] !== undefined && opts[publicKeyName] !== undefined) F.reject('give ' + keyIdName + ' or ' + publicKeyName + ', not both');
  if (opts[keyIdName] !== undefined) {
    if (typeof opts[keyIdName] !== 'string' || !/^[0-9a-f]{64}$/.test(opts[keyIdName])) F.reject(keyIdName + ' is 64 lowercase hex characters');
    return opts[keyIdName];
  }
  if (opts[publicKeyName] !== undefined) {
    let pk = opts[publicKeyName];
    if (typeof pk === 'string') {
      const raw = Buffer.from(pk, 'base64');
      if (raw.toString('base64') !== pk) F.reject(publicKeyName + ' is canonical base64');
      pk = raw;
    }
    return F.keyIdOf(pk);
  }
  if (required) F.reject('the expected ' + name + ' is required, give ' + keyIdName + ' or ' + publicKeyName + ' so an attacker cannot substitute a consent of its own');
  return null;
}

function enforceExpectedIdentities(opts, add, patientActual, granteeActual) {
  if (opts.patientKeyId !== undefined || opts.patientPublicKey !== undefined) {
    const expected = expectedParty(opts, 'patient', 'patientKeyId', 'patientPublicKey', false);
    const same = expected !== null && expected === patientActual;
    add('expected patient', same, same ? 'bound to the expected patient' : 'bound to a different patient than expected');
  }
  if (opts.granteeKeyId !== undefined || opts.granteePublicKey !== undefined) {
    const expected = expectedParty(opts, 'grantee', 'granteeKeyId', 'granteePublicKey', false);
    const same = expected !== null && expected === granteeActual;
    add('expected grantee', same, same ? 'bound to the expected grantee' : 'bound to a different grantee than expected');
  }
}

async function consentCore(envelope, opts, add, prefix) {
  let c;
  try {
    c = F.parse(envelope);
  } catch (e) {
    add(prefix + 'format', false, e.message);
    return null;
  }
  if (c.type !== 'consent') {
    add(prefix + 'format', false, 'a ' + c.type + ' envelope was given where a consent was expected');
    return null;
  }
  add(prefix + 'format', true, 'a well formed consent');
  const sigOk = signatureOk(c);
  add(prefix + 'signature', sigOk, sigOk ? 'the ML-DSA-65 signature of the patient is valid' : 'the consent signature does not verify');
  const bound = c.signerId === c.statement.patientKeyId;
  add(prefix + 'patient', bound, bound ? 'signed by the patient it names' : 'signed by a key other than the patient it names');
  if (!sigOk || !bound) return { c, ok: false, position: null, ref: null };
  const position = await checkAnchor(c, opts, add, prefix + 'anchor', untilOf(c));
  return { c, ok: true, position, ref: F.refOf(c) };
}

async function revocationOf(core, opts, add) {
  const list = listOption(opts, 'revocations');
  if (list === undefined) {
    add('revocations', false, 'no revocation list was supplied, so it is unknown whether the consent was withdrawn', false, true);
    return { earliest: null, unproven: false, checked: false };
  }
  const valid = [];
  for (const [i, env] of list.entries()) {
    const name = 'revocation ' + (i + 1);
    let r;
    try {
      r = F.parse(env);
    } catch (e) {
      add(name, true, 'ignored, it is not a well formed envelope');
      continue;
    }
    if (r.type !== 'revoke' || r.statement.consentId !== core.c.statement.consentId || r.statement.consentRef !== core.ref || r.statement.patientKeyId !== core.c.statement.patientKeyId) {
      add(name, true, 'ignored, it concerns another consent');
      continue;
    }
    if (!signatureOk(r) || r.signerId !== core.c.statement.patientKeyId) {
      add(name, true, 'ignored, it is not signed by the patient of this consent');
      continue;
    }
    valid.push(r);
  }
  let earliest = null;
  let unproven = false;
  for (const copies of groupByIdentity(valid).values()) {
    const position = await earliestOf(copies, opts);
    if (position) earliest = earlier(earliest, position);
    else unproven = true;
  }
  if (valid.length) add('revocations', true, earliest ? 'the patient revoked this consent at ' + iso(earliest) : 'the patient revoked this consent, the revocation time is not yet proven');
  else add('revocations', true, 'no revocation of this consent was supplied');
  return { earliest, unproven, checked: true };
}

async function verifyConsent(envelope, opts) {
  const { checks, add } = recorder();
  const expected = expectedParty(opts, 'patient', 'patientKeyId', 'patientPublicKey', true);
  const core = await consentCore(envelope, opts, add, '');
  if (!core) return finish(checks, { type: null });
  const trusted = expected === core.c.statement.patientKeyId;
  add('expected patient', trusted, trusted ? 'granted by the expected patient' : 'granted by a different patient than expected');
  if (opts.granteeKeyId !== undefined || opts.granteePublicKey !== undefined) {
    const grantee = expectedParty(opts, 'grantee', 'granteeKeyId', 'granteePublicKey', false);
    const same = grantee === core.c.statement.granteeKeyId;
    add('expected grantee', same, same ? 'granted to the expected grantee' : 'granted to a different grantee than expected');
  }
  const requireAnchor = opts.requireAnchor !== false;
  if (core.ok && core.c.anchor === undefined) {
    if (requireAnchor) add('anchor', false, 'the consent is not anchored, so its time is only the claim of the patient', false, true);
    else add('anchor', true, 'not anchored');
  }
  let rev = { earliest: null, unproven: false, checked: false };
  if (core.ok) {
    rev = await revocationOf(core, opts, add);
    if (opts.at !== undefined) {
      const tp = F.timeProblem(opts.at, 'at');
      if (tp) F.reject(tp);
    }
    let early = null;
    let late = null;
    if (opts.at !== undefined) {
      early = Date.parse(opts.at);
      late = early;
    } else {
      try {
        const clock = await chainClock(clockOptions(opts));
        early = clock.early;
        late = clock.late;
      } catch (e) {
        add('in force', false, 'the current time could not be confirmed by the chain, so it is unknown whether the consent is in force, ' + ((e && e.message) || 'unknown error'), true);
      }
    }
    if (early !== null && early < Date.parse(core.c.statement.validFrom)) add('in force', false, 'the consent is not in force until ' + core.c.statement.validFrom);
    if (late !== null && late > Date.parse(core.c.statement.validUntil)) add('in force', false, 'the consent expired at ' + core.c.statement.validUntil);
    if (rev.earliest) {
      const revMs = rev.earliest.ms;
      if (late !== null && late >= revMs) add('in force', false, 'the patient revoked this consent at ' + iso(rev.earliest));
    }
    if (rev.unproven) {
      add('in force', false, 'a revocation exists whose time is not yet proven, so it cannot be ruled out that the withdrawal predates the verification time', false, true);
    }
  }
  return finish(checks, {
    type: 'consent',
    consentId: core.c.statement.consentId,
    consentRef: core.ref,
    subjectRef: core.c.statement.subjectRef,
    patientKeyId: core.c.statement.patientKeyId,
    granteeKeyId: core.c.statement.granteeKeyId,
    granteeLabel: core.c.statement.granteeLabel,
    purposes: core.c.statement.purposes,
    categories: core.c.statement.categories,
    validFrom: core.c.statement.validFrom,
    validUntil: core.c.statement.validUntil,
    anchoredAt: core.position ? iso(core.position) : null,
    revokedAt: rev.earliest ? iso(rev.earliest) : null,
    patientTrusted: trusted,
    revocationChecked: rev.checked,
    notes: ['the grantee label is text written by the patient, it is not a verified identity, bind the grantee to a key with granteeKeyId'],
  });
}

async function verifyAcknowledge(envelope, opts) {
  const { checks, add } = recorder();
  let a;
  try {
    a = F.parse(envelope);
  } catch (e) {
    add('format', false, e.message);
    return finish(checks, { type: null });
  }
  if (a.type !== 'acknowledge') {
    add('format', false, 'a ' + a.type + ' envelope was given where an acknowledgement was expected');
    return finish(checks, { type: a.type });
  }
  add('format', true, 'a well formed acknowledgement');
  const sigOk = signatureOk(a);
  add('signature', sigOk, sigOk ? 'the ML-DSA-65 signature of the grantee is valid' : 'the acknowledgement signature does not verify');
  const bound = a.signerId === a.statement.granteeKeyId;
  add('grantee', bound, bound ? 'signed by the grantee it names' : 'signed by a key other than the grantee it names');
  if (opts.consent === undefined) F.reject('the consent the acknowledgement answers is required');
  const core = await consentCore(opts.consent, opts, add, 'consent ');
  if (core && core.ok) {
    const matches = a.statement.consentRef === core.ref && a.statement.consentId === core.c.statement.consentId && a.statement.granteeKeyId === core.c.statement.granteeKeyId;
    add('consent binding', matches, matches ? 'the acknowledgement answers this exact consent as its grantee' : 'the acknowledgement does not belong to this consent or its grantee');
  }
  enforceExpectedIdentities(opts, add, core && core.ok ? core.c.statement.patientKeyId : null, a.statement.granteeKeyId);
  const pos = sigOk && bound ? await checkAnchor(a, opts, add, 'anchor') : null;
  if (sigOk && bound && a.anchor === undefined) {
    if (opts.requireAnchor !== false) add('anchor', false, 'the acknowledgement is not anchored, so its time is only the claim of the grantee', false, true);
    else add('anchor', true, 'not anchored');
  }
  return finish(checks, { type: 'acknowledge', consentId: a.statement.consentId, consentRef: a.statement.consentRef, granteeKeyId: a.statement.granteeKeyId, acknowledgedAt: a.statement.acknowledgedAt, anchoredAt: pos ? iso(pos) : null });
}

async function verifyRevoke(envelope, opts) {
  const { checks, add } = recorder();
  let r;
  try {
    r = F.parse(envelope);
  } catch (e) {
    add('format', false, e.message);
    return finish(checks, { type: null });
  }
  if (r.type !== 'revoke') {
    add('format', false, 'a ' + r.type + ' envelope was given where a revocation was expected');
    return finish(checks, { type: r.type });
  }
  add('format', true, 'a well formed consent revocation');
  const sigOk = signatureOk(r);
  add('signature', sigOk, sigOk ? 'the ML-DSA-65 signature of the patient is valid' : 'the revocation signature does not verify');
  const bound = r.signerId === r.statement.patientKeyId;
  add('patient', bound, bound ? 'signed by the patient it names' : 'signed by a key other than the patient it names');
  if (opts.consent === undefined) F.reject('the consent the revocation withdraws is required');
  const core = await consentCore(opts.consent, opts, add, 'consent ');
  if (core && core.ok) {
    const matches = r.statement.consentRef === core.ref && r.statement.consentId === core.c.statement.consentId && r.statement.patientKeyId === core.c.statement.patientKeyId;
    add('consent binding', matches, matches ? 'the revocation withdraws this exact consent' : 'the revocation does not belong to this consent');
  }
  enforceExpectedIdentities(opts, add, r.statement.patientKeyId, core && core.ok ? core.c.statement.granteeKeyId : null);
  const pos = sigOk && bound ? await checkAnchor(r, opts, add, 'anchor') : null;
  if (sigOk && bound && r.anchor === undefined) {
    if (opts.requireAnchor !== false) add('anchor', false, 'the revocation is not anchored, so its time is only the claim of the patient', false, true);
    else add('anchor', true, 'not anchored');
  }
  return finish(checks, { type: 'revoke', consentId: r.statement.consentId, consentRef: r.statement.consentRef, patientKeyId: r.statement.patientKeyId, revokedAt: r.statement.revokedAt, anchoredAt: pos ? iso(pos) : null });
}

const VERIFY_OPTIONS = new Set(['type', 'consent', 'patientKeyId', 'patientPublicKey', 'granteeKeyId', 'granteePublicKey', 'revocations', 'strict', 'requireAnchor', 'maxAnchorDelay', 'at', 'deadlineMs', 'rpc', 'client', 'clients', 'trustSingleEndpoint', 'trustCustomEndpoints', 'allowLoopback', 'endpointAllowList', 'expectedSender', 'contract', 'trustCustomContract', 'network', 'clockSlackMs']);

async function verify(envelope, options) {
  if (options === undefined || options === null || typeof options !== 'object') F.reject('options is an object that names the expected type');
  const opts = own(options);
  const unknown = Object.keys(opts).find((k) => !VERIFY_OPTIONS.has(k));
  if (unknown !== undefined) F.reject('the option ' + unknown.replace(/[^A-Za-z0-9_]/g, '?').slice(0, 40) + ' is not an option of verify');
  if (!F.TYPES.includes(opts.type)) F.reject('type is consent, acknowledge or revoke, so a record of one type can never be presented as another');
  delayOf(opts);
  if (strictOf(opts) && opts.trustSingleEndpoint === true) F.reject('strict verification needs at least two independent endpoints and refuses trustSingleEndpoint, set strict to false to see what one endpoint reports, which is never a valid result');
  if (opts.at !== undefined) {
    const tp = F.timeProblem(opts.at, 'at');
    if (tp) F.reject(tp);
  }
  const np = networkProblem(opts);
  if (np) F.reject(np);
  opts[DEADLINE] = performance.now() + deadlineOf(opts);
  const net = { endpoints: new Set(), official: null };
  opts[NET] = net;
  let res;
  if (opts.type === 'consent') res = await verifyConsent(envelope, opts);
  else if (opts.type === 'acknowledge') res = await verifyAcknowledge(envelope, opts);
  else res = await verifyRevoke(envelope, opts);
  const checks = res.checks;
  delete res.checks;
  return Object.assign(res, { endpoints: [...net.endpoints], officialEndpoints: net.official, checks });
}

module.exports = { verify };
