#!/usr/bin/env node
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const qc = require('..');
const qstamp = require('@quantovainc/qstamp');

const ENVELOPE_MAX = 1024 * 1024;
const VALUE_FILE_MAX = 64 * 1024;
let stdinTaken = false;

const HELP = `qconsent, quantum secure patient consent records with Quantova time proofs

  qconsent keygen <keyfile>
  qconsent key <keyfile>
  qconsent grant --key <patient keyfile> --grantee <grantee key json>
                 --purpose NAME ... --category NAME ... --valid-until TIME [--valid-from TIME]
                 [--grantee-label-file FILE] [--subject-ref HEX] [--note-file FILE] --out FILE
  qconsent acknowledge --key <grantee keyfile> --consent FILE [--note-file FILE] --out FILE
  qconsent revoke --key <patient keyfile> --consent FILE [--note-file FILE] --out FILE
  qconsent status --consent FILE [--grantee-key-id HEX] [--revocation FILE]... [--at TIME] [--rpc URL]...
                  [--trust-custom-endpoints] [--allow-endpoint HOST]... [--allow-loopback]
                  [--trust-single-endpoint --no-strict]
  qconsent subject --secret-file FILE --identity-file FILE
  qconsent anchor <envelope>... --network NAME --seed-file <file> [--index N] [--rpc URL]... [--trust-single-endpoint]
                  [--trust-custom-endpoints] [--allow-endpoint HOST]... [--allow-loopback] [--max-fee N]
  qconsent complete <envelope>... --pending FILE [--tx ID] [--rpc URL]... [--trust-single-endpoint]
                    [--allow-endpoint HOST]... [--allow-loopback]
  qconsent verify <envelope> --type consent|acknowledge|revoke --network NAME
                  [--patient-key-id HEX | --patient-public-key FILE] [--grantee-key-id HEX]
                  [--consent FILE] [--revocation FILE... | --no-revocations] [--allow-unanchored] [--at TIME]
                  [--max-anchor-delay SECONDS] [--expect-sender ADDRESS]... [--rpc URL]... [--trust-custom-endpoints]
                  [--allow-endpoint HOST]... [--allow-loopback] [--trust-single-endpoint --no-strict] [--json]
  qconsent ref <consent>

QConsent records carry no patient data. A consent names the patient key, the grantee key, the purposes the
data may be used for, the categories of data covered, and the period of validity. Only a salted commitment to
the patient identity, the subject reference, may be carried, and it is computed by the grantee with subject.

Decisions about validity and expiry use the time of the chain, read from at least two independent endpoints.
Endpoints given with --rpc are used for the time and by verify only with --trust-custom-endpoints, loopback
endpoints only with --allow-loopback and private network endpoints only when named with --allow-endpoint.
--trust-single-endpoint relies on one endpoint, refused unless --no-strict is given, and a result that rests
on it is never VALID. An anchor counts only when it is proven by a finality certificate or by official
endpoints of two different operators, any other anchor is UNPROVEN and never VALID. --network names the
network the records were anchored on, testnet for the public network, and verify also takes custom.

The grantee label, notes and the patient identity are read from the files named by the -file options, or from
standard input when the file is -, so they never appear in the shell history or the process list, and only one
value can come from standard input.

Exit codes are 0 for valid or active, 1 for invalid, inactive or an error, 2 for indeterminate or unproven and
64 for usage errors.`;

function usageError(message) {
  const e = new Error(message);
  e.usage = true;
  return e;
}

const SPEC = {
  keygen: { flags: ['force'], values: [] },
  key: { flags: [], values: [] },
  grant: { flags: ['force'], values: ['key', 'grantee', 'valid-until', 'valid-from', 'grantee-label', 'grantee-label-file', 'subject-ref', 'note', 'note-file', 'out'], multi: ['purpose', 'category'] },
  acknowledge: { flags: ['force'], values: ['key', 'consent', 'note', 'note-file', 'out'] },
  revoke: { flags: ['force'], values: ['key', 'consent', 'note', 'note-file', 'out'] },
  status: { flags: ['trust-single-endpoint', 'trust-custom-endpoints', 'allow-loopback', 'no-strict'], values: ['consent', 'grantee-key-id', 'at'], multi: ['revocation', 'rpc', 'allow-endpoint'] },
  subject: { flags: [], values: ['secret-file', 'identity-file'] },
  anchor: { flags: ['trust-single-endpoint', 'trust-custom-endpoints', 'allow-loopback'], values: ['seed-file', 'index', 'max-fee', 'network'], multi: ['rpc', 'allow-endpoint'] },
  complete: { flags: ['trust-single-endpoint', 'allow-loopback'], values: ['pending', 'tx'], multi: ['rpc', 'allow-endpoint'] },
  verify: { flags: ['allow-unanchored', 'no-revocations', 'json', 'trust-single-endpoint', 'trust-custom-endpoints', 'allow-loopback', 'no-strict'], values: ['type', 'consent', 'patient-key-id', 'patient-public-key', 'grantee-key-id', 'at', 'max-anchor-delay', 'network'], multi: ['revocation', 'rpc', 'allow-endpoint', 'expect-sender'] },
  ref: { flags: [], values: [] },
};

function parse(command, argv) {
  const spec = SPEC[command];
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) {
      positional.push(a);
      continue;
    }
    const name = a.slice(2);
    if (spec.flags.includes(name)) {
      flags[name] = true;
    } else if (spec.values.includes(name) || (spec.multi || []).includes(name)) {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) throw usageError('--' + name + ' needs a value');
      if (v.length === 0) throw usageError('--' + name + ' was given an empty value');
      i += 1;
      if ((spec.multi || []).includes(name)) (flags[name] = flags[name] || []).push(v);
      else if (flags[name] !== undefined) throw usageError('--' + name + ' was given twice');
      else flags[name] = v;
    } else {
      throw usageError('unknown option ' + safe(a).slice(0, 40));
    }
  }
  return { positional, flags };
}

function hexNibble(code) {
  if (code >= 48 && code <= 57) return code - 48;
  if (code >= 97 && code <= 102) return code - 87;
  if (code >= 65 && code <= 70) return code - 55;
  return -1;
}

function openRegular(file, what) {
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0);
  let fd;
  try {
    fd = fs.openSync(file, flags);
  } catch (e) {
    throw usageError(e.code === 'ELOOP' ? 'the ' + what + ' must not be a symbolic link' : 'the ' + what + ' ' + safe(file) + ' could not be opened');
  }
  if (!fs.fstatSync(fd).isFile()) {
    fs.closeSync(fd);
    throw usageError('the ' + what + ' must be a regular file');
  }
  return fd;
}

function readSeed(file, what) {
  if (!file) throw usageError(what + ' is required');
  const fd = openRegular(file, 'key file');
  const raw = Buffer.allocUnsafeSlow(131);
  const seed = new Uint8Array(32);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw usageError('the key file must be a regular file');
    if (process.platform !== 'win32') {
      if ((st.mode & 0o077) !== 0) throw usageError('the key file ' + file + ' is readable by other users, restrict it with chmod 600');
      if (typeof process.getuid === 'function' && st.uid !== process.getuid()) throw usageError('the key file ' + file + ' is not owned by the current user');
    }
    const n = fs.readSync(fd, raw, 0, raw.length, 0);
    if (n > 66) throw usageError('the key file must hold only a 32 byte seed as 64 hex characters');
    let end = n;
    while (end > 0 && (raw[end - 1] === 10 || raw[end - 1] === 13 || raw[end - 1] === 32)) end -= 1;
    if (end !== 64) throw usageError('the key file must hold a 32 byte seed as 64 hex characters');
    for (let i = 0; i < 32; i += 1) {
      const hi = hexNibble(raw[2 * i]);
      const lo = hexNibble(raw[2 * i + 1]);
      if (hi < 0 || lo < 0) throw usageError('the key file must hold a 32 byte seed as 64 hex characters');
      seed[i] = (hi << 4) | lo;
    }
    return seed;
  } catch (e) {
    seed.fill(0);
    throw e;
  } finally {
    raw.fill(0);
    fs.closeSync(fd);
  }
}

function statOf(file) {
  try {
    return fs.lstatSync(file);
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
}

const pendingTemp = new Set();

function cleanupTemp() {
  for (const t of pendingTemp) {
    try {
      fs.rmSync(t, { force: true });
    } catch (e) {
      continue;
    }
  }
}

for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(sig, () => {
    cleanupTemp();
    process.exit(130);
  });
}

function atomicWrite(dest, data, force) {
  const existing = statOf(dest);
  if (existing && existing.isSymbolicLink()) throw usageError('refusing to write through the symbolic link ' + safe(dest));
  if (existing && !existing.isFile()) throw usageError('something other than a file exists at ' + safe(dest));
  if (existing && !force) throw usageError('a file already exists at ' + safe(dest) + ', pass --force to replace it');
  const dir = path.dirname(dest);
  const tmp = path.join(dir, '.' + path.basename(dest) + '.' + crypto.randomBytes(6).toString('hex') + '.tmp');
  pendingTemp.add(tmp);
  try {
    const fd = fs.openSync(tmp, 'wx', 0o600);
    try {
      fs.fchmodSync(fd, 0o600);
      fs.writeSync(fd, data);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    if (force) {
      fs.renameSync(tmp, dest);
    } else {
      try {
        fs.linkSync(tmp, dest);
      } catch (e) {
        if (e.code === 'EEXIST') throw usageError('a file already exists at ' + safe(dest) + ', pass --force to replace it');
        throw e;
      }
      fs.rmSync(tmp, { force: true });
    }
    try {
      const dfd = fs.openSync(dir, 'r');
      try {
        fs.fsyncSync(dfd);
      } finally {
        fs.closeSync(dfd);
      }
    } catch (e) {
      void e;
    }
  } finally {
    fs.rmSync(tmp, { force: true });
    pendingTemp.delete(tmp);
  }
}

function strictJson(text) {
  const value = JSON.parse(text);
  const stack = [];
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    const top = stack[stack.length - 1];
    if (ch === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      if (top && top.keys && top.expectKey) {
        const key = JSON.parse(text.slice(i, j + 1));
        if (top.keys.has(key)) throw new Error('the JSON repeats the key ' + JSON.stringify(key));
        top.keys.add(key);
        top.expectKey = false;
      }
      i = j;
    } else if (ch === '{') {
      stack.push({ keys: new Set(), expectKey: true });
    } else if (ch === '[') {
      stack.push({ keys: null });
    } else if (ch === '}' || ch === ']') {
      stack.pop();
    } else if (ch === ',' && top && top.keys) {
      top.expectKey = true;
    }
  }
  return value;
}

function readJson(file, what, invalidExit) {
  const fd = openRegular(file, what);
  const buf = Buffer.alloc(ENVELOPE_MAX + 1);
  let n;
  try {
    n = fs.readSync(fd, buf, 0, buf.length, 0);
  } finally {
    fs.closeSync(fd);
  }
  const bad = (message) => {
    const e = new Error(message);
    if (invalidExit) e.invalid = true;
    else e.usage = true;
    return e;
  };
  if (n > ENVELOPE_MAX) throw bad('the ' + what + ' is larger than ' + ENVELOPE_MAX + ' bytes');
  try {
    return strictJson(buf.subarray(0, n).toString('utf8'));
  } catch (e) {
    throw bad('the ' + what + ' ' + safe(file) + ' is not valid JSON');
  }
}

function asciiJson(value) {
  return JSON.stringify(value, null, 2).replace(/[\u007f-￿]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

function safe(value) {
  return String(value).replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff\ufff9-\ufffb]/gu, '?');
}

function withSeed(file, what, fn) {
  const seed = readSeed(file, what);
  try {
    return fn(seed);
  } finally {
    seed.fill(0);
  }
}

function networkFlag(flags, verifying) {
  const names = Object.keys(qstamp.NETWORKS).concat(verifying ? ['custom'] : []);
  if (flags.network === undefined) throw usageError('--network is required');
  if (!names.includes(flags.network)) throw usageError('--network is one of ' + names.join(', ') + ', the network the records are anchored on');
  return flags.network;
}

function endpoints(flags) {
  const out = { trustSingleEndpoint: !!flags['trust-single-endpoint'], strict: !flags['no-strict'] };
  if (flags.rpc) out.clients = flags.rpc;
  if (flags['allow-endpoint']) out.endpointAllowList = flags['allow-endpoint'];
  if (flags['trust-custom-endpoints']) out.trustCustomEndpoints = true;
  if (flags['allow-loopback']) out.allowLoopback = true;
  if (flags['expect-sender']) out.expectedSender = flags['expect-sender'];
  return out;
}

function need(flags, name) {
  if (flags[name] === undefined) throw usageError('--' + name + ' is required');
  return flags[name];
}

function readFileBytes(file, what, max) {
  const fd = openRegular(file, what);
  try {
    const size = fs.fstatSync(fd).size;
    if (size > max) throw usageError('the ' + what + ' is larger than ' + max + ' bytes');
    const buf = Buffer.alloc(size);
    let off = 0;
    while (off < size) {
      const n = fs.readSync(fd, buf, off, size - off, off);
      if (n === 0) break;
      off += n;
    }
    return buf.subarray(0, off);
  } finally {
    fs.closeSync(fd);
  }
}

function valueFile(file, what) {
  let raw;
  if (file === '-') {
    if (stdinTaken) throw usageError('only one value can be read from standard input');
    stdinTaken = true;
    try {
      raw = fs.readFileSync(0);
    } catch (e) {
      throw usageError(what + ' - could not read standard input');
    }
  } else {
    raw = readFileBytes(file, what.replace(/^--/, '').replace(/-file$/, '') + ' file', VALUE_FILE_MAX);
  }
  if (raw.length > VALUE_FILE_MAX) throw usageError(what + ' holds more than ' + VALUE_FILE_MAX + ' bytes');
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(raw).replace(/\r?\n$/, '');
  } catch (e) {
    throw usageError(what + ' must hold UTF-8 text');
  }
}

function inlineRefused(flags, name) {
  if (flags[name] !== undefined) throw usageError('--' + name + ' is no longer taken on the command line, where it shows in the shell history and the process list, give --' + name + '-file FILE, or --' + name + '-file - to read it from standard input');
}

function privateValue(flags, name) {
  inlineRefused(flags, name);
  const file = flags[name + '-file'];
  return file === undefined ? undefined : valueFile(file, '--' + name + '-file');
}

function writeEnvelope(file, env, force) {
  atomicWrite(file, asciiJson(env) + '\n', force);
}

async function cmdKeygen(positional, flags) {
  if (positional.length !== 1) throw usageError('keygen takes one key file path');
  const seed = qc.generateKey();
  const text = Buffer.alloc(65);
  try {
    const digits = '0123456789abcdef';
    for (let i = 0; i < 32; i += 1) {
      text[2 * i] = digits.charCodeAt(seed[i] >> 4);
      text[2 * i + 1] = digits.charCodeAt(seed[i] & 15);
    }
    text[64] = 10;
    atomicWrite(positional[0], text, flags.force);
    console.log('key id ' + qc.keyId(seed));
  } finally {
    seed.fill(0);
    text.fill(0);
  }
  return 0;
}

async function cmdKey(positional) {
  if (positional.length !== 1) throw usageError('key takes one key file path');
  const desc = withSeed(positional[0], 'a key file', (seed) => qc.describeKey(seed));
  process.stdout.write(asciiJson(desc) + '\n');
  return 0;
}

async function cmdGrant(positional, flags) {
  if (positional.length) throw usageError('grant takes options only');
  const out = need(flags, 'out');
  const grantee = readJson(need(flags, 'grantee'), 'grantee key');
  const purposes = flags.purpose || [];
  const categories = flags.category || [];
  if (purposes.length === 0) throw usageError('at least one --purpose is required');
  if (categories.length === 0) throw usageError('at least one --category is required');
  const granteeLabel = privateValue(flags, 'grantee-label');
  const note = privateValue(flags, 'note');
  const env = withSeed(need(flags, 'key'), '--key', (seed) => qc.grant({
    key: seed, grantee, purposes, categories, validUntil: need(flags, 'valid-until'),
    validFrom: flags['valid-from'], subjectRef: flags['subject-ref'], granteeLabel, note,
  }));
  writeEnvelope(out, env, flags.force);
  console.log('consent ' + env.statement.consentId + ' granted to grantee ' + env.statement.granteeKeyId + ', written to ' + safe(out));
  return 0;
}

async function cmdAcknowledge(positional, flags) {
  if (positional.length) throw usageError('acknowledge takes options only');
  const out = need(flags, 'out');
  const consent = readJson(need(flags, 'consent'), 'consent', true);
  const note = privateValue(flags, 'note');
  const env = withSeed(need(flags, 'key'), '--key', (seed) => qc.acknowledge({ key: seed, consent, note }));
  writeEnvelope(out, env, flags.force);
  console.log('acknowledgement of consent ' + env.statement.consentId + ' written to ' + safe(out));
  return 0;
}

async function cmdRevoke(positional, flags) {
  if (positional.length) throw usageError('revoke takes options only');
  const out = need(flags, 'out');
  const consent = readJson(need(flags, 'consent'), 'consent', true);
  const note = privateValue(flags, 'note');
  const env = withSeed(need(flags, 'key'), '--key', (seed) => qc.revoke({ key: seed, consent, note }));
  writeEnvelope(out, env, flags.force);
  console.log('revocation of consent ' + env.statement.consentId + ' written to ' + safe(out));
  return 0;
}

async function cmdStatus(positional, flags) {
  if (positional.length) throw usageError('status takes options only');
  const consent = readJson(need(flags, 'consent'), 'consent', true);
  const revocations = (flags.revocation || []).map((f) => readJson(f, 'revocation'));
  const res = await qc.status(consent, Object.assign({ granteeKeyId: flags['grantee-key-id'], revocations, at: flags.at }, endpoints(flags)));
  if (res.active) {
    console.log('ACTIVE until ' + safe(res.validUntil));
  } else {
    for (const r of res.reasons) console.log('inactive  ' + safe(r));
    console.log('INACTIVE');
  }
  return res.active ? 0 : 1;
}

async function cmdSubject(positional, flags) {
  if (positional.length) throw usageError('subject takes options only');
  const secret = readFileBytes(need(flags, 'secret-file'), 'subject secret', 1024);
  const identity = valueFile(need(flags, 'identity-file'), '--identity-file');
  try {
    if (secret.length !== 32) throw usageError('the subject secret file holds 32 raw bytes');
    console.log(qc.subjectRef(Uint8Array.from(secret), identity));
  } finally {
    secret.fill(0);
  }
  return 0;
}

function pendingPath(file) {
  return file + '.pending.json';
}

function saveAnchored(files, anchored) {
  anchored.forEach((env, i) => {
    writeEnvelope(files[i], env, true);
    console.log('anchored ' + safe(files[i]) + ' in transaction ' + env.anchor.anchor.tx);
  });
}

async function cmdAnchor(positional, flags) {
  if (positional.length === 0) throw usageError('anchor takes one or more envelopes');
  if (new Set(positional.map((f) => path.resolve(f))).size !== positional.length) throw usageError('each envelope may be given once');
  for (const f of positional) {
    if (statOf(pendingPath(f))) throw usageError('an unfinished anchor exists in ' + safe(pendingPath(f)) + ', finish it with complete first');
  }
  const pendingFile = pendingPath(positional[0]);
  const envs = positional.map((f) => readJson(f, 'envelope', true));
  let index = 0;
  if (flags.index !== undefined) {
    if (!/^\d{1,9}$/.test(flags.index)) throw usageError('--index is a whole number');
    index = Number(flags.index);
  }
  const network = networkFlag(flags, false);
  const seed = readSeed(flags['seed-file'] || process.env.QSTAMP_SEED_FILE, '--seed-file of a funded Quantova account');
  let saved = false;
  const keep = (pending) => {
    const text = asciiJson(pending) + '\n';
    for (const f of positional) atomicWrite(pendingPath(f), text, saved);
    saved = true;
  };
  let anchored;
  try {
    anchored = await qc.anchor(envs, Object.assign({ seed, index, network, maxFee: flags['max-fee'], onPending: keep }, endpoints(flags)));
  } catch (e) {
    if (e && e.pending && typeof e.pending === 'object') {
      try {
        keep(e.pending);
        e.message += ', the pending stamp was saved in ' + safe(pendingFile) + ', finish it with qconsent complete ' + positional.map(safe).join(' ') + ' --pending ' + safe(pendingFile);
      } catch (e2) {
        e.message += ', the pending stamp follows on standard output, keep it to finish the anchor';
        process.stdout.write(asciiJson(e.pending) + '\n');
      }
    }
    throw e;
  } finally {
    seed.fill(0);
  }
  saveAnchored(positional, anchored);
  if (saved) for (const f of positional) fs.rmSync(pendingPath(f), { force: true });
  return 0;
}

async function cmdComplete(positional, flags) {
  if (positional.length === 0) throw usageError('complete takes the envelopes given to anchor, in the same order');
  if (!flags.pending) throw usageError('--pending is required');
  const pending = readJson(flags.pending, 'pending stamp');
  if (flags.tx !== undefined) {
    if (!/^QTX1[0-9A-Z]{20,120}$/.test(flags.tx)) throw usageError('--tx is the QTX1 identifier of the stamp transaction');
    if (pending && typeof pending === 'object' && typeof pending.tx === 'string' && pending.tx !== flags.tx) throw usageError('the pending stamp already names another transaction');
    if (pending && typeof pending === 'object') pending.tx = flags.tx;
  }
  const envs = positional.map((f) => readJson(f, 'envelope', true));
  const anchored = await qc.complete(envs, pending, endpoints(flags));
  saveAnchored(positional, anchored);
  fs.rmSync(flags.pending, { force: true });
  for (const f of positional) fs.rmSync(pendingPath(f), { force: true });
  return 0;
}

async function cmdVerify(positional, flags) {
  if (positional.length !== 1) throw usageError('verify takes one envelope');
  if (flags['patient-key-id'] !== undefined && flags['patient-public-key'] !== undefined) throw usageError('give --patient-key-id or --patient-public-key, not both');
  if (flags['patient-key-id'] !== undefined && !/^[0-9a-f]{64}$/.test(flags['patient-key-id'])) throw usageError('--patient-key-id is 64 lowercase hex characters');
  const env = readJson(positional[0], 'envelope', true);
  const opts = { requireAnchor: !flags['allow-unanchored'] };
  if (flags.at !== undefined) opts.at = flags.at;
  if (flags['max-anchor-delay'] !== undefined) {
    if (!/^[1-9][0-9]{0,9}$/.test(flags['max-anchor-delay'])) throw usageError('--max-anchor-delay is a whole number of seconds');
    opts.maxAnchorDelay = Number(flags['max-anchor-delay']);
  }
  if (!['consent', 'acknowledge', 'revoke'].includes(flags.type)) throw usageError('give the expected envelope type with --type consent, acknowledge or revoke');
  opts.type = flags.type;
  if (opts.type === 'consent') {
    if (flags['patient-key-id'] === undefined && flags['patient-public-key'] === undefined) throw usageError('give the expected patient with --patient-key-id or --patient-public-key');
    if (flags['patient-key-id'] !== undefined) opts.patientKeyId = flags['patient-key-id'];
    if (flags['patient-public-key'] !== undefined) {
      const desc = readJson(flags['patient-public-key'], 'patient key');
      if (!desc || desc.format !== 'qconsent-key/1' || typeof desc.publicKey !== 'string') throw usageError('the patient key file is not a qconsent-key/1 description');
      opts.patientPublicKey = desc.publicKey;
    }
    if (flags['grantee-key-id'] !== undefined) {
      if (!/^[0-9a-f]{64}$/.test(flags['grantee-key-id'])) throw usageError('--grantee-key-id is 64 lowercase hex characters');
      opts.granteeKeyId = flags['grantee-key-id'];
    }
    if (flags['no-revocations'] && flags.revocation) throw usageError('give --revocation or --no-revocations, not both');
    if (flags.revocation) opts.revocations = flags.revocation.map((f) => readJson(f, 'revocation'));
    if (flags['no-revocations']) opts.revocations = [];
  } else {
    if (flags.consent === undefined) throw usageError('--consent is required to verify an ' + (opts.type === 'acknowledge' ? 'acknowledgement' : 'revocation'));
    opts.consent = readJson(flags.consent, 'consent', true);
  }
  opts.network = networkFlag(flags, true);
  Object.assign(opts, endpoints(flags));
  const res = await qc.verify(env, opts);
  if (flags.json) {
    process.stdout.write(asciiJson(res) + '\n');
  } else {
    if (res.type) console.log('type  ' + res.type);
    for (const c of res.checks) console.log((c.ok ? 'ok    ' : c.transport ? 'retry ' : c.indeterminate || c.unproven ? 'open  ' : 'FAIL  ') + safe(c.name) + '  ' + safe(c.detail));
    for (const n of res.notes || []) console.log('note  ' + safe(n));
    if ((res.endpoints || []).length) {
      console.log('endpoints  ' + res.endpoints.map(safe).join(', '));
      if (res.officialEndpoints === false) console.log('notice  endpoints other than the official ones of this network were consulted, an anchor confirmed only by them is not proven');
    }
    console.log(res.status.toUpperCase());
  }
  return res.status === 'valid' ? 0 : res.status === 'indeterminate' || res.status === 'unproven' ? 2 : 1;
}

async function cmdRef(positional) {
  if (positional.length !== 1) throw usageError('ref takes one consent envelope');
  const env = readJson(positional[0], 'consent', true);
  console.log(qc.consentRef(env));
  return 0;
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    console.log(HELP);
    return command ? 0 : 64;
  }
  if (!Object.hasOwn(SPEC, command)) throw usageError('unknown command ' + safe(command).slice(0, 40));
  const { positional, flags } = parse(command, rest);
  const run = { keygen: cmdKeygen, key: cmdKey, grant: cmdGrant, acknowledge: cmdAcknowledge, revoke: cmdRevoke, status: cmdStatus, subject: cmdSubject, anchor: cmdAnchor, complete: cmdComplete, verify: cmdVerify, ref: cmdRef }[command];
  return run(positional, flags);
}

function friendly(e) {
  if (e && typeof e.syscall === 'string' && typeof e.code === 'string') return 'a file could not be ' + (e.syscall === 'open' || e.syscall === 'read' ? 'opened' : 'written') + ' (' + e.code + ')';
  return (e && e.message) || String(e);
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    console.error(safe(friendly(e)).slice(0, 600));
    process.exitCode = e && (e.usage || e.code === 'QCONSENT_INVALID_INPUT') ? 64 : 1;
  },
);
