// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const nodeCrypto = require('crypto');

const FORMAT = 'qconsent/1';
const ALGORITHM = 'ML-DSA-65';
const KIND = 1201;
const TYPES = Object.freeze(['consent', 'acknowledge', 'revoke']);
const KEY_DOMAIN = Buffer.from('quantova/qconsent/key/1', 'ascii');
const REF_DOMAIN = Buffer.from('quantova/qconsent/ref/1', 'ascii');
const ANCHOR_DOMAIN = Buffer.from('quantova/qconsent/anchor/1', 'ascii');
const SUBJECT_DOMAIN = Buffer.from('quantova/qconsent/subject/1', 'ascii');
const MAGIC = Buffer.from('QCNS', 'ascii');
const VERSION = 1;
const PUBLIC_KEY_BYTES = 1952;
const SIGNATURE_BYTES = 3309;
const LABEL_MAX = 200;
const NOTE_MAX = 1000;
const CODES_MAX = 32;
const HEX32 = /^[0-9a-f]{64}$/;
const HEX16 = /^[0-9a-f]{32}$/;
const CODE = /^[a-z][a-z0-9_]{0,31}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MAX_LIFETIME_MS = 50 * 366 * 24 * 3600 * 1000;
const UNSAFE_TEXT = /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000\u2800\u115f\u1160\u3164\uffa0]/u;

const FIELDS = Object.freeze({
  consent: ['consentId', 'subjectRef', 'patientKeyId', 'granteeKeyId', 'granteeLabel', 'purposes', 'categories', 'validFrom', 'validUntil', 'grantedAt', 'note'],
  acknowledge: ['consentId', 'consentRef', 'granteeKeyId', 'acknowledgedAt', 'note'],
  revoke: ['consentId', 'consentRef', 'patientKeyId', 'revokedAt', 'note'],
});

function fail(message) {
  const e = new Error('the envelope is not valid, ' + message);
  e.code = 'QCONSENT_INVALID_ENVELOPE';
  throw e;
}

function reject(message) {
  const e = new Error(message);
  e.code = 'QCONSENT_INVALID_INPUT';
  throw e;
}

function sha3(...parts) {
  const h = nodeCrypto.createHash('sha3-256');
  for (const p of parts) h.update(p);
  return h.digest();
}

function keyIdOf(publicKey) {
  if (!((ArrayBuffer.isView(publicKey) && publicKey instanceof Uint8Array)) || publicKey.length !== PUBLIC_KEY_BYTES) reject('a public key is ' + PUBLIC_KEY_BYTES + ' bytes');
  return sha3(KEY_DOMAIN, Buffer.from([0]), publicKey).toString('hex');
}

function subjectRefOf(secret, identity) {
  if (!((ArrayBuffer.isView(secret) && secret instanceof Uint8Array)) || secret.length !== 32) reject('the subject secret is a 32 byte Uint8Array held by the grantee');
  if (new Set(secret).size < 13) reject('a subject secret made of too few different byte values is refused, draw it from a secure random source');
  if (typeof identity !== 'string' || identity.length === 0 || identity.length > LABEL_MAX) reject('the patient identity is 1 to ' + LABEL_MAX + ' characters');
  if (!identity.isWellFormed() || identity.normalize('NFC') !== identity || UNSAFE_TEXT.test(identity)) reject('the patient identity must be well formed text in Unicode normal form C');
  return sha3(SUBJECT_DOMAIN, Buffer.from([0]), Buffer.from(secret), Buffer.from(identity, 'utf8')).toString('hex');
}

function textProblem(value, max, what, required) {
  if (typeof value !== 'string') return what + ' must be text';
  if (required && value.length === 0) return what + ' cannot be empty';
  if (value.length > max) return what + ' is longer than ' + max + ' characters';
  if (!value.isWellFormed()) return what + ' holds a broken Unicode surrogate';
  if (value.normalize('NFC') !== value) return what + ' must be in Unicode normal form C';
  if (UNSAFE_TEXT.test(value)) return what + ' holds control, invisible or direction characters';
  return null;
}

function timeProblem(value, what) {
  if (typeof value !== 'string' || !ISO_UTC.test(value)) return what + ' must be an ISO 8601 UTC time with milliseconds and a Z suffix';
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value) return what + ' is not a real calendar time';
  return null;
}

function pattern(value, re, what, rule) {
  if (typeof value !== 'string' || !re.test(value)) return what + ' must be ' + rule;
  return null;
}

function refProblem(value, empty, what) {
  if (empty && value === '') return null;
  if (typeof value !== 'string' || !HEX32.test(value)) return what + ' must be 64 lowercase hex characters' + (empty ? ', or empty' : '');
  return null;
}

function codeListProblem(list, what) {
  if (!Array.isArray(list) || list.length === 0 || list.length > CODES_MAX) return what + ' must list 1 to ' + CODES_MAX + ' codes';
  let last = '';
  for (const code of list) {
    if (typeof code !== 'string' || !CODE.test(code)) return 'each ' + what + ' code is lowercase letters, digits or underscores, 1 to 32 characters, starting with a letter';
    if (code <= last) return what + ' must be sorted in ascending order with no repeats';
    last = code;
  }
  return null;
}

function statementProblem(type, st) {
  if (!TYPES.includes(type)) return 'type must be one of ' + TYPES.join(', ');
  if (st === null || typeof st !== 'object' || Array.isArray(st)) return 'the statement must be an object';
  const fields = FIELDS[type];
  if (Object.keys(st).sort().join(',') !== fields.slice().sort().join(',')) return 'a ' + type + ' statement holds exactly ' + fields.join(', ');
  const checks = [];
  checks.push(pattern(st.consentId, HEX16, 'consentId', '32 lowercase hex characters'));
  checks.push(textProblem(st.note, NOTE_MAX, 'note', false));
  if (type === 'consent') {
    checks.push(refProblem(st.subjectRef, true, 'subjectRef'));
    checks.push(pattern(st.patientKeyId, HEX32, 'patientKeyId', '64 lowercase hex characters'));
    checks.push(pattern(st.granteeKeyId, HEX32, 'granteeKeyId', '64 lowercase hex characters'));
    checks.push(textProblem(st.granteeLabel, LABEL_MAX, 'granteeLabel', false));
    checks.push(codeListProblem(st.purposes, 'purposes'));
    checks.push(codeListProblem(st.categories, 'categories'));
    checks.push(timeProblem(st.validFrom, 'validFrom'), timeProblem(st.validUntil, 'validUntil'), timeProblem(st.grantedAt, 'grantedAt'));
    if (!checks.some(Boolean) && Date.parse(st.validFrom) >= Date.parse(st.validUntil)) checks.push('validFrom must be earlier than validUntil');
    if (!checks.some(Boolean) && Date.parse(st.validUntil) - Date.parse(st.validFrom) > MAX_LIFETIME_MS) checks.push('a consent may last at most fifty years');
    if (!checks.some(Boolean) && st.patientKeyId === st.granteeKeyId) checks.push('the grantee key must differ from the patient key');
  } else if (type === 'acknowledge') {
    checks.push(refProblem(st.consentRef, false, 'consentRef'));
    checks.push(pattern(st.granteeKeyId, HEX32, 'granteeKeyId', '64 lowercase hex characters'));
    checks.push(timeProblem(st.acknowledgedAt, 'acknowledgedAt'));
  } else {
    checks.push(refProblem(st.consentRef, false, 'consentRef'));
    checks.push(pattern(st.patientKeyId, HEX32, 'patientKeyId', '64 lowercase hex characters'));
    checks.push(timeProblem(st.revokedAt, 'revokedAt'));
  }
  return checks.find(Boolean) || null;
}

function field(buf) {
  if (buf.length > 0xffff) reject('a signed field is too long');
  const len = Buffer.alloc(2);
  len.writeUInt16BE(buf.length);
  return Buffer.concat([len, buf]);
}

function count(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n);
  return field(b);
}

const ascii = (s) => field(Buffer.from(s, 'ascii'));
const utf8 = (s) => field(Buffer.from(s, 'utf8'));
const hex = (s) => field(Buffer.from(s, 'hex'));

function payload(type, st) {
  const parts = [MAGIC, Buffer.from([VERSION]), ascii(type), hex(st.consentId)];
  if (type === 'consent') {
    parts.push(hex(st.subjectRef === '' ? '' : st.subjectRef), hex(st.patientKeyId), hex(st.granteeKeyId), utf8(st.granteeLabel));
    parts.push(count(st.purposes.length));
    for (const code of st.purposes) parts.push(ascii(code));
    parts.push(count(st.categories.length));
    for (const code of st.categories) parts.push(ascii(code));
    parts.push(ascii(st.validFrom), ascii(st.validUntil), ascii(st.grantedAt));
  } else if (type === 'acknowledge') {
    parts.push(hex(st.consentRef), hex(st.granteeKeyId), ascii(st.acknowledgedAt));
  } else {
    parts.push(hex(st.consentRef), hex(st.patientKeyId), ascii(st.revokedAt));
  }
  parts.push(utf8(st.note));
  return Buffer.concat(parts);
}

function decodeBase64(value, bytes, what) {
  if (typeof value !== 'string' || value.length !== Math.ceil(bytes / 3) * 4) fail(what + ' must be base64 of ' + bytes + ' bytes');
  const raw = Buffer.from(value, 'base64');
  if (raw.toString('base64') !== value || raw.length !== bytes) fail(what + ' is not canonical base64 of ' + bytes + ' bytes');
  return raw;
}

function exactKeys(obj, required, optional, where) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) fail(where + ' must be an object');
  const allowed = new Set(required.concat(optional));
  for (const k of Object.keys(obj)) if (!allowed.has(k)) fail(where + ' holds an unexpected field');
  for (const k of required) if (!Object.prototype.hasOwnProperty.call(obj, k)) fail(where + ' is missing ' + k);
}

function plainCopy(value, depth) {
  const d = depth === undefined ? 0 : depth;
  if (d > 6) throw new Error('nested too deeply');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('not a finite number');
    return value;
  }
  if (typeof value !== 'object') throw new Error('not plain data');
  const proto = Object.getPrototypeOf(value);
  if (Array.isArray(value)) {
    if (proto !== Array.prototype) throw new Error('not a plain array');
    if (value.length > 4096) throw new Error('a list is too long');
    const out = [];
    for (let i = 0; i < value.length; i += 1) {
      const desc = Object.getOwnPropertyDescriptor(value, i);
      if (!desc || !('value' in desc)) throw new Error('not plain data');
      out.push(plainCopy(desc.value, d + 1));
    }
    return out;
  }
  if (proto !== Object.prototype && proto !== null) throw new Error('not a plain object');
  const out = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') throw new Error('not plain data');
    const desc = Object.getOwnPropertyDescriptor(value, key);
    if (!('value' in desc) || !desc.enumerable) throw new Error('not plain data');
    Object.defineProperty(out, key, { value: plainCopy(desc.value, d + 1), enumerable: true, writable: true, configurable: true });
  }
  return out;
}

function parse(envelope) {
  exactKeys(envelope, ['format', 'type', 'algorithm', 'signer', 'statement', 'signature'], ['anchor'], 'the envelope');
  if (envelope.format !== FORMAT) fail('format must be ' + FORMAT);
  if (envelope.algorithm !== ALGORITHM) fail('algorithm must be ' + ALGORITHM);
  if (!TYPES.includes(envelope.type)) fail('type must be one of ' + TYPES.join(', '));
  exactKeys(envelope.signer, ['id', 'publicKey'], [], 'signer');
  if (typeof envelope.signer.id !== 'string' || !HEX32.test(envelope.signer.id)) fail('signer.id must be 64 lowercase hex characters');
  const publicKey = decodeBase64(envelope.signer.publicKey, PUBLIC_KEY_BYTES, 'signer.publicKey');
  let statement;
  try {
    statement = plainCopy(envelope.statement);
  } catch (e) {
    fail('the statement is not plain data');
  }
  const problem = statementProblem(envelope.type, statement);
  if (problem) fail(problem);
  const signature = decodeBase64(envelope.signature, SIGNATURE_BYTES, 'signature');
  const anchor = Object.prototype.hasOwnProperty.call(envelope, 'anchor') ? envelope.anchor : undefined;
  return { type: envelope.type, signerId: envelope.signer.id, publicKey, statement, signature, anchor };
}

function encoded(parsed) {
  return payload(parsed.type, parsed.statement);
}

function refOf(parsed) {
  return sha3(REF_DOMAIN, Buffer.from([0]), encoded(parsed), parsed.signature).toString('hex');
}

function anchorDigest(parsed) {
  return sha3(ANCHOR_DOMAIN, Buffer.from([0]), encoded(parsed), parsed.signature);
}

module.exports = {
  FORMAT, ALGORITHM, KIND, TYPES, FIELDS, PUBLIC_KEY_BYTES, SIGNATURE_BYTES, LABEL_MAX, NOTE_MAX, CODES_MAX,
  sha3, keyIdOf, subjectRefOf, textProblem, timeProblem, statementProblem, payload, encoded, parse, refOf, anchorDigest, reject, plainCopy,
};
