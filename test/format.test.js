// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const qc = require('..');

function soon(days) {
  return new Date(Date.now() + days * 86400 * 1000).toISOString();
}

function grant(extra) {
  const patient = qc.generateKey();
  const grantee = qc.generateKey();
  return qc.grant(Object.assign({
    key: patient,
    grantee: qc.describeKey(grantee),
    purposes: ['diagnosis', 'treatment'],
    categories: ['allergies', 'medications'],
    validUntil: soon(365),
  }, extra));
}

test('a consent is a well formed envelope', () => {
  const c = grant({ granteeLabel: 'Tokyo General Hospital', note: 'cardiology' });
  assert.equal(c.format, 'qconsent/1');
  assert.equal(c.type, 'consent');
  assert.equal(c.algorithm, 'ML-DSA-65');
  assert.match(c.signer.id, /^[0-9a-f]{64}$/);
  assert.equal(c.statement.patientKeyId, c.signer.id);
  assert.match(c.signature, /^[A-Za-z0-9+/]+=*$/);
  assert.equal(Buffer.from(c.signature, 'base64').length, qc.SIGNATURE_BYTES);
  assert.equal(Buffer.from(c.signer.publicKey, 'base64').length, qc.PUBLIC_KEY_BYTES);
});

test('consentRef is stable and the signature binds the statement', () => {
  const c = grant({});
  const ref = qc.consentRef(c);
  assert.match(ref, /^[0-9a-f]{64}$/);
  assert.equal(qc.consentRef(JSON.parse(JSON.stringify(c))), ref);
  const tampered = JSON.parse(JSON.stringify(c));
  tampered.statement.purposes = ['diagnosis', 'marketing'];
  assert.throws(() => qc.consentRef(tampered), (e) => e.code === 'QCONSENT_INVALID_CONSENT' && /signature does not verify/.test(e.message));
});

test('a flipped signature bit is rejected', () => {
  const c = grant({});
  const bad = JSON.parse(JSON.stringify(c));
  const sig = Buffer.from(bad.signature, 'base64');
  sig[0] ^= 1;
  bad.signature = sig.toString('base64');
  assert.throws(() => qc.consentRef(bad));
});

test('purposes and categories must be sorted, deduped code lists', () => {
  assert.throws(() => grant({ purposes: [] }), /purposes/);
  assert.throws(() => grant({ purposes: ['b', 'a'] }), /ascending/);
  assert.throws(() => grant({ purposes: ['a', 'a'] }), /ascending/);
  assert.throws(() => grant({ categories: ['UPPER'] }), /lowercase/);
  assert.throws(() => grant({ purposes: Array.from({ length: 33 }, (_, i) => 'p' + i) }), /1 to 32/);
});

test('the grantee key must differ from the patient key', () => {
  const patient = qc.generateKey();
  assert.throws(() => qc.grant({ key: patient, grantee: qc.describeKey(patient), purposes: ['a'], categories: ['x'], validUntil: soon(10) }), /grantee key/);
});

test('validity window and lifetime are checked', () => {
  assert.throws(() => grant({ validFrom: soon(10), validUntil: soon(5) }), /earlier than validUntil/);
  assert.throws(() => grant({ validFrom: soon(0), validUntil: soon(60 * 366) }), /fifty years/);
  assert.throws(() => grant({ validUntil: 'not a time' }), /ISO 8601/);
});

test('validUntil and grantee are required', () => {
  const patient = qc.generateKey();
  assert.throws(() => qc.grant({ key: patient, grantee: qc.describeKey(qc.generateKey()), purposes: ['a'], categories: ['x'] }), /validUntil is required/);
  assert.throws(() => qc.grant({ key: patient, purposes: ['a'], categories: ['x'], validUntil: soon(10) }), /grantee is required/);
});

test('an unknown option is refused and nothing is signed', () => {
  const patient = qc.generateKey();
  assert.throws(() => qc.grant({ key: patient, grantee: qc.describeKey(qc.generateKey()), purposes: ['a'], categories: ['x'], validUntil: soon(10), scope: 'oops' }), /not an option of grant/);
});

test('acknowledge only by the named grantee', () => {
  const patient = qc.generateKey();
  const grantee = qc.generateKey();
  const consent = qc.grant({ key: patient, grantee: qc.describeKey(grantee), purposes: ['a'], categories: ['x'], validUntil: soon(10) });
  const ack = qc.acknowledge({ key: grantee, consent });
  assert.equal(ack.type, 'acknowledge');
  assert.equal(ack.statement.consentRef, qc.consentRef(consent));
  assert.equal(ack.statement.granteeKeyId, qc.keyId(grantee));
  assert.throws(() => qc.acknowledge({ key: qc.generateKey(), consent }), /only the grantee/);
  assert.throws(() => qc.acknowledge({ key: patient, consent }), /only the grantee/);
});

test('revoke only by the patient, and it binds the exact consent', () => {
  const patient = qc.generateKey();
  const grantee = qc.generateKey();
  const consent = qc.grant({ key: patient, grantee: qc.describeKey(grantee), purposes: ['a'], categories: ['x'], validUntil: soon(10) });
  const rev = qc.revoke({ key: patient, consent });
  assert.equal(rev.type, 'revoke');
  assert.equal(rev.statement.consentRef, qc.consentRef(consent));
  assert.equal(rev.statement.patientKeyId, qc.keyId(patient));
  assert.throws(() => qc.revoke({ key: grantee, consent }), /only the patient/);
});

test('subjectRef is a deterministic salted commitment that hides the identity', () => {
  const secret = new Uint8Array(32);
  crypto.randomFillSync(secret);
  const a = qc.subjectRef(secret, 'Patient 12345 Tokyo');
  const b = qc.subjectRef(secret, 'Patient 12345 Tokyo');
  assert.equal(a, b);
  assert.match(a, /^[0-9a-f]{64}$/);
  const other = new Uint8Array(32);
  crypto.randomFillSync(other);
  assert.notEqual(qc.subjectRef(other, 'Patient 12345 Tokyo'), a);
  assert.notEqual(qc.subjectRef(secret, 'Patient 99999 Osaka'), a);
  assert.throws(() => qc.subjectRef(new Uint8Array(16), 'x'), /32 byte/);
  assert.throws(() => qc.subjectRef(new Uint8Array(32), 'x'), /different byte values/);
});

test('a consent carries a subject reference unchanged', () => {
  const secret = new Uint8Array(32);
  crypto.randomFillSync(secret);
  const sr = qc.subjectRef(secret, 'Patient 12345 Tokyo');
  const c = grant({ subjectRef: sr });
  assert.equal(c.statement.subjectRef, sr);
});

test('a key is a 32 byte seed and too little entropy is refused', () => {
  assert.throws(() => qc.publicKey(new Uint8Array(31)), /32 byte/);
  assert.throws(() => qc.publicKey(new Uint8Array(32)), /different byte values/);
});

test('a key description hides the seed and never serialises it', () => {
  const key = qc.generateKey();
  assert.equal(JSON.stringify(key), '"SecretKey [hidden]"');
  const desc = qc.describeKey(key);
  assert.equal(desc.format, 'qconsent-key/1');
  assert.equal(desc.id, qc.keyId(key));
});

test('a record of one type can never be read as another', () => {
  const patient = qc.generateKey();
  const grantee = qc.generateKey();
  const consent = qc.grant({ key: patient, grantee: qc.describeKey(grantee), purposes: ['a'], categories: ['x'], validUntil: soon(10) });
  const rev = qc.revoke({ key: patient, consent });
  assert.throws(() => qc.consentRef(rev), /not a consent|QCONSENT_INVALID_CONSENT/);
});
