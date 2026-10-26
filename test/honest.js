// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const path = require('path');
const qc = require('..');
const { makeChain, client, SEED } = require('./chain');

const ROOT = path.join(__dirname, '..');
const qstamp = require('@quantovainc/qstamp');

function provenByPinnedOperators() {
  const had = Object.prototype.hasOwnProperty.call(qstamp, 'isProven');
  const before = qstamp.isProven;
  qstamp.isProven = (r) => !!r && r.status === 'unproven' && Array.isArray(r.checks) && r.checks.every((c) => c.ok || c.name === 'proof');
  return () => {
    if (had) qstamp.isProven = before;
    else delete qstamp.isProven;
  };
}

function iso(ms) {
  return new Date(ms).toISOString();
}

async function honest() {
  const chain = makeChain(ROOT);
  const ep = { network: 'testnet', trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const patient = qc.generateKey();
  const grantee = qc.generateKey();
  const consent = qc.grant({
    key: patient,
    grantee: qc.describeKey(grantee),
    granteeLabel: 'Tokyo General Hospital',
    purposes: ['diagnosis', 'treatment'],
    categories: ['allergies', 'medications'],
    validFrom: iso(chain.time * 1000 - 60000),
    validUntil: iso((chain.time + 30 * 86400) * 1000 + 537),
    note: 'outpatient cardiology',
  });
  const [c] = await qc.anchor(consent, Object.assign({ seed: SEED, index: 0 }, ep));
  const acknowledgement = qc.acknowledge({ key: grantee, consent: c });
  const [ack] = await qc.anchor(acknowledgement, Object.assign({ seed: SEED, index: 0 }, ep));
  const revocation = qc.revoke({ key: patient, consent: c, note: 'care ended' });
  const [rv] = await qc.anchor(revocation, Object.assign({ seed: SEED, index: 0 }, ep));
  const at = iso((chain.time + 1) * 1000);
  const patientKeyId = qc.keyId(patient);
  const granteeKeyId = qc.keyId(grantee);
  const options = {
    consent: Object.assign({ type: 'consent', patientKeyId, granteeKeyId, revocations: [], at }, ep),
    acknowledge: Object.assign({ type: 'acknowledge', consent: c, at }, ep),
    revoke: Object.assign({ type: 'revoke', consent: c, patientKeyId, at }, ep),
  };
  const records = { consent: c, acknowledge: ack, revoke: rv };
  const plain = { consent, acknowledge: acknowledgement, revoke: revocation };
  const plainOptions = {
    consent: Object.assign({}, options.consent, { requireAnchor: false }),
    acknowledge: Object.assign({}, options.acknowledge, { consent, requireAnchor: false }),
    revoke: Object.assign({}, options.revoke, { consent, requireAnchor: false }),
  };
  return { qc, chain, ep, patient, grantee, patientKeyId, granteeKeyId, records, plain, options, plainOptions, at };
}

module.exports = { honest, provenByPinnedOperators, iso, ROOT };
