// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const qc = require('..');
const qstamp = require('@quantovainc/qstamp');
const { honest, provenByPinnedOperators } = require('./honest');

test('the shared deadline stops anchor checks across the whole verify pass', async () => {
  const h = await honest();
  const restore = provenByPinnedOperators();
  const realVerify = qstamp.verify;
  let calls = 0;
  qstamp.verify = (...a) => {
    calls += 1;
    return realVerify(...a);
  };
  const perf = require('perf_hooks').performance;
  const realNow = perf.now.bind(perf);
  let first = true;
  perf.now = () => {
    if (first) {
      first = false;
      return 0;
    }
    return 1e12;
  };
  try {
    const opts = Object.assign({}, h.options.consent, { revocations: [h.records.revoke] });
    const res = await qc.verify(h.records.consent, opts);
    assert.equal(calls, 0);
    assert.notEqual(res.status, 'valid');
    assert.ok(res.checks.some((x) => !x.ok && /reached its time limit/.test(x.detail)));
  } finally {
    perf.now = realNow;
    qstamp.verify = realVerify;
    restore();
  }
});

test('a generous deadline still checks every anchor', async () => {
  const h = await honest();
  const restore = provenByPinnedOperators();
  try {
    const res = await qc.verify(h.records.consent, Object.assign({}, h.options.consent, { deadlineMs: 600000 }));
    assert.equal(res.status, 'valid', JSON.stringify(res.checks.filter((x) => !x.ok)));
  } finally {
    restore();
  }
});

test('deadlineMs is bounded', async () => {
  const h = await honest();
  await assert.rejects(qc.verify(h.records.consent, Object.assign({}, h.options.consent, { deadlineMs: 0 })), /deadlineMs/);
  await assert.rejects(qc.verify(h.records.consent, Object.assign({}, h.options.consent, { deadlineMs: 600001 })), /deadlineMs/);
});
