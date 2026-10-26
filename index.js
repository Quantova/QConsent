// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const C = require('./lib/consent');
const { verify } = require('./lib/verify');
const F = require('./lib/format');

module.exports = {
  generateKey: C.generateKey,
  publicKey: C.publicKey,
  keyId: C.keyId,
  describeKey: C.describeKey,
  subjectRef: C.subjectRef,
  grant: C.grant,
  acknowledge: C.acknowledge,
  revoke: C.revoke,
  status: C.status,
  anchor: C.anchor,
  complete: C.complete,
  verify,
  consentRef: (consent) => F.refOf(C.consentOf(consent)),
  anchorDigest: (envelope) => F.anchorDigest(F.parse(envelope)).toString('hex'),
  FORMAT: F.FORMAT,
  ALGORITHM: F.ALGORITHM,
  KIND: F.KIND,
  TYPES: F.TYPES,
  PUBLIC_KEY_BYTES: F.PUBLIC_KEY_BYTES,
  SIGNATURE_BYTES: F.SIGNATURE_BYTES,
};
