// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const wasm = require('../wasm/qconsent_native.js');

function bytes(value, label) {
  if (!((ArrayBuffer.isView(value) && value instanceof Uint8Array)) || !(value.buffer instanceof ArrayBuffer)) throw new Error(label + ' must be a Uint8Array');
  return Uint8Array.from(value);
}

module.exports = {
  publicKey: (seed) => {
    const s = bytes(seed, 'the signing key');
    try {
      return Uint8Array.from(wasm.publicKey(s));
    } finally {
      s.fill(0);
    }
  },
  sign: (seed, message, randomness) => {
    const s = bytes(seed, 'the signing key');
    let r;
    try {
      r = bytes(randomness, 'the randomness');
      return Uint8Array.from(wasm.sign(s, bytes(message, 'the message'), r));
    } finally {
      s.fill(0);
      if (r) r.fill(0);
    }
  },
  verify: (publicKey, message, signature) => wasm.verify(bytes(publicKey, 'the public key'), bytes(message, 'the message'), bytes(signature, 'the signature')),
  PUBLIC_KEY_BYTES: wasm.publicKeyBytes(),
  SIGNATURE_BYTES: wasm.signatureBytes(),
};
