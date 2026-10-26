/* tslint:disable */
/* eslint-disable */

export function publicKey(seed_bytes: Uint8Array): Uint8Array;

export function publicKeyBytes(): number;

export function sign(seed_bytes: Uint8Array, message: Uint8Array, randomness: Uint8Array): Uint8Array;

export function signatureBytes(): number;

export function verify(public_key: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
