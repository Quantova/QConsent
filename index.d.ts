// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type EnvelopeType = 'consent' | 'acknowledge' | 'revoke';

export interface Envelope {
  format: 'qconsent/1';
  type: EnvelopeType;
  algorithm: 'ML-DSA-65';
  signer: { id: string; publicKey: string };
  statement: Record<string, unknown>;
  signature: string;
  anchor?: unknown;
}

export interface KeyDescription {
  format: 'qconsent-key/1';
  algorithm: 'ML-DSA-65';
  id: string;
  publicKey: string;
}

export interface GrantOptions {
  key: Uint8Array;
  grantee: KeyDescription | Uint8Array | string;
  granteeLabel?: string;
  purposes: string[];
  categories: string[];
  validFrom?: string;
  validUntil: string;
  subjectRef?: string;
  note?: string;
}

export interface AcknowledgeOptions {
  key: Uint8Array;
  consent: Envelope;
  acknowledgedAt?: string;
  note?: string;
}

export interface RevokeOptions {
  key: Uint8Array;
  consent: Envelope;
  revokedAt?: string;
  note?: string;
}

export interface EndpointOptions {
  network?: 'testnet';
  rpc?: string | string[];
  client?: unknown;
  clients?: Array<string | unknown>;
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
  endpointAllowList?: string[];
  clockSlackMs?: number;
  strict?: boolean;
}

export interface StatusOptions extends EndpointOptions {
  at?: string;
  granteeKeyId?: KeyDescription | Uint8Array | string;
  revocations?: Envelope[];
}

export interface StatusResult {
  active: boolean;
  reasons: string[];
  consentId: string;
  consentRef: string;
  patientKeyId: string;
  granteeKeyId: string;
  purposes: string[];
  categories: string[];
  validFrom: string;
  validUntil: string;
  revokedAt: string | null;
  at: string;
  atSupplied: boolean;
  chainTime: string;
}

export interface AnchorOptions extends EndpointOptions {
  seed: Uint8Array;
  index: number;
  meter?: number;
  maxFee?: string | number;
  timeoutMs?: number;
  onPending?: (pending: unknown) => void | Promise<void>;
}

export interface VerifyOptions {
  type: EnvelopeType;
  network: 'testnet' | 'custom';
  consent?: Envelope;
  patientKeyId?: string;
  patientPublicKey?: Uint8Array | string;
  granteeKeyId?: string;
  granteePublicKey?: Uint8Array | string;
  revocations?: Envelope[];
  strict?: boolean;
  requireAnchor?: boolean;
  maxAnchorDelay?: number;
  at?: string;
  rpc?: string | string[];
  client?: unknown;
  clients?: Array<string | unknown>;
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
  endpointAllowList?: string[];
  expectedSender?: string | string[];
  contract?: string;
  trustCustomContract?: boolean;
}

export interface VerifyCheck {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
  unproven: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'invalid' | 'indeterminate' | 'unproven';
  type: EnvelopeType | null;
  checks: VerifyCheck[];
  notes?: string[];
  [field: string]: unknown;
  endpoints: string[];
  officialEndpoints: boolean | null;
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function subjectRef(secret: Uint8Array, identity: string): string;
export function grant(options: GrantOptions): Envelope;
export function acknowledge(options: AcknowledgeOptions): Envelope;
export function revoke(options: RevokeOptions): Envelope;
export function status(consent: Envelope, options?: StatusOptions): Promise<StatusResult>;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: EndpointOptions & { timeoutMs?: number }): Promise<Envelope[]>;
export function verify(envelope: unknown, options: VerifyOptions): Promise<VerifyResult>;
export function consentRef(consent: Envelope): string;
export function anchorDigest(envelope: Envelope): string;
export const FORMAT: 'qconsent/1';
export const ALGORITHM: 'ML-DSA-65';
export const KIND: number;
export const TYPES: readonly EnvelopeType[];
export const PUBLIC_KEY_BYTES: number;
export const SIGNATURE_BYTES: number;
