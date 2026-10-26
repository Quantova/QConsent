/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const publicKey: (a: number, b: number) => [number, number, number, number];
export const publicKeyBytes: () => number;
export const sign: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
export const signatureBytes: () => number;
export const verify: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
export const __wbindgen_externrefs: WebAssembly.Table;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_start: () => void;
