import { sha256 } from "@noble/hashes/sha2.js";

const encoder = new TextEncoder();
const HEX = "0123456789abcdef";

export function utf8(s: string): Uint8Array {
  return encoder.encode(s);
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += (HEX[b >> 4] as string) + (HEX[b & 15] as string);
  return out;
}

export function sha256Hex(s: string | Uint8Array): string {
  return toHex(sha256(typeof s === "string" ? utf8(s) : s));
}
