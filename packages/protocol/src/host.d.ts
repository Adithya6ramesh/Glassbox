// The only host APIs the protocol package may use. Standard Web APIs, available in
// Node.js and browsers.
// - TextEncoder: measure the UTF-8 size of an event (size limits are in bytes)
declare class TextEncoder { encode(input?: string): Uint8Array }
// Referenced by valibot's type declarations only (file/blob schemas, never used here).
interface Blob { readonly size: number; readonly type: string }
interface File extends Blob { readonly name: string }
