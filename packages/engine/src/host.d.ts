// The only host APIs the engine may use (engine-spec §1.1). All are standard Web APIs,
// available in Node.js and browsers, so the engine stays portable to the browser grader.
// - performance.now(): Decision.elapsedMs and the hardStopMs backstop, never for logic
// - TextEncoder / TextDecoder / atob: byte ↔ text conversion (no I/O)
declare const performance: { now(): number };
declare class TextEncoder { encode(input?: string): Uint8Array }
declare class TextDecoder {
  constructor(label?: string, options?: { fatal?: boolean; ignoreBOM?: boolean });
  decode(input?: Uint8Array): string;
}
declare function atob(data: string): string;
// Referenced by valibot's type declarations only (file/blob schemas, never used here).
interface Blob { readonly size: number; readonly type: string }
interface File extends Blob { readonly name: string }
