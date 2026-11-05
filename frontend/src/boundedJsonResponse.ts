/** Development safety guards, not historical operating limits or server request budgets. */
export interface JsonResponseLimits { readonly maxResponseBytes: number; readonly maxJsonDepth: number }
export const DEVELOPMENT_RESPONSE_LIMITS: Readonly<JsonResponseLimits> = Object.freeze({ maxResponseBytes: 1048576, maxJsonDepth: 32 });
export function responseLimits(input: JsonResponseLimits): Readonly<JsonResponseLimits> {
  if (!input || typeof input !== 'object') throw new Error('INVALID_RESPONSE_LIMITS');
  const values = ['maxResponseBytes', 'maxJsonDepth'].map(key => {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    const value: unknown = descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > 2147483647) throw new Error('INVALID_RESPONSE_LIMITS');
    return value;
  });
  return Object.freeze({ maxResponseBytes: values[0], maxJsonDepth: values[1] });
}
/** Scan decoded JSON keys and nesting before databinding; JSON.parse still verifies the full grammar. */
function strictJson(text: string, maximumDepth: number): unknown {
  const stack: { object: boolean; key: boolean; keys: Set<string> }[] = [];
  for (let at = 0; at < text.length; at += 1) {
    const ch = text[at];
    if (ch === '"') {
      const start = at; let ended = false;
      while (++at < text.length) {
        if (text[at] === '\\') { at += 1; continue; }
        if (text[at] === '"') { ended = true; break; }
      }
      if (!ended) throw new Error();
      const token: unknown = JSON.parse(text.slice(start, at + 1));
      const frame = stack[stack.length - 1];
      if (frame?.object && frame.key) {
        if (typeof token !== 'string' || frame.keys.has(token)) throw new Error();
        frame.keys.add(token); frame.key = false;
      }
    } else if (ch === '{' || ch === '[') {
      if (stack.length >= maximumDepth) throw new Error();
      stack.push({ object: ch === '{', key: ch === '{', keys: new Set() });
    } else if (ch === '}' || ch === ']') {
      const frame = stack.pop(); if (!frame || frame.object !== (ch === '}')) throw new Error();
    } else if (ch === ',' && stack[stack.length - 1]?.object) stack[stack.length - 1].key = true;
  }
  if (stack.length) throw new Error();
  return JSON.parse(text, (_key: string, value: unknown) => {
    if (typeof value === 'number' && !Number.isFinite(value)) throw new Error(); return value;
  });
}

/** Counts decoded stream bytes, never falls back to json/text; browser allocations are outside this bound. */
export async function readBoundedJson(response: Response, configured: JsonResponseLimits): Promise<unknown> {
  const limits = responseLimits(configured);
  const reader = response.body?.getReader();
  if (!reader) throw new Error('INVALID_RESPONSE');
  let ended = false;
  try {
    const length = response.headers.get('Content-Length');
    if (length !== null && (!/^[0-9]+$/.test(length) || length.length > 15 || Number(length) > limits.maxResponseBytes)) throw new Error('INVALID_RESPONSE');
    const chunks: Uint8Array[] = []; let total = 0;
    for (;;) {
      const next = await reader.read();
      if (next.done) { ended = true; break; }
      if (!(next.value instanceof Uint8Array) || next.value.byteLength > limits.maxResponseBytes - total) throw new Error('INVALID_RESPONSE');
      if (next.value.byteLength === 0) continue;
      total += next.value.byteLength; chunks.push(next.value.slice());
    }
    const bytes = new Uint8Array(total); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return strictJson(new TextDecoder('utf-8', { fatal: true }).decode(bytes), limits.maxJsonDepth);
  } catch {
    throw new Error('INVALID_RESPONSE');
  } finally {
    // Do not await an unbounded cancellation promise. Attempt lock release even if cancellation throws.
    if (!ended) { try { void reader.cancel().catch(() => undefined); } catch { /* best effort */ } }
    try { reader.releaseLock(); } catch { /* no physical cleanup claim */ }
  }
}
