import { describe, expect, it, vi } from 'vitest';
import { readBoundedJson, responseLimits } from './boundedJsonResponse';

const encode = (text: string) => new TextEncoder().encode(text);
const limits = (maxResponseBytes = 1048576, maxJsonDepth = 32) => ({ maxResponseBytes, maxJsonDepth });
function response(chunks: Uint8Array[], headers: HeadersInit = {}) {
  return new Response(new ReadableStream<Uint8Array>({ start(stream) {
    for (const chunk of chunks) stream.enqueue(chunk);
    stream.close();
  } }), { headers });
}
describe('bounded inert JSON response boundary', () => {
  it('accepts exact bytes and rejects one excess byte across separate chunks without json fallback', async () => {
    const exact = response([encode('{"x":'), encode('1}')]);
    const fallback = vi.spyOn(exact, 'json');
    await expect(readBoundedJson(exact, limits(7))).resolves.toEqual({ x: 1 });
    expect(fallback).not.toHaveBeenCalled();
    await expect(readBoundedJson(response([encode('{"x":1}'), encode(' ')]), limits(7))).rejects.toThrow('INVALID_RESPONSE');
  });
  it('rejects declared excess before reading and always attempts cancel plus release even when cleanup fails', async () => {
    const read = vi.fn(); const cancel = vi.fn(() => { throw new Error('PRIVATE_CLEANUP'); });
    const releaseLock = vi.fn(() => { throw new Error('PRIVATE_LOCK'); });
    const wire = { headers: new Headers({ 'Content-Length': '8' }), body: { getReader: () => ({ read, cancel, releaseLock }) } } as unknown as Response;
    await expect(readBoundedJson(wire, limits(7))).rejects.toThrow('INVALID_RESPONSE');
    expect(read).not.toHaveBeenCalled(); expect(cancel).toHaveBeenCalledTimes(1); expect(releaseLock).toHaveBeenCalledTimes(1);
  });
  it.each(['{"a":1,"\\u0061":2}', '{"a":{"x":1,"x":2}}', '{"x":1e999}', '{"x":]'])('rejects ambiguous or invalid JSON %s', async text => {
    await expect(readBoundedJson(response([encode(text)]), limits())).rejects.toThrow('INVALID_RESPONSE');
  });
  it('counts containers rather than brackets and escaped quotes inside strings at the depth boundary', async () => {
    const value = '['.repeat(31) + '{"x":"[\\\"]"}' + ']'.repeat(31);
    await expect(readBoundedJson(response([encode(value)]), limits())).resolves.toBeDefined();
    await expect(readBoundedJson(response([encode('[' + value + ']')]), limits())).rejects.toThrow('INVALID_RESPONSE');
  });
  it('fatal-decodes UTF8 while allowing a multibyte character split between chunks', async () => {
    const bytes = encode('"가"');
    await expect(readBoundedJson(response([bytes.slice(0, 2), bytes.slice(2)]), limits())).resolves.toBe('가');
    await expect(readBoundedJson(response([new Uint8Array([34, 255, 34])]), limits())).rejects.toThrow('INVALID_RESPONSE');
  });
  it('does not wait indefinitely for cancellation and releases the reader after a stream failure', async () => {
    const cancel = vi.fn(() => new Promise<void>(() => undefined)); const releaseLock = vi.fn();
    const wire = { headers: new Headers(), body: { getReader: () => ({ read: async () => { throw new Error('PRIVATE_READ'); }, cancel, releaseLock }) } } as unknown as Response;
    await expect(readBoundedJson(wire, limits())).rejects.toThrow('INVALID_RESPONSE');
    expect(cancel).toHaveBeenCalledTimes(1); expect(releaseLock).toHaveBeenCalledTimes(1);
  });
  it('snapshots native limits without evaluating getters or coercion hooks', () => {
    let calls = 0;
    expect(() => responseLimits({ get maxResponseBytes() { calls++; return 7; }, maxJsonDepth: 2 })).toThrow();
    expect(calls).toBe(0);
    for (const value of [0, -1, NaN, Infinity, 1.5, true, '7']) {
      expect(() => responseLimits({ maxResponseBytes: value as number, maxJsonDepth: 2 })).toThrow();
    }
    const input = limits(7, 2); const saved = responseLimits(input); input.maxResponseBytes = 99;
    expect(saved).toEqual(limits(7, 2)); expect(Object.isFrozen(saved)).toBe(true);
  });
  it('never copies or retains empty chunks while preserving subsequent valid bytes', async () => {
    let emptyCopies = 0;
    class EmptyChunk extends Uint8Array {
      override slice(_start?: number, _end?: number): Uint8Array {
        emptyCopies += 1;
        throw new Error('EMPTY_CHUNK_COPIED');
      }
    }
    const chunks = [new EmptyChunk(0), new EmptyChunk(0), encode('{"x":'), new EmptyChunk(0), encode('1}'), new EmptyChunk(0)];
    await expect(readBoundedJson(response(chunks), limits(7))).resolves.toEqual({ x: 1 });
    expect(emptyCopies).toBe(0);
  });

});
