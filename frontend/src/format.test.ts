import { describe, expect, it } from 'vitest';
import { applicationCount, integerKrw, currency, formatValue, isUuid, time } from './format';
import { csvCell } from './components/Experiments';

describe('faithful operator formatting', () => {
  it('shows unknown amounts as missing, never zero', () => {
    expect(currency(null)).toBe('미제공');
    expect(currency(undefined)).toBe('미제공');
    expect(currency(0)).toBe('0원');
  });
  it('formats integer KRW without floating-point conversion', () => {
    expect(currency(1000000)).toBe('1,000,000원');
  });
  it('preserves exact integer KRW detail amounts beyond JavaScript number precision', () => {
    expect(integerKrw('9007199254740993', 'KRW')).toBe('9,007,199,254,740,993원');
    expect(integerKrw('0', 'KRW')).toBe('0원');
    expect(integerKrw('1234567', 'KRW')).toBe('1,234,567원');
  });
  it.each([undefined, null, '', '01', '-1', '1.5', '1e3', ' 1 ', 'NaN', 0, 1, {}, []])(
    'rejects missing or invalid exact amounts: %s',
    (amount) => expect(integerKrw(amount, 'KRW')).toBe('미제공'),
  );
  it.each([undefined, null, '', 'USD', 'krw', {}, 123])('requires the API KRW currency: %s', (code) => {
    expect(integerKrw('1200', code)).toBe('미제공');
  });
  it('shows valid server application counts, including zero', () => {
    expect(applicationCount(0)).toBe('0건');
    expect(applicationCount(1234)).toBe('1,234건');
  });
  it.each([undefined, null, '', '2', -1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, {}, []])(
    'rejects missing or invalid counts: %s',
    (count) => expect(applicationCount(count)).toBe('미제공'),
  );
  it('labels server times as UTC', () => {
    expect(time('2026-10-09T04:00:00Z')).toContain('UTC');
  });
  it('preserves missing, false, and zero as distinct facts', () => {
    expect(formatValue(null)).toBe('미제공');
    expect(formatValue(false)).toBe('아니요');
    expect(formatValue(0)).toBe('0');
  });
  it('checks UUIDs before opening arbitrary routes', () => {
    expect(isUuid('00000000-0000-4000-8000-000000000102')).toBe(true);
    expect(isUuid('../payment')).toBe(false);
  });
  it('neutralizes spreadsheet formulas in exported CSV', () => {
    expect(csvCell('=HYPERLINK("https://example.com")')).toBe('"\'=HYPERLINK(""https://example.com"")"');
    expect(csvCell('@SUM(A1)')).toBe('"\'@SUM(A1)"');
  });
});
