import { describe, expect, it } from 'vitest';
import { currency, formatValue, isUuid, time } from './format';
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
