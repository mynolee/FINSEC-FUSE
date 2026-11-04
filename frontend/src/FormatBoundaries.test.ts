import { describe, expect, it, vi } from 'vitest';
import { DISPLAY_MAX_TEXT } from './displayProjection';
import { applicationCount, currency, integerKrw, time } from './format';

describe('display formatter boundaries', () => {
  it('does not claim an unsafe numeric integer amount is exact', () => {
    expect(currency(Number.MAX_SAFE_INTEGER + 1)).toBe('미제공');
    expect(currency(Number.MAX_SAFE_INTEGER)).not.toBe('미제공');
    expect(currency(0)).toBe('0원');
    expect(currency(1.5)).toBe('1.5원');
    expect(integerKrw('9007199254740993', 'KRW')).toBe('9,007,199,254,740,993원');
  });

  it('bounds exact integer conversion without truncating a money value', () => {
    const boundary = '9'.repeat(DISPLAY_MAX_TEXT);
    expect(integerKrw(boundary, 'KRW').replaceAll(',', '')).toBe(boundary + '원');
    expect(integerKrw(boundary + '9', 'KRW')).toBe('미제공');
  });

  it('does not invoke Intl for overlong exact amounts or invalid numeric values', () => {
    const formatter = vi.spyOn(Intl, 'NumberFormat').mockImplementation(() => {
      throw new RangeError('synthetic formatter unavailable');
    });
    try {
      expect(integerKrw('1'.repeat(DISPLAY_MAX_TEXT + 1), 'KRW')).toBe('미제공');
      expect(currency(Infinity)).toBe('미제공');
      expect(currency(Number.MAX_SAFE_INTEGER + 1)).toBe('미제공');
      expect(applicationCount(0.5)).toBe('미제공');
      expect(formatter).not.toHaveBeenCalled();
    } finally {
      formatter.mockRestore();
    }
  });

  it('keeps an Intl failure local to the unavailable display value', () => {
    const formatter = vi.spyOn(Intl, 'NumberFormat').mockImplementation(() => {
      throw new RangeError('synthetic formatter unavailable');
    });
    try {
      expect(currency(1)).toBe('미제공');
      expect(integerKrw('1', 'KRW')).toBe('미제공');
      expect(applicationCount(1)).toBe('미제공');
    } finally {
      formatter.mockRestore();
    }
    const dateFormatter = vi.spyOn(Intl, 'DateTimeFormat').mockImplementation(() => {
      throw new RangeError('synthetic date formatter unavailable');
    });
    try {
      expect(time('2026-10-09T04:00:00Z')).toBe('미제공');
      expect(dateFormatter).toHaveBeenCalledTimes(1);
    } finally {
      dateFormatter.mockRestore();
    }
  });
});
