import { describe, expect, it } from 'vitest';
import { applicationCount, integerKrw, currency, errorMessage, formatValue, isUuid, publicErrorDetails, REASON_LABELS, time } from './format';
import { ApiError } from './api';
import { csvCell } from './components/Experiments';

describe('faithful operator formatting', () => {
  it('projects only finite public error metadata without altering its source', () => {
    const source = { status: 503, reasonCodes: ['DEPENDENCY_UNAVAILABLE', 'HTTP_503', 'SYNTHETIC_PRIVATE_ERROR_VALUE', 'HTTP_600', 'HTTP_099', 'FORBIDDEN', 'FORBIDDEN'] };
    expect(publicErrorDetails(source)).toEqual({ status: 503, reasonCodes: ['DEPENDENCY_UNAVAILABLE', 'HTTP_503', 'FORBIDDEN'] });
    expect(source.reasonCodes).toContain('SYNTHETIC_PRIVATE_ERROR_VALUE');
  });
  it.each([0, 99, 600, -1, NaN, Infinity, 401.5, '401', null, undefined])('rejects non-HTTP error status metadata: %s', status => {
    expect(publicErrorDetails({ status, reasonCodes: ['HTTP_401'] })).toEqual({ status: null, reasonCodes: ['HTTP_401'] });
  });
  it.each([100, 200, 401, 599])('preserves valid integer HTTP status %s', status => {
    expect(publicErrorDetails({ status })).toEqual({ status, reasonCodes: [] });
  });
  it('does not invoke metadata getters or inherited fields', () => {
    let calls = 0;
    const source = Object.create({ status: 401, reasonCodes: ['UNAUTHENTICATED'] });
    Object.defineProperty(source, 'status', { get() { calls += 1; throw new Error('SYNTHETIC_PRIVATE_ERROR_VALUE'); } });
    Object.defineProperty(source, 'reasonCodes', { get() { calls += 1; return ['FORBIDDEN']; } });
    expect(publicErrorDetails(source)).toEqual({ status: null, reasonCodes: [] });
    expect(publicErrorDetails(Object.create({ status: 403, reasonCodes: ['FORBIDDEN'] }))).toEqual({ status: null, reasonCodes: [] });
    expect(calls).toBe(0);
  });
  it('bounds metadata scans and skips array accessor entries', () => {
    let calls = 0;
    const codes = Array(101).fill('SYNTHETIC_PRIVATE_ERROR_VALUE');
    Object.defineProperty(codes, '0', { get() { calls += 1; throw new Error('SYNTHETIC_PRIVATE_ERROR_VALUE'); } });
    codes[100] = 'FORBIDDEN';
    expect(publicErrorDetails({ status: 400, reasonCodes: codes })).toEqual({ status: 400, reasonCodes: [] });
    expect(calls).toBe(0);
  });
  it.each([
    new Error('SYNTHETIC_PRIVATE_ERROR_VALUE'),
    new TypeError('https://synthetic.invalid/?token=SYNTHETIC_PRIVATE_ERROR_VALUE'),
    new ApiError('SYNTHETIC_PRIVATE_ERROR_VALUE', 400, ['SYNTHETIC_PRIVATE_ERROR_VALUE']),
    'SYNTHETIC_PRIVATE_ERROR_VALUE',
    { message: 'SYNTHETIC_PRIVATE_ERROR_VALUE' },
    undefined,
    null,
  ])('never echoes unknown error content', error => {
    expect(errorMessage(error)).toBe('요청을 처리하지 못했어요.');
  });
  it('maps a known public API reason code without returning its raw exception message', () => {
    expect(errorMessage(new ApiError('SYNTHETIC_PRIVATE_ERROR_VALUE', 503, ['DEPENDENCY_UNAVAILABLE'])))
      .toBe(REASON_LABELS.DEPENDENCY_UNAVAILABLE);
    expect(errorMessage(new ApiError('SYNTHETIC_PRIVATE_ERROR_VALUE', 401, ['UNAUTHENTICATED'])))
      .toBe('토큰을 확인하고 다시 연결해 주세요.');
  });
  it.each([
    '서버 응답에서 원래 요청의 처리 결과를 확인하지 못했어요. 같은 요청 번호로 다시 확인하세요.',
    '고객·등록 신청·계좌와 1~50,000,000원의 정수 금액을 확인하세요.',
    '안전 출처·양의 정수 버전·조치 사유를 확인하세요.',
    '확인 자료는 유효한 UUID를 한 개 이상 입력하세요.',
  ])('preserves existing fixed public guidance: %s', message => {
    expect(errorMessage(new Error(message))).toBe(message);
  });
  it('never invokes error-message or reason-code getters', () => {
    let calls = 0;
    const error = new Error();
    Object.defineProperty(error, 'message', { get() { calls += 1; throw new Error('SYNTHETIC_PRIVATE_ERROR_VALUE'); } });
    Object.defineProperty(error, 'reasonCodes', { get() { calls += 1; return ['DEPENDENCY_UNAVAILABLE']; } });
    expect(errorMessage(error)).toBe('요청을 처리하지 못했어요.');
    expect(calls).toBe(0);
  });
  it('ignores accessor and inherited reason-code entries', () => {
    let calls = 0;
    const codes: string[] = [];
    Object.defineProperty(codes, '0', { get() { calls += 1; throw new Error('SYNTHETIC_PRIVATE_ERROR_VALUE'); } });
    const error = new Error('SYNTHETIC_PRIVATE_ERROR_VALUE');
    Object.defineProperty(error, 'reasonCodes', { value: codes });
    expect(errorMessage(error)).toBe('요청을 처리하지 못했어요.');
    expect(calls).toBe(0);
    const inherited = Object.create(Object.assign(new Error('SYNTHETIC_PRIVATE_ERROR_VALUE'), {
      reasonCodes: ['DEPENDENCY_UNAVAILABLE'],
    }));
    expect(errorMessage(inherited)).toBe('요청을 처리하지 못했어요.');
  });
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
