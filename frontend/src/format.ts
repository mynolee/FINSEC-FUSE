import type { Row } from './types';
import { DISPLAY_MAX_TEXT } from './displayProjection';
export const STATE_LABELS: Record<string, string> = {
  KYC_PENDING: '신원 확인 대기',
  KYC_VALIDATED: '증거 검증 완료',
  REVIEW_READY: '대출 추천 검토',
  WAIT_APPROVAL: '직원 승인 대기',
  APPROVED: '직원 승인 완료',
  PAYMENT_RESERVED: '지급 예약 중',
  PAID: 'Mock 지급 완료',
  REJECTED: '업무 부적격 · 거절',
  BLOCKED: '보안 정책 차단',
  ON_HOLD: '처리 보류',
};
export const REASON_LABELS: Record<string, string> = {
  EVIDENCE_MISSING: '고객 확인 자료가 없어 심사로 넘기지 않았어요.',
  EVIDENCE_INVALID: '확인 자료의 고객·상태·유효성을 검증하지 못했어요.',
  APPROVAL_REQUIRED: '정확한 지급 조건에 대한 직원 승인이 필요해요.',
  RISK_LIMIT_EXCEEDED: '자동 처리 위험 한도를 넘어 직원 승인을 기다려요.',
  QUARANTINED: '관계있는 실행이나 출처가 격리되어 있어요.',
  CONTEXT_MISMATCH: '업무 주인 또는 위임 대상이 일치하지 않아요.',
  SCOPE_EXCEEDED: '이 역할에 허용된 행동 범위를 벗어났어요.',
  SIGNATURE_INVALID: '전달 봉투의 무결성을 확인하지 못했어요.',
  STALE_GENERATION: '복구 이전 회차의 결과는 사용할 수 없어요.',
  GRANT_EXPIRED: '행동 허가가 만료되어 다시 확인해야 해요.',
  APPROVAL_INVALID: '현재 지급 조건에 사용할 수 있는 승인이 없어요.',
  REVIEW_CHANGED: '승인 화면을 연 뒤 내용이 바뀌었어요. 새 미리보기를 확인하세요.',
  WORKFLOW_CHANGED: '업무 회차가 바뀌었어요. 현재 상태를 다시 조회하세요.',
  DEPENDENCY_UNAVAILABLE: '외부 서비스 또는 저장소 장애로 보류했어요. 공격 차단으로 집계하지 않아요.',
  REQUEST_BODY_TIMEOUT: '요청 본문을 받는 시간이 초과됐어요. 요청 접수 상태를 확인하세요.',
  MODEL_OUTPUT_INVALID: 'AI 응답 형식이 맞지 않아 보류했어요.',
  MANUAL_REVIEW_REQUIRED: '자동 재평가 횟수를 소진했어요. 수동 조사가 필요해요.',
  RECOVERY_CHECK_FAILED: '안전한 출처와 확인 자료를 다시 검증해야 해요.',
};
export function formatValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return '미제공';
  if (typeof value === 'boolean') return value ? '예' : '아니요';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}
export function value(row: Row, ...keys: string[]): unknown {
  for (const key of keys) if (row[key] !== undefined && row[key] !== null) return row[key];
  return undefined;
}
export function text(row: Row, ...keys: string[]): string {
  return formatValue(value(row, ...keys));
}
export function currency(amount: unknown): string {
  if (typeof amount !== 'number' || !Number.isFinite(amount) ||
    (Number.isInteger(amount) && !Number.isSafeInteger(amount))) return '미제공';
  try {
    return `${new Intl.NumberFormat('ko-KR').format(amount)}원`;
  } catch {
    return '미제공';
  }
}
/** Detail API money is an exact integer string; never coerce it through Number. */
export function integerKrw(amount: unknown, currencyCode: unknown): string {
  if (currencyCode !== 'KRW' || typeof amount !== 'string' || amount.length > DISPLAY_MAX_TEXT || !/^(0|[1-9]\d*)$/.test(amount)) return '미제공';
  try {
    return `${new Intl.NumberFormat('ko-KR').format(BigInt(amount))}원`;
  } catch {
    return '미제공';
  }
}
export function applicationCount(count: unknown): string {
  if (typeof count !== 'number' || !Number.isSafeInteger(count) || count < 0) return '미제공';
  try {
    return `${new Intl.NumberFormat('ko-KR').format(count)}건`;
  } catch {
    return '미제공';
  }
}
export function time(iso: unknown): string {
  if (typeof iso !== 'string' || !Number.isFinite(Date.parse(iso))) return formatValue(iso);
  try {
    return new Intl.DateTimeFormat('ko-KR', { dateStyle: 'short', timeStyle: 'medium', timeZone: 'UTC' })
      .format(new Date(iso)) + ' UTC';
  } catch {
    return '미제공';
  }
}
export function shortId(id: unknown): string {
  return typeof id === 'string' && id.length > 16 ? `${id.slice(0, 8)}…${id.slice(-4)}` : formatValue(id);
}
export function isUuid(id: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id);
}
const GENERIC_ERROR_MESSAGE = '요청을 처리하지 못했어요.';
// Existing public API and local form-validation copy only. Unknown exception
// messages are never diagnostics suitable for the operator screen.
const PUBLIC_ERROR_MESSAGES = new Set([
  GENERIC_ERROR_MESSAGE,
  ...Object.values(REASON_LABELS),
  '조회 대상은 유효한 UUID여야 해요.',
  '조회 상태와 0 이상의 정수 페이지를 확인해 주세요.',
  '응답을 받지 못했어요. 서버에서 접수했을 수 있으므로 같은 요청 번호로 다시 확인하세요.',
  'Spring 서버에 연결하지 못했어요. 서버와 네트워크 상태를 확인해 주세요.',
  '서버가 올바른 JSON 응답을 보내지 않았어요.',
  '토큰을 확인하고 다시 연결해 주세요.',
  '현재 인증 주체에게 이 작업의 권한이 없어요.',
  '조회할 수 있는 대상을 찾지 못했어요.',
  '서버 응답에서 원래 요청의 처리 결과를 확인하지 못했어요. 같은 요청 번호로 다시 확인하세요.',
  '등록된 합성 데이터 조회 인증을 확인해 주세요.',
  '등록된 합성 데이터를 조회할 권한이 없어요.',
  '등록된 합성 데이터를 조회하지 못했어요. 다시 시도해 주세요.',
  '등록된 합성 데이터 응답을 확인하지 못했어요.',
  '이 작업의 이전 처리 결과가 확인되지 않았어요. 먼저 원래 입력과 요청 번호로 재확인하세요.',
  '업무 ID는 유효한 UUID여야 해요.',
  '격리 사건 ID는 유효한 UUID여야 해요.',
  '실험 ID는 유효한 UUID여야 해요.',
  '실험 응답의 대상이 일치하지 않아요.',
  '고객·등록 신청·계좌와 1~50,000,000원의 정수 금액을 확인하세요.',
  '격리 대상·양의 정수 버전·조사 내용을 확인하세요.',
  '안전 출처·양의 정수 버전·조치 사유를 확인하세요.',
  '확인 자료는 유효한 UUID를 한 개 이상 입력하세요.',
]);
const PUBLIC_ERROR_CODES: Record<string, string> = {
  ...REASON_LABELS,
  UNAUTHENTICATED: '토큰을 확인하고 다시 연결해 주세요.',
  FORBIDDEN: '현재 인증 주체에게 이 작업의 권한이 없어요.',
  NOT_FOUND: '조회할 수 있는 대상을 찾지 못했어요.',
};
function errorData(error: object, key: string): unknown {
  const field = Object.getOwnPropertyDescriptor(error, key);
  return field && Object.hasOwn(field, 'value') ? field.value : undefined;
}
const PUBLIC_ERROR_REASON_CODES = new Set([
  ...Object.keys(REASON_LABELS),
  'UNAUTHENTICATED', 'FORBIDDEN', 'NOT_FOUND', 'INVALID_REQUEST', 'INVALID_RESPONSE',
  'METHOD_NOT_ALLOWED', 'NOT_ACCEPTABLE', 'REQUEST_TOO_LARGE', 'UNSUPPORTED_MEDIA_TYPE',
  'LIVE_NOT_AVAILABLE', 'CAPTURE_ERROR', 'REVIEWER_REJECTED', 'COMMIT_OUTCOME_UNKNOWN',
]);
/** Display-only public metadata; this projection does not establish authentication. */
export function publicErrorDetails(error: unknown): { status: number | null; reasonCodes: readonly string[] } {
  try {
    if (!error || typeof error !== 'object') return { status: null, reasonCodes: [] };
    const rawStatus = errorData(error, 'status');
    const status = typeof rawStatus === 'number' && Number.isInteger(rawStatus) && rawStatus >= 100 && rawStatus <= 599
      ? rawStatus : null;
    const rawCodes = errorData(error, 'reasonCodes');
    const codes = new Set<string>();
    if (Array.isArray(rawCodes)) {
      const length = errorData(rawCodes, 'length');
      const count = typeof length === 'number' ? Math.min(length, 100) : 0;
      for (let index = 0; index < count; index += 1) {
        const code = errorData(rawCodes, String(index));
        if (typeof code === 'string' && (PUBLIC_ERROR_REASON_CODES.has(code) || /^HTTP_[1-5]\d{2}$/.test(code))) codes.add(code);
      }
    }
    return { status, reasonCodes: Object.freeze([...codes]) };
  } catch {
    return { status: null, reasonCodes: [] };
  }
}
export function errorMessage(error: unknown): string {
  try {
    if (!(error instanceof Error)) return GENERIC_ERROR_MESSAGE;
    const message = errorData(error, 'message');
    if (typeof message === 'string' && PUBLIC_ERROR_MESSAGES.has(message)) return message;
    for (const code of publicErrorDetails(error).reasonCodes) {
      if (Object.hasOwn(PUBLIC_ERROR_CODES, code)) return PUBLIC_ERROR_CODES[code];
    }
  } catch {
    // Malformed objects/proxies must not turn UI error rendering into another failure.
  }
  return GENERIC_ERROR_MESSAGE;
}
