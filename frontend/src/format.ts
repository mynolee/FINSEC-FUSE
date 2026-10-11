import type { Row } from './types';
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
  return typeof amount === 'number' && Number.isFinite(amount)
    ? `${new Intl.NumberFormat('ko-KR').format(amount)}원`
    : '미제공';
}
/** Detail API money is an exact integer string; never coerce it through Number. */
export function integerKrw(amount: unknown, currencyCode: unknown): string {
  if (currencyCode !== 'KRW' || typeof amount !== 'string' || !/^(0|[1-9]\d*)$/.test(amount)) return '미제공';
  return `${new Intl.NumberFormat('ko-KR').format(BigInt(amount))}원`;
}
export function applicationCount(count: unknown): string {
  return typeof count === 'number' && Number.isSafeInteger(count) && count >= 0
    ? `${new Intl.NumberFormat('ko-KR').format(count)}건`
    : '미제공';
}
export function time(iso: unknown): string {
  if (typeof iso !== 'string' || !Number.isFinite(Date.parse(iso))) return formatValue(iso);
  return (
    new Intl.DateTimeFormat('ko-KR', { dateStyle: 'short', timeStyle: 'medium', timeZone: 'UTC' }).format(
      new Date(iso),
    ) + ' UTC'
  );
}
export function shortId(id: unknown): string {
  return typeof id === 'string' && id.length > 16 ? `${id.slice(0, 8)}…${id.slice(-4)}` : formatValue(id);
}
export function isUuid(id: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id);
}
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : '요청을 처리하지 못했어요.';
}
