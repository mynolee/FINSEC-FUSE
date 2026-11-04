import { parseSimulationFixtureRegistry } from './simulationFixtures';
import { REASON_LABELS } from './format';
import { validReadEnvelope } from './responseContract';
import type {
  ApprovalPreview,
  DecisionResponse,
  Experiment,
  ExperimentCancelReceipt,
  Impact,
  Trace,
  Workflow,
  WorkflowList,
} from './types';

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public reasonCodes: string[] = [],
    public uncertain = false,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}
const ERROR_REASON_CODES = new Set([
  ...Object.keys(REASON_LABELS),
  'UNAUTHENTICATED', 'FORBIDDEN', 'NOT_FOUND', 'INVALID_REQUEST', 'INVALID_RESPONSE',
  'METHOD_NOT_ALLOWED', 'NOT_ACCEPTABLE', 'REQUEST_TOO_LARGE', 'UNSUPPORTED_MEDIA_TYPE',
  'LIVE_NOT_AVAILABLE', 'CAPTURE_ERROR', 'REVIEWER_REJECTED', 'COMMIT_OUTCOME_UNKNOWN',
]);
function safeErrorCodes(data: unknown, status: number): string[] {
  if (!record(data)) return [`HTTP_${status}`];
  const candidates = Array.isArray(data.reasonCodes)
    ? data.reasonCodes
    : [data.reasonCode ?? data.code];
  const codes = candidates.filter(
    (code): code is string => typeof code === 'string' && ERROR_REASON_CODES.has(code),
  );
  return codes.length ? [...new Set(codes)] : [`HTTP_${status}`];
}
function safeReceipt(data: DecisionResponse): DecisionResponse {
  const messages = {
    ALLOW: '서버가 요청을 처리했어요.',
    WAIT_APPROVAL: '직원 승인을 기다리고 있어요.',
    DENY: '요청이 거절됐어요. 처리 상태와 사유를 확인하세요.',
    ERROR: '요청을 완료하지 못했어요. 처리 상태와 사유를 확인하세요.',
  };
  return {
    ...data,
    message: messages[data.decision],
    reasonCodes: [...new Set(data.reasonCodes.filter(code => ERROR_REASON_CODES.has(code)))],
  };
}
const ACTION_FIELDS = [
  'requestId',
  'workflowId',
  'generation',
  'state',
  'decision',
  'reasonCodes',
  'message',
  'replayed',
];
const WORKFLOW_STATES = [
  'KYC_PENDING',
  'KYC_VALIDATED',
  'REVIEW_READY',
  'WAIT_APPROVAL',
  'APPROVED',
  'PAYMENT_RESERVED',
  'PAID',
  'REJECTED',
  'BLOCKED',
  'ON_HOLD',
];
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function closedFields(value: Record<string, unknown>, required: string[]) {
  return (
    required.every((key) => Object.hasOwn(value, key)) &&
    Object.keys(value).every((key) => required.includes(key))
  );
}
function uuid(value: unknown): value is string {
  return (
    typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)
  );
}
function integer(value: unknown, minimum = 0): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= 2147483647;
}
function readIdentifier(value: unknown): string {
  if (!uuid(value)) throw new ApiError('조회 대상은 유효한 UUID여야 해요.', 0, ['INVALID_REQUEST']);
  return encodeURIComponent(value);
}
function quarantineTarget(scope: unknown, target: unknown) {
  if (!record(target)) return false;
  switch (scope) {
    case 'RUN':
      return closedFields(target, ['runId']) && uuid(target.runId);
    case 'RESULT':
      return closedFields(target, ['resultId']) && uuid(target.resultId);
    case 'WORKFLOW':
      return closedFields(target, ['workflowId']) && uuid(target.workflowId);
    case 'SOURCE_VERSION':
      return (
        closedFields(target, ['documentId', 'documentVersion']) &&
        uuid(target.documentId) &&
        integer(target.documentVersion, 1)
      );
    case 'AGENT_VERSION':
      return (
        closedFields(target, ['agentId', 'agentVersion']) &&
        typeof target.agentId === 'string' &&
        target.agentId.length > 0 &&
        target.agentId.length <= 64 &&
        integer(target.agentVersion, 1)
      );
    default:
      return false;
  }
}
function experimentCancelReceipt(data: unknown, path: string, actionId: string): data is ExperimentCancelReceipt {
  const match = /^\/experiments\/([^/]+)\/cancel$/.exec(path);
  return !!match && record(data) &&
    closedFields(data, ['requestId', 'experimentId', 'status', 'completedPairs', 'replayed', 'resultsSource']) &&
    uuid(data.requestId) && data.requestId === actionId && uuid(data.experimentId) && data.experimentId === match[1] &&
    (data.status === 'CANCELLED' || data.status === 'COMPLETED') && integer(data.completedPairs) &&
    typeof data.replayed === 'boolean' && data.resultsSource === 'VIRTUAL_SIMULATION';
}

/** Validate the public producers' stored receipts, not a guess about current workflow state. */
function actionReceipt(data: unknown, path: string, actionId: string): data is DecisionResponse {
  if (
    !record(data) ||
    !uuid(data.requestId) ||
    data.requestId !== actionId ||
    !(data.workflowId === null || uuid(data.workflowId)) ||
    !(data.generation === null || integer(data.generation, 1)) ||
    typeof data.state !== 'string' ||
    typeof data.decision !== 'string' ||
    !['ALLOW', 'WAIT_APPROVAL', 'DENY', 'ERROR'].includes(data.decision) ||
    !Array.isArray(data.reasonCodes) ||
    !data.reasonCodes.every((code) => typeof code === 'string') ||
    typeof data.message !== 'string' ||
    typeof data.replayed !== 'boolean'
  )
    return false;

  if (path === '/workflows')
    return (
      closedFields(data, ACTION_FIELDS) &&
      uuid(data.workflowId) &&
      integer(data.generation, 1) &&
      WORKFLOW_STATES.includes(data.state)
    );

  const workflow = /^\/workflows\/([^/]+)\/(approvals|resume)$/.exec(path);
  if (workflow) {
    if (data.workflowId !== workflow[1] || !integer(data.generation, 1)) return false;
    if (workflow[2] === 'approvals')
      return (
        closedFields(data, [
          ...ACTION_FIELDS,
          'approvalId',
          'extraRiskLimit',
          'riskLimit',
          'expiresAt',
          'payJobId',
        ]) &&
        uuid(data.approvalId) &&
        integer(data.extraRiskLimit) &&
        integer(data.riskLimit) &&
        typeof data.expiresAt === 'string' &&
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(data.expiresAt) &&
        Number.isFinite(Date.parse(data.expiresAt)) &&
        new Date(data.expiresAt).toISOString().slice(0, 19) === data.expiresAt.slice(0, 19) &&
        data.decision === 'ALLOW' &&
        ((data.state === 'APPROVED' && uuid(data.payJobId)) ||
          (data.state === 'REJECTED' && data.payJobId === null))
      );
    // The saved run-limit denial has no new KYC job and retains its old generation.
    return data.decision === 'DENY'
      ? closedFields(data, ACTION_FIELDS) && data.state === 'ON_HOLD'
      : closedFields(data, [...ACTION_FIELDS, 'kycJobId']) &&
          data.decision === 'ALLOW' &&
          data.state === 'KYC_PENDING' &&
          uuid(data.kycJobId);
  }

  if (path === '/experiments')
    return (
      closedFields(data, [...ACTION_FIELDS, 'experimentId', 'status', 'totalRuns']) &&
      data.workflowId === null &&
      data.generation === null &&
      uuid(data.experimentId) &&
      data.state === 'PENDING' &&
      data.status === 'PENDING' &&
      data.decision === 'ALLOW' &&
      integer(data.totalRuns, 1)
    );

  const release = /^\/quarantines\/([^/]+)\/release$/.exec(path);
  if (path === '/quarantines' || release)
    return (
      closedFields(data, [...ACTION_FIELDS, 'quarantineId', 'scope', 'target']) &&
      uuid(data.quarantineId) &&
      (!release || data.quarantineId === release[1]) &&
      data.generation === null &&
      data.state === (release ? 'RELEASED' : 'ACTIVE') &&
      data.decision === 'ALLOW' &&
      quarantineTarget(data.scope, data.target) &&
      (data.scope === 'WORKFLOW'
        ? data.workflowId === (data.target as Record<string, unknown>).workflowId
        : data.workflowId === null)
    );
  return false;
}

interface PendingMutation {
  fingerprint: string;
  actionId: string;
  inFlight?: Promise<DecisionResponse>;
}

export class FuseApi {
  private readonly uncertainRequests = new Map<string, PendingMutation>();
  private readonly cancellationRequests = new Map<string, { actionId: string; inFlight?: Promise<ExperimentCancelReceipt> }>();
  unresolvedExperimentCancel(id: string) {
    return this.cancellationRequests.get(id)?.actionId;
  }
  unresolved(path: string) {
    const pending = this.uncertainRequests.get(path);
    return pending ? { path, body: JSON.parse(pending.fingerprint), actionId: pending.actionId } : undefined;
  }
  constructor(
    private readonly token: string,
    private readonly fetcher: typeof fetch = fetch,
  ) {}
  async request<T>(
    path: string,
    options: { signal?: AbortSignal; body?: unknown; actionId?: string } = {},
  ): Promise<T> {
    const mutation = options.body !== undefined;
    const actionId = mutation ? (options.actionId ?? crypto.randomUUID()) : undefined;
    const checkReadCancellation = () => {
      if (!mutation && options.signal?.aborted) throw new DOMException('요청이 취소됐어요.', 'AbortError');
    };
    checkReadCancellation();
    if (mutation && options.signal?.aborted) {
      // This branch runs before fetch: there is definitively no dispatch by this call.
      throw new ApiError('요청을 처리하지 못했어요.', 0, ['INVALID_REQUEST']);
    }
    let response: Response;
    try {
      // Native browser fetch requires its global receiver, not this FuseApi instance.
      // A local function call also preserves the ordinary function contract for injected fetchers.
      const fetcher = this.fetcher;
      response = await fetcher(`/api/v1${path}`, {
        method: mutation ? 'POST' : 'GET',
        headers: {
          Authorization: `Bearer ${this.token}`,
          Accept: 'application/json',
          ...(mutation
            ? {
                'Content-Type': 'application/json',
                'Idempotency-Key': actionId!,
              }
            : {}),
        },
        ...(mutation ? { body: JSON.stringify(options.body) } : {}),
        signal: options.signal
          ? AbortSignal.any([options.signal, AbortSignal.timeout(30000)])
          : AbortSignal.timeout(30000),
        credentials: 'omit',
        cache: 'no-store',
      });
    } catch {
      checkReadCancellation();
      // Aborting a sent mutation does not establish that the server rolled it back.
      throw new ApiError(
        mutation
          ? '응답을 받지 못했어요. 서버에서 접수했을 수 있으므로 같은 요청 번호로 다시 확인하세요.'
          : 'Spring 서버에 연결하지 못했어요. 서버와 네트워크 상태를 확인해 주세요.',
        0,
        ['DEPENDENCY_UNAVAILABLE'],
        mutation,
      );
    }
    checkReadCancellation();
    let data: unknown;
    try {
      data = await response.json();
    } catch {
      checkReadCancellation();
      throw new ApiError(
        '서버가 올바른 JSON 응답을 보내지 않았어요.',
        response.status,
        ['INVALID_RESPONSE'],
        mutation && (response.ok || response.status >= 500),
      );
    }
    checkReadCancellation();
    if (!response.ok) {
      const codes = safeErrorCodes(data, response.status);
      const fallback =
        response.status === 401
          ? '토큰을 확인하고 다시 연결해 주세요.'
          : response.status === 403
            ? '현재 인증 주체에게 이 작업의 권한이 없어요.'
            : response.status === 404
              ? '조회할 수 있는 대상을 찾지 못했어요.'
              : '요청을 처리하지 못했어요.';
      throw new ApiError(
        fallback,
        response.status,
        codes,
        mutation && response.status >= 500,
      );
    }
    if (mutation && (![200, 201, 202].includes(response.status) || !(experimentCancelReceipt(data, path, actionId!) || actionReceipt(data, path, actionId!)))) {
      throw new ApiError(
        '서버 응답에서 원래 요청의 처리 결과를 확인하지 못했어요. 같은 요청 번호로 다시 확인하세요.',
        response.status,
        ['INVALID_RESPONSE'],
        true,
      );
    }
    if (!mutation && !validReadEnvelope(path, data)) {
      throw new ApiError('서버가 올바른 JSON 응답을 보내지 않았어요.', response.status, ['INVALID_RESPONSE']);
    }
    if (mutation && experimentCancelReceipt(data, path, actionId!)) return { ...data } as T;
    return (mutation ? safeReceipt(data as DecisionResponse) : data) as T;
  }
  async workflows(state = '', page = 0, signal?: AbortSignal) {
    if (!integer(page) || typeof state !== 'string' || (state !== '' && !WORKFLOW_STATES.includes(state))) {
      throw new ApiError('조회 상태와 0 이상의 정수 페이지를 확인해 주세요.', 0, ['INVALID_REQUEST']);
    }
    return this.request<WorkflowList>(
      `/workflows?size=20&page=${page}${state ? `&state=${encodeURIComponent(state)}` : ''}`,
      { signal },
    );
  }
  async workflow(id: string, signal?: AbortSignal) {
    return this.request<Workflow>(`/workflows/${readIdentifier(id)}`, { signal });
  }
  async trace(id: string, signal?: AbortSignal) {
    return this.request<Trace>(`/workflows/${readIdentifier(id)}/trace`, { signal });
  }
  async preview(id: string, signal?: AbortSignal) {
    return this.request<ApprovalPreview>(`/workflows/${readIdentifier(id)}/approval-preview`, { signal });
  }
  async impact(id: string, signal?: AbortSignal) {
    return this.request<Impact>(`/incidents/${readIdentifier(id)}/impact`, { signal });
  }
  async simulationFixtures(signal?: AbortSignal) {
    let data: unknown;
    try {
      data = await this.request<unknown>('/simulation/fixtures', { signal });
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') throw error;
      if (signal?.aborted) throw new DOMException('합성 데이터 조회가 취소됐어요.', 'AbortError');
      const status = error instanceof ApiError ? error.status : 0;
      const codeByStatus: Record<number, string> = {
        200: 'INVALID_RESPONSE', 201: 'INVALID_RESPONSE', 202: 'INVALID_RESPONSE',
        400: 'INVALID_REQUEST', 401: 'UNAUTHENTICATED', 403: 'FORBIDDEN',
        405: 'METHOD_NOT_ALLOWED', 406: 'NOT_ACCEPTABLE', 413: 'REQUEST_TOO_LARGE',
        415: 'UNSUPPORTED_MEDIA_TYPE', 431: 'REQUEST_TOO_LARGE',
      };
      const message = status === 401
        ? '등록된 합성 데이터 조회 인증을 확인해 주세요.'
        : status === 403
          ? '등록된 합성 데이터를 조회할 권한이 없어요.'
          : '등록된 합성 데이터를 조회하지 못했어요. 다시 시도해 주세요.';
      // Preserve the HTTP status, but never echo dependency message/reasonCodes/cause.
      throw new ApiError(message, status, [codeByStatus[status] ?? 'DEPENDENCY_UNAVAILABLE']);
    }
    try {
      return parseSimulationFixtureRegistry(data);
    } catch {
      throw new ApiError('등록된 합성 데이터 응답을 확인하지 못했어요.', 200, ['INVALID_RESPONSE']);
    }
  }
  async experiment(id: string, signal?: AbortSignal) {
    return this.request<Experiment>(`/experiments/${readIdentifier(id)}`, { signal });
  }
  async cancelExperiment(id: string): Promise<ExperimentCancelReceipt> {
    const target = readIdentifier(id);
    const previous = this.cancellationRequests.get(id);
    if (previous?.inFlight) return previous.inFlight;
    const pending = previous ?? { actionId: crypto.randomUUID(), inFlight: undefined as Promise<ExperimentCancelReceipt> | undefined };
    this.cancellationRequests.set(id, pending);
    const attempt = this.request<ExperimentCancelReceipt>(`/experiments/${target}/cancel`, { body: {}, actionId: pending.actionId });
    pending.inFlight = attempt;
    try {
      const receipt = await attempt;
      if (this.cancellationRequests.get(id) === pending) this.cancellationRequests.delete(id);
      return receipt;
    } catch (error) {
      // Once uncertain, later denial cannot resolve whether the original cancellation committed.
      if (!previous && !(error instanceof ApiError && error.uncertain) && this.cancellationRequests.get(id) === pending)
        this.cancellationRequests.delete(id);
      throw error;
    } finally {
      if (pending.inFlight === attempt) pending.inFlight = undefined;
    }
  }
  async mutate(path: string, body: unknown, actionId: string) {
    if (/^\/experiments\/[^/]+\/cancel$/.test(path))
      throw new ApiError('요청을 처리하지 못했어요.', 0, ['INVALID_REQUEST']);
    // Preserve the original serialized body as well as its ID across modal/route changes.
    const fingerprint = JSON.stringify(body);
    const unresolved = this.uncertainRequests.get(path);
    if (unresolved && unresolved.fingerprint !== fingerprint) {
      throw new ApiError(
        '이 작업의 이전 처리 결과가 확인되지 않았어요. 먼저 원래 입력과 요청 번호로 재확인하세요.',
        0,
        ['COMMIT_OUTCOME_UNKNOWN'],
        true,
      );
    }
    // Remounted forms share an active send; no concurrent duplicate can clear a later action.
    if (unresolved?.inFlight) return unresolved.inFlight;
    const pending = unresolved ?? { fingerprint, actionId };
    this.uncertainRequests.set(path, pending);
    const attempt = this.request<DecisionResponse>(path, {
      body: JSON.parse(pending.fingerprint),
      actionId: pending.actionId,
    });
    pending.inFlight = attempt;
    try {
      const result = await attempt;
      if (this.uncertainRequests.get(path) === pending) this.uncertainRequests.delete(path);
      return result;
    } catch (error) {
      // A later authentication/admission failure cannot resolve an earlier unknown commit.
      if (
        !unresolved &&
        !(error instanceof ApiError && error.uncertain) &&
        this.uncertainRequests.get(path) === pending
      )
        this.uncertainRequests.delete(path);
      throw error;
    } finally {
      if (pending.inFlight === attempt) pending.inFlight = undefined;
    }
  }
}
