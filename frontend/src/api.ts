import type {
  ApprovalPreview,
  DecisionResponse,
  Experiment,
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
    } catch (error) {
      if (options.signal?.aborted) throw error;
      throw new ApiError(
        mutation
          ? '응답을 받지 못했어요. 서버에서 접수했을 수 있으므로 같은 요청 번호로 다시 확인하세요.'
          : 'Spring 서버에 연결하지 못했어요. 서버와 네트워크 상태를 확인해 주세요.',
        0,
        ['DEPENDENCY_UNAVAILABLE'],
        mutation,
      );
    }
    let data: unknown;
    try {
      data = await response.json();
    } catch {
      throw new ApiError(
        '서버가 올바른 JSON 응답을 보내지 않았어요.',
        response.status,
        ['INVALID_RESPONSE'],
        mutation && (response.ok || response.status >= 500),
      );
    }
    if (!response.ok) {
      const record = data && typeof data === 'object' ? (data as Record<string, unknown>) : {};
      const codes = Array.isArray(record.reasonCodes)
        ? record.reasonCodes.map(String)
        : [String(record.reasonCode ?? record.code ?? `HTTP_${response.status}`)];
      const fallback =
        response.status === 401
          ? '토큰을 확인하고 다시 연결해 주세요.'
          : response.status === 403
            ? '현재 인증 주체에게 이 작업의 권한이 없어요.'
            : response.status === 404
              ? '조회할 수 있는 대상을 찾지 못했어요.'
              : '요청을 처리하지 못했어요.';
      throw new ApiError(
        typeof record.message === 'string' ? record.message : fallback,
        response.status,
        codes,
        mutation && response.status >= 500,
      );
    }
    if (mutation && (![200, 201, 202].includes(response.status) || !actionReceipt(data, path, actionId!))) {
      throw new ApiError(
        '서버 응답에서 원래 요청의 처리 결과를 확인하지 못했어요. 같은 요청 번호로 다시 확인하세요.',
        response.status,
        ['INVALID_RESPONSE'],
        true,
      );
    }
    return data as T;
  }
  workflows(state = '', page = 0, signal?: AbortSignal) {
    return this.request<WorkflowList>(
      `/workflows?size=20&page=${page}${state ? `&state=${encodeURIComponent(state)}` : ''}`,
      { signal },
    );
  }
  workflow(id: string, signal?: AbortSignal) {
    return this.request<Workflow>(`/workflows/${encodeURIComponent(id)}`, { signal });
  }
  trace(id: string, signal?: AbortSignal) {
    return this.request<Trace>(`/workflows/${encodeURIComponent(id)}/trace`, { signal });
  }
  preview(id: string, signal?: AbortSignal) {
    return this.request<ApprovalPreview>(`/workflows/${encodeURIComponent(id)}/approval-preview`, { signal });
  }
  impact(id: string, signal?: AbortSignal) {
    return this.request<Impact>(`/incidents/${encodeURIComponent(id)}/impact`, { signal });
  }
  experiment(id: string, signal?: AbortSignal) {
    return this.request<Experiment>(`/experiments/${encodeURIComponent(id)}`, { signal });
  }
  async mutate(path: string, body: unknown, actionId: string) {
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
