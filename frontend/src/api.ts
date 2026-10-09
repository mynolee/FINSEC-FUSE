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
export class FuseApi {
  private readonly uncertainRequests = new Map<
    string,
    { body: unknown; fingerprint: string; actionId: string }
  >();
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
                'Idempotency-Key': options.actionId ?? crypto.randomUUID(),
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
    const stableId = unresolved?.actionId ?? actionId;
    const snapshot = JSON.parse(fingerprint);
    this.uncertainRequests.set(path, { body: snapshot, fingerprint, actionId: stableId });
    try {
      const result = await this.request<DecisionResponse>(path, { body: snapshot, actionId: stableId });
      this.uncertainRequests.delete(path);
      return result;
    } catch (error) {
      // A later authentication/admission failure cannot resolve an earlier unknown commit.
      if (!unresolved && !(error instanceof ApiError && error.uncertain)) this.uncertainRequests.delete(path);
      throw error;
    }
  }
}
