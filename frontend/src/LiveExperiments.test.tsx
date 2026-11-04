import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { describeExperimentIssue, ExperimentsPage, MVP_CASES } from './components/Experiments';
import { FuseApi } from './api';

const ID = '00000000-0000-4000-8000-000000000301';
const response = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const receipt = (options: RequestInit) => ({
  requestId: new Headers(options.headers).get('Idempotency-Key'),
  workflowId: null,
  generation: null,
  decision: 'ALLOW',
  state: 'PENDING',
  reasonCodes: [],
  message: 'Experiment queued',
  replayed: false,
  experimentId: ID,
  status: 'PENDING',
  totalRuns:
    JSON.parse(options.body as string).caseIds.length * 2 * JSON.parse(options.body as string).repeatCount,
});
async function login() {
  await userEvent.type(screen.getByLabelText('개발용 인증 토큰'), 'live-ui-test-token');
  await userEvent.click(screen.getByRole('button', { name: /연결하고 업무 조회/ }));
}
async function openForm() {
  render(<App />);
  await login();
  await userEvent.click(screen.getByRole('button', { name: '새 실험' }));
  return screen.getByRole('dialog');
}
const costCheckbox = (dialog: HTMLElement) =>
  within(dialog).getByRole('checkbox', { name: /외부 모델 전송과 발생 가능한 비용/ });
const mockCheckbox = (dialog: HTMLElement) =>
  within(dialog).getByRole('checkbox', { name: '실험 전용 Mock 업무 실행을 요청합니다.' });
beforeEach(() => {
  vi.restoreAllMocks();
  window.location.hash = '/experiments';
});

describe('optional LIVE experiment UI, mocked requests only', () => {
  it('keeps a newly selected experiment when an earlier create completes in the same API session', async () => {
    const nextId = '00000000-0000-4000-8000-000000000302';
    let finishCreate!: (response: Response) => void;
    let createOptions!: RequestInit;
    const pendingCreate = new Promise<Response>(resolve => { finishCreate = resolve; });
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (_url, options) => {
      if (options?.method === 'POST') {
        createOptions = options;
        return pendingCreate;
      }
      return response({ experimentId: nextId, status: 'COMPLETED', caseOutputs: [] });
    });
    const api = new FuseApi('synthetic-same-session', fetcher);
    const view = render(<ExperimentsPage api={api} />);
    await userEvent.click(screen.getByRole('button', { name: '새 실험' }));
    const dialog = screen.getByRole('dialog');
    await userEvent.click(mockCheckbox(dialog));
    await userEvent.click(within(dialog).getByRole('button', { name: '비교 실험 접수' }));
    window.location.hash = `/experiments/${nextId}`;
    view.rerender(<ExperimentsPage api={api} id={nextId} />);
    expect(screen.getByRole('dialog')).toBe(dialog);
    await waitFor(() => expect(screen.getByLabelText('실험 UUID')).toHaveValue(nextId));
    await act(async () => { finishCreate(response(receipt(createOptions), 202)); });
    expect(window.location.hash).toBe(`#/experiments/${nextId}`);
    expect(screen.getByLabelText('실험 UUID')).toHaveValue(nextId);
    expect(screen.getByRole('dialog')).toBe(dialog);
    expect(within(dialog).getByRole('status')).toHaveTextContent('서버가 요청을 처리했어요.');
    expect(api.unresolved('/experiments')).toBeUndefined();
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
    view.unmount();
  });

  it('releases a download URL when anchor setup fails after URL allocation', async () => {
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async () => response({
      experimentId: ID, status: 'COMPLETED', caseOutputs: [],
    }));
    const create = vi.fn(() => 'blob:synthetic-download');
    const revoke = vi.fn();
    const NativeURL = URL;
    vi.stubGlobal('URL', class extends NativeURL {
      static createObjectURL = create;
      static revokeObjectURL = revoke;
    });
    const view = render(<ExperimentsPage api={new FuseApi('synthetic-session', fetcher)} id={ID} />);
    try {
      const button = await screen.findByRole('button', { name: '정제 JSON 내보내기' });
      const originalCreate = document.createElement.bind(document);
      const anchorSetup = vi.spyOn(document, 'createElement').mockImplementation((name, options) => {
        if (name === 'a') throw new Error('synthetic anchor setup failure');
        return originalCreate(name, options);
      });
      const timers = vi.spyOn(globalThis, 'setTimeout');
      await userEvent.click(button);
      expect(create).toHaveBeenCalledTimes(1);
      const cleanupIndex = timers.mock.calls.findIndex(([, delay]) => delay === 1000);
      expect(cleanupIndex).toBeGreaterThanOrEqual(0);
      const cleanup = timers.mock.calls[cleanupIndex][0];
      clearTimeout(timers.mock.results[cleanupIndex].value);
      if (typeof cleanup === 'function') act(() => cleanup());
      expect(revoke).toHaveBeenCalledWith('blob:synthetic-download');
      expect(screen.getByRole('alert')).toHaveTextContent('요청을 처리하지 못했어요.');
      expect(button).toBeEnabled();
      anchorSetup.mockRestore();
      timers.mockRestore();
    } finally {
      view.unmount();
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });

  it.each(['target', 'session'] as const)('retires a pending export when the %s changes without blocking the new export', async change => {
    const nextId = change === 'target' ? '00000000-0000-4000-8000-000000000302' : ID;
    let finishOld!: (response: Response) => void;
    const oldExport = new Promise<Response>(resolve => { finishOld = resolve; });
    const newExport = new Promise<Response>(() => {});
    const record = (experimentId: string) => ({ experimentId, status: 'COMPLETED', caseOutputs: [] });
    const first = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(record(ID)))
      .mockReturnValueOnce(oldExport);
    const second = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response(record(nextId)))
      .mockReturnValueOnce(newExport);
    const firstApi = new FuseApi('synthetic-first-session', first);
    const nextApi = change === 'session' ? new FuseApi('synthetic-next-session', second) : firstApi;
    if (change === 'target') first.mockImplementation((url, options) => second(url, options));
    const create = vi.fn();
    const NativeURL = URL;
    vi.stubGlobal('URL', class extends NativeURL { static createObjectURL = create; });
    const view = render(<ExperimentsPage api={firstApi} id={ID} />);
    try {
      const button = await screen.findByRole('button', { name: '정제 JSON 내보내기' });
      await userEvent.click(button);
      expect(button).toBeDisabled();
      view.rerender(<ExperimentsPage api={nextApi} id={nextId} />);
      expect(screen.getByLabelText('실험 UUID')).toHaveValue(nextId);
      const nextButton = await screen.findByRole('button', { name: '정제 JSON 내보내기' });
      await waitFor(() => expect(nextButton).toBeEnabled());
      await userEvent.click(nextButton);
      expect(nextButton).toBeDisabled();
      await act(async () => { finishOld(response(record(ID))); });
      expect(create).not.toHaveBeenCalled();
      expect(nextButton).toBeDisabled();
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
      await userEvent.click(nextButton);
      expect(second).toHaveBeenCalledTimes(2);
      expect(second.mock.calls.every(([url]) => String(url).endsWith(`/experiments/${nextId}`))).toBe(true);
    } finally {
      view.unmount();
      vi.unstubAllGlobals();
    }
  });

  it('requires new Mock and LIVE cost consent after the API session changes', async () => {
    const first = vi.fn<typeof fetch>();
    const second = vi.fn<typeof fetch>();
    const view = render(<ExperimentsPage api={new FuseApi('synthetic-first-session', first)} />);
    await userEvent.click(screen.getByRole('button', { name: '새 실험' }));
    let dialog = screen.getByRole('dialog');
    await userEvent.selectOptions(within(dialog).getByLabelText('모델 모드'), 'LIVE');
    await userEvent.click(costCheckbox(dialog));
    await userEvent.click(mockCheckbox(dialog));
    expect(within(dialog).getByRole('button', { name: '비용 확인 후 LIVE 실험 접수' })).toBeEnabled();
    view.rerender(<ExperimentsPage api={new FuseApi('synthetic-second-session', second)} />);
    dialog = screen.getByRole('dialog');
    expect(costCheckbox(dialog)).not.toBeChecked();
    expect(mockCheckbox(dialog)).not.toBeChecked();
    fireEvent.submit(dialog.querySelector('form')!);
    expect(first).not.toHaveBeenCalled();
    expect(second).not.toHaveBeenCalled();
  });

  it('defaults to REPLAY once and does not ask to approve external model costs', async () => {
    const fetcher = vi.fn().mockImplementation((_url, options) =>
      Promise.resolve(
        options.method === 'POST'
          ? response(receipt(options), 202)
          : response({
              experimentId: ID,
              status: 'PENDING',
              modelMode: 'REPLAY',
              progress: { completed: 0, total: 12 },
              caseOutputs: [],
            }),
      ),
    );
    vi.stubGlobal('fetch', fetcher);
    const dialog = await openForm();
    expect(within(dialog).getByLabelText('모델 모드')).toHaveValue('REPLAY');
    expect(within(dialog).getByText('1회 (고정)')).toBeInTheDocument();
    expect(
      within(dialog).queryByRole('checkbox', { name: /외부 모델 전송과 발생 가능한 비용/ }),
    ).not.toBeInTheDocument();
    await userEvent.click(mockCheckbox(dialog));
    await userEvent.click(within(dialog).getByRole('button', { name: '비교 실험 접수' }));
    await waitFor(() => expect(window.location.hash).toBe(`#/experiments/${ID}`));
    expect(JSON.parse(fetcher.mock.calls[0][1].body)).toEqual({
      fixtureSetId: 'mvp-security-v1',
      caseIds: MVP_CASES,
      mode: 'PAIRED',
      modelMode: 'REPLAY',
      repeatCount: 1,
    });
    expect(fetcher.mock.calls[0][0]).toBe('/api/v1/experiments');
  });
  it('requires separate affirmative LIVE cost consent even for direct form submit', async () => {
    const fetcher = vi.fn();
    vi.stubGlobal('fetch', fetcher);
    const dialog = await openForm();
    await userEvent.selectOptions(within(dialog).getByLabelText('모델 모드'), 'LIVE');
    expect(within(dialog).getByText('3회 (고정)')).toBeInTheDocument();
    expect(within(dialog).getByText('외부 모델 호출 비용이 발생할 수 있어요.')).toBeInTheDocument();
    await userEvent.click(mockCheckbox(dialog));
    expect(within(dialog).getByRole('button', { name: '비용 확인 후 LIVE 실험 접수' })).toBeDisabled();
    fireEvent.submit(dialog.querySelector('form')!);
    expect(fetcher).not.toHaveBeenCalled();
    await userEvent.click(costCheckbox(dialog));
    expect(within(dialog).getByRole('button', { name: '비용 확인 후 LIVE 실험 접수' })).toBeEnabled();
  });
  it('sends LIVE paired repeatCount 3 only after both confirmations and only to Spring', async () => {
    const fetcher = vi.fn().mockImplementation((_url, options) =>
      Promise.resolve(
        options.method === 'POST'
          ? response(receipt(options), 202)
          : response({
              experimentId: ID,
              status: 'PENDING',
              modelMode: 'LIVE',
              progress: { completed: 0, total: 36 },
              caseOutputs: [],
            }),
      ),
    );
    vi.stubGlobal('fetch', fetcher);
    const dialog = await openForm();
    await userEvent.selectOptions(within(dialog).getByLabelText('모델 모드'), 'LIVE');
    await userEvent.click(mockCheckbox(dialog));
    await userEvent.click(costCheckbox(dialog));
    await userEvent.click(within(dialog).getByRole('button', { name: '비용 확인 후 LIVE 실험 접수' }));
    await waitFor(() => expect(window.location.hash).toBe(`#/experiments/${ID}`));
    expect(fetcher.mock.calls.filter(([, options]) => options.method === 'POST')).toHaveLength(1);
    expect(fetcher.mock.calls.every(([url]) => url.startsWith('/api/v1/experiments'))).toBe(true);
    expect(fetcher.mock.calls[0][0]).toBe('/api/v1/experiments');
    expect(JSON.parse(fetcher.mock.calls[0][1].body)).toEqual({
      fixtureSetId: 'mvp-security-v1',
      caseIds: MVP_CASES,
      mode: 'PAIRED',
      modelMode: 'LIVE',
      repeatCount: 3,
    });
    expect(fetcher.mock.calls[0][1].headers['Idempotency-Key']).toMatch(/^[a-f0-9-]{36}$/);
  });
  it('clears consent whenever the fixture scope or model mode changes', async () => {
    vi.stubGlobal('fetch', vi.fn());
    const dialog = await openForm();
    await userEvent.selectOptions(within(dialog).getByLabelText('모델 모드'), 'LIVE');
    await userEvent.click(mockCheckbox(dialog));
    await userEvent.click(costCheckbox(dialog));
    await userEvent.selectOptions(
      within(dialog).getByLabelText('등록된 사례 묶음'),
      'security-evaluation-v1',
    );
    expect(costCheckbox(dialog)).not.toBeChecked();
    expect(mockCheckbox(dialog)).not.toBeChecked();
    expect(within(dialog).getByText('360개 · 60개 사례 × 3회 × 두 환경')).toBeInTheDocument();
    await userEvent.click(costCheckbox(dialog));
    await userEvent.click(mockCheckbox(dialog));
    await userEvent.selectOptions(within(dialog).getByLabelText('모델 모드'), 'REPLAY');
    expect(mockCheckbox(dialog)).not.toBeChecked();
    await userEvent.selectOptions(within(dialog).getByLabelText('모델 모드'), 'LIVE');
    expect(costCheckbox(dialog)).not.toBeChecked();
  });
  it('explains LIVE_NOT_AVAILABLE without falling back to an unapproved model call', async () => {
    const fetcher = vi
      .fn()
      .mockImplementation(() =>
        Promise.resolve(response({ reasonCodes: ['LIVE_NOT_AVAILABLE'], message: 'LIVE disabled' }, 400)),
      );
    vi.stubGlobal('fetch', fetcher);
    const dialog = await openForm();
    await userEvent.selectOptions(within(dialog).getByLabelText('모델 모드'), 'LIVE');
    await userEvent.click(mockCheckbox(dialog));
    await userEvent.click(costCheckbox(dialog));
    await userEvent.click(within(dialog).getByRole('button', { name: '비용 확인 후 LIVE 실험 접수' }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('LIVE_NOT_AVAILABLE');
    expect(within(dialog).getByRole('note')).toHaveTextContent('서버에서 LIVE가 활성화되지 않았어요');
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('shows real capture metadata and does not call a LIVE result synthetic when the server says false', async () => {
    window.location.hash = `/experiments/${ID}`;
    const capture = {
      modelMode: 'LIVE',
      model: 'test-only-live-model',
      promptVersion: 'KYC-PROMPT-TEST',
      promptHash: 'a'.repeat(64),
      modelOutputHash: 'b'.repeat(64),
      inputSnapshotHash: 'c'.repeat(64),
      captureRequestId: ID,
      captureRunId: ID,
      modelOutput: { status: 'VERIFIED', evidenceIds: [] },
    };
    const experiment = {
      experimentId: ID,
      status: 'COMPLETED',
      modelMode: 'LIVE',
      syntheticModelOutputs: false,
      liveRobustnessMeasured: true,
      progress: { completed: 2, total: 2 },
      caseOutputs: ['BASELINE', 'FUSE'].map((environment) => ({
        caseId: 'mock-live-case',
        repeat: 1,
        environment,
        status: 'COMPLETED',
        state: 'BLOCKED',
        decision: 'DENY',
        securityCheckDurationMs: 1.25,
        quarantineLatencyMs: null,
        trace: { modelCapture: capture },
      })),
      metrics: { exclusions: [], syntheticModelOutputs: false, liveRobustnessMeasured: true },
    };
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(() => Promise.resolve(response(experiment))),
    );
    render(<App />);
    await login();
    expect(await screen.findByText('실제 모델 캡처 응답 (서버 기록)')).toBeInTheDocument();
    expect(screen.getByText('공통 평가 공격 쌍의 실제 모델 결과로 측정됨')).toBeInTheDocument();
    expect(screen.queryByText('합성 후보 응답 재생 (서버 메타데이터)')).not.toBeInTheDocument();
    expect(screen.getAllByText('test-only-live-model')).toHaveLength(2);
    expect(screen.getAllByText('1.250 ms')).toHaveLength(2);
    expect(screen.getAllByText('미측정')).toHaveLength(2);
  });
  it('keeps capture failure and induction failure out of both arms without claiming valid live measurement', async () => {
    window.location.hash = `/experiments/${ID}`;
    const experiment = {
      experimentId: ID,
      status: 'COMPLETED',
      modelMode: 'LIVE',
      syntheticModelOutputs: false,
      liveRobustnessMeasured: false,
      caseOutputs: ['BASELINE', 'FUSE'].map((environment) => ({
        caseId: 'mock-failure',
        repeat: 1,
        environment,
        status: 'ERROR',
        state: 'ON_HOLD',
        decision: 'ERROR',
        exclusionReason: 'MODEL_OUTPUT_INVALID',
        trace: {},
      })),
      metrics: { exclusions: [{ pair: 'mock-failure:1', reasons: ['MODEL_OUTPUT_INVALID'] }] },
    };
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(() => Promise.resolve(response(experiment))),
    );
    render(<App />);
    await login();
    expect(await screen.findByText('LIVE 요청 · 아직 유효한 캡처 기록 없음')).toBeInTheDocument();
    expect(screen.getByText('아직 측정되지 않음')).toBeInTheDocument();
    expect(screen.getAllByText('공통 분모 제외')).toHaveLength(2);
    expect(screen.getAllByText(/모델 응답 형식 또는 캡처 연결 검증에 실패했어요/)).toHaveLength(3);
    expect(describeExperimentIssue('INDUCTION_FAILED')).toContain('공통 공격 분모에서 제외');
    expect(describeExperimentIssue('CAPTURE_ERROR:TimeoutException')).toContain('방어 성공이 아닙니다');
  });
});
