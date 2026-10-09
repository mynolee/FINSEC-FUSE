import { fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { describeExperimentIssue, MVP_CASES } from './components/Experiments';

const ID = '00000000-0000-4000-8000-000000000301';
const response = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const receipt = { requestId: ID, decision: 'ALLOW', state: 'PENDING', reasonCodes: [], replayed: false };
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
  it('defaults to REPLAY once and does not ask to approve external model costs', async () => {
    const fetcher = vi.fn().mockImplementation(() => Promise.resolve(response(receipt)));
    vi.stubGlobal('fetch', fetcher);
    const dialog = await openForm();
    expect(within(dialog).getByLabelText('모델 모드')).toHaveValue('REPLAY');
    expect(within(dialog).getByText('1회 (고정)')).toBeInTheDocument();
    expect(
      within(dialog).queryByRole('checkbox', { name: /외부 모델 전송과 발생 가능한 비용/ }),
    ).not.toBeInTheDocument();
    await userEvent.click(mockCheckbox(dialog));
    await userEvent.click(within(dialog).getByRole('button', { name: '비교 실험 접수' }));
    await within(dialog).findByRole('status');
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
    const fetcher = vi.fn().mockImplementation(() => Promise.resolve(response(receipt)));
    vi.stubGlobal('fetch', fetcher);
    const dialog = await openForm();
    await userEvent.selectOptions(within(dialog).getByLabelText('모델 모드'), 'LIVE');
    await userEvent.click(mockCheckbox(dialog));
    await userEvent.click(costCheckbox(dialog));
    await userEvent.click(within(dialog).getByRole('button', { name: '비용 확인 후 LIVE 실험 접수' }));
    await within(dialog).findByRole('status');
    expect(fetcher).toHaveBeenCalledTimes(1);
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
