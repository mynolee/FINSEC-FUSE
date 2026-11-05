import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FuseApi } from './api';
import { ExperimentsPage } from './components/Experiments';

const FIXTURE = 'synthetic-explicit-sixty';
const EXPERIMENT = '00000000-0000-4000-8000-000000000961';
// Declared synthetic transport fixture only; production never constructs IDs or case data.
const IDS = [
  "synthetic-explicit-case-01",
  "synthetic-explicit-case-02",
  "synthetic-explicit-case-03",
  "synthetic-explicit-case-04",
  "synthetic-explicit-case-05",
  "synthetic-explicit-case-06",
  "synthetic-explicit-case-07",
  "synthetic-explicit-case-08",
  "synthetic-explicit-case-09",
  "synthetic-explicit-case-10",
  "synthetic-explicit-case-11",
  "synthetic-explicit-case-12",
  "synthetic-explicit-case-13",
  "synthetic-explicit-case-14",
  "synthetic-explicit-case-15",
  "synthetic-explicit-case-16",
  "synthetic-explicit-case-17",
  "synthetic-explicit-case-18",
  "synthetic-explicit-case-19",
  "synthetic-explicit-case-20",
  "synthetic-explicit-case-21",
  "synthetic-explicit-case-22",
  "synthetic-explicit-case-23",
  "synthetic-explicit-case-24",
  "synthetic-explicit-case-25",
  "synthetic-explicit-case-26",
  "synthetic-explicit-case-27",
  "synthetic-explicit-case-28",
  "synthetic-explicit-case-29",
  "synthetic-explicit-case-30",
  "synthetic-explicit-case-31",
  "synthetic-explicit-case-32",
  "synthetic-explicit-case-33",
  "synthetic-explicit-case-34",
  "synthetic-explicit-case-35",
  "synthetic-explicit-case-36",
  "synthetic-explicit-case-37",
  "synthetic-explicit-case-38",
  "synthetic-explicit-case-39",
  "synthetic-explicit-case-40",
  "synthetic-explicit-case-41",
  "synthetic-explicit-case-42",
  "synthetic-explicit-case-43",
  "synthetic-explicit-case-44",
  "synthetic-explicit-case-45",
  "synthetic-explicit-case-46",
  "synthetic-explicit-case-47",
  "synthetic-explicit-case-48",
  "synthetic-explicit-case-49",
  "synthetic-explicit-case-50",
  "synthetic-explicit-case-51",
  "synthetic-explicit-case-52",
  "synthetic-explicit-case-53",
  "synthetic-explicit-case-54",
  "synthetic-explicit-case-55",
  "synthetic-explicit-case-56",
  "synthetic-explicit-case-57",
  "synthetic-explicit-case-58",
  "synthetic-explicit-case-59",
  "synthetic-explicit-case-60"
];
const metadata = (caseIds: string[]) => ({ executionMode: 'VIRTUAL_NON_DURABLE', fixtureSets: [
  { fixtureSetId: FIXTURE, caseIds, modelModes: ['REPLAY'], resultsSource: 'VIRTUAL_SIMULATION' } ] });
const response = (body: unknown) => new Response(JSON.stringify(body), { status: 200,
  headers: { 'Content-Type': 'application/json' } });
async function open(fetcher: typeof fetch) {
  render(<ExperimentsPage api={new FuseApi('synthetic-sixty-session', fetcher)} />);
  await userEvent.click(screen.getByRole('button', { name: '새 실험' }));
  const dialog = screen.getByRole('dialog');
  await userEvent.selectOptions(within(dialog).getByLabelText('실험 자료'), 'registered-sixty');
  return dialog;
}
const posts = (fetcher: ReturnType<typeof vi.fn<typeof fetch>>) =>
  fetcher.mock.calls.filter(([, options]) => options?.method === 'POST');
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('explicit registered sixty-case public create form, synthetic transport only', () => {
  it.each([
    { label: 'no registered fixture', data: { executionMode: 'VIRTUAL_NON_DURABLE', fixtureSets: [] } },
    { label: 'zero cases', data: metadata([]) },
    { label: 'fifty-nine cases', data: metadata(IDS.slice(0, 59)) },
    { label: 'duplicate case', data: metadata([...IDS.slice(0, 59), IDS[0]]) },
    { label: 'invalid case identifier', data: metadata([...IDS.slice(0, 59), 'unknown-not-synthetic']) },
  ])('never POSTs or pads the $label registry', async ({ label, data }) => {
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async () => response(data));
    const dialog = await open(fetcher);
    await waitFor(() => expect(within(dialog).getByLabelText('등록된 사례 묶음')).toBeDisabled());
    // Wait for a settled error/empty selection, not merely its initial loading disablement.
    if (label === 'no registered fixture' || label === 'fifty-nine cases')
      await within(dialog).findByText('현재 등록된 서로 다른 사례 60개 묶음이 없습니다. 원본 사례를 자동 복원하지 않습니다.');
    else await within(dialog).findByRole('alert');
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(within(dialog).getByRole('button', { name: '비교 실험 접수' })).toBeDisabled();
    fireEvent.submit(dialog.querySelector('form')!);
    expect(posts(fetcher)).toHaveLength(0);
    expect(within(dialog).queryByRole('option', { name: /공격 40개/ })).not.toBeInTheDocument();
  });

  it('keeps a pending registry unselectable and still requires explicit selection after it resolves', async () => {
    let resolve!: (value: Response) => void;
    const pending = new Promise<Response>(done => { resolve = done; });
    const fetcher = vi.fn<typeof fetch>().mockImplementation(() => pending);
    const dialog = await open(fetcher);
    expect(within(dialog).getByLabelText('등록된 사례 묶음')).toBeDisabled();
    fireEvent.submit(dialog.querySelector('form')!); expect(posts(fetcher)).toHaveLength(0);
    resolve(response(metadata(IDS)));
    await within(dialog).findByRole('option', { name: '합성 묶음 1 · 60개 사례' });
    expect(within(dialog).getByLabelText('등록된 사례 묶음')).toHaveValue('');
    expect(within(dialog).getByRole('button', { name: '비교 실험 접수' })).toBeDisabled();
    expect(posts(fetcher)).toHaveLength(0);
  });

  it('POSTs the exact selected server IDs and fixture in REPLAY without inventing an original catalog', async () => {
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (_url, options) => {
      if (options?.method !== 'POST') return response(metadata(IDS));
      return response({ requestId: new Headers(options.headers).get('Idempotency-Key'), workflowId: null,
        generation: null, state: 'PENDING', decision: 'ALLOW', reasonCodes: [], message: 'VIRTUAL_EXPERIMENT_ACCEPTED',
        replayed: false, experimentId: EXPERIMENT, status: 'PENDING', totalRuns: 120 });
    });
    const dialog = await open(fetcher);
    await within(dialog).findByRole('option', { name: '합성 묶음 1 · 60개 사례' });
    await userEvent.selectOptions(within(dialog).getByLabelText('등록된 사례 묶음'), FIXTURE);
    expect(within(dialog).getByLabelText('모델 모드')).toHaveValue('REPLAY');
    expect(within(dialog).getByLabelText('모델 모드')).toBeDisabled();
    await userEvent.click(within(dialog).getByRole('checkbox', { name: '실험 전용 Mock 업무 실행을 요청합니다.' }));
    await userEvent.click(within(dialog).getByRole('button', { name: '비교 실험 접수' }));
    await waitFor(() => expect(posts(fetcher)).toHaveLength(1));
    expect(posts(fetcher)[0][0]).toBe('/api/v1/experiments');
    expect(JSON.parse(posts(fetcher)[0][1]!.body as string)).toEqual({ fixtureSetId: FIXTURE,
      caseIds: IDS, mode: 'PAIRED', modelMode: 'REPLAY', repeatCount: 1 });
    expect(fetcher.mock.calls.every(([url]) => ['/api/v1/simulation/fixtures', '/api/v1/experiments'].includes(String(url)))).toBe(true);
    expect(IDS).toHaveLength(60); expect(new Set(IDS).size).toBe(60);
  });
});
