import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FuseApi } from './api';
import { ExperimentsPage } from './components/Experiments';

const ID = '00000000-0000-4000-8000-000000000971';
const response = (progress: unknown) => new Response(JSON.stringify({
  experimentId: ID, status: 'COMPLETED', modelMode: 'REPLAY',
  resultsSource: 'VIRTUAL_SIMULATION', syntheticModelOutputs: true,
  liveRobustnessMeasured: false, caseOutputs: [], progress,
}), { status: 200, headers: { 'Content-Type': 'application/json' } });
const progressText = () => screen.getByText('진행', { selector: 'dt' }).parentElement?.querySelector('dd')?.textContent;
async function open(progress: unknown) {
  const fetcher = vi.fn<typeof fetch>().mockImplementation(async () => response(progress));
  render(<ExperimentsPage api={new FuseApi('synthetic-progress-session', fetcher)} id={ID} />);
  await screen.findByText(ID);
  return fetcher;
}
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('public experiment pair progress display, synthetic transport only', () => {
  it.each([[0, 3], [1, 3], [3, 3], [Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]])('shows %s/%s as comparison pairs without doubling environment runs', async (completedPairs, totalPairs) => {
    const fetcher = await open({ completedPairs, totalPairs });
    await waitFor(() => expect(progressText()).toBe(`${completedPairs} / ${totalPairs} 비교 쌍`));
    expect(progressText()).not.toContain('환경 실행');
    expect(fetcher.mock.calls.every(([url, options]) => url === `/api/v1/experiments/${ID}` && options?.method === 'GET')).toBe(true);
  });

  it.each([
    { completedPairs: '1', totalPairs: 3 }, { completedPairs: 1, totalPairs: '3' },
    { completedPairs: true, totalPairs: 3 }, { completedPairs: 1.5, totalPairs: 3 },
    { completedPairs: -1, totalPairs: 3 }, { completedPairs: 4, totalPairs: 3 },
    { completedPairs: 0, totalPairs: 0 }, { completedPairs: 0, totalPairs: -1 },
    { completedPairs: 1, totalPairs: 3.5 }, { completedPairs: 0, totalPairs: Number.MAX_SAFE_INTEGER + 1 },
    { completedPairs: Number.MAX_SAFE_INTEGER + 1, totalPairs: Number.MAX_SAFE_INTEGER + 1 },
    { completedPairs: null, totalPairs: 3 },
  ])('does not hide malformed pair counts behind valid legacy fields: %j', async (pair) => {
    await open({ ...pair, completedRuns: 2, totalRuns: 6, completed: 2, total: 6 });
    await waitFor(() => expect(progressText()).toBe('미제공'));
  });

  it.each([{ completedPairs: 1 }, { totalPairs: 3 }])('does not reinterpret an incomplete pair as environment runs: %j', async (pair) => {
    await open({ ...pair, completedRuns: 2, totalRuns: 6 });
    await waitFor(() => expect(progressText()).toBe('미제공'));
  });

  it.each([
    [{ completedRuns: 2, totalRuns: 6 }, '2 / 6 환경 실행'],
    [{ completed: 1, total: 4 }, '1 / 4 환경 실행'],
    [{ completedRuns: 0, totalRuns: 0 }, '0 / 0 환경 실행'],
    [2, '2'], [0.5, '0.5'],
  ])('preserves prior progress forms only when pair fields are absent: %j', async (progress, expected) => {
    await open(progress);
    await waitFor(() => expect(progressText()).toBe(expected));
  });

  it('does not invoke pair or legacy accessor values to manufacture progress', async () => {
    const getter = vi.fn(() => { throw new Error('synthetic-progress-accessor'); });
    const progress = { totalPairs: 3, completedRuns: 2, totalRuns: 6 };
    Object.defineProperty(progress, 'completedPairs', { enumerable: true, get: getter });
    Object.defineProperty(progress, 'completedRuns', { enumerable: true, get: getter });
    Object.defineProperty(progress, 'totalRuns', { enumerable: true, get: getter });
    const api = new FuseApi('synthetic-own-data-session', vi.fn());
    vi.spyOn(api, 'experiment').mockResolvedValue({ experimentId: ID, status: 'COMPLETED', caseOutputs: [], progress });
    render(<ExperimentsPage api={api} id={ID} />);
    await screen.findByText(ID);
    await waitFor(() => expect(progressText()).toBe('미제공'));
    expect(getter).not.toHaveBeenCalled();
  });

  it.each([undefined, {}])('keeps absent or empty progress unavailable: %j', async (progress) => {
    await open(progress);
    await waitFor(() => expect(progressText()).toBe('미제공'));
  });
  it.each([
    { completedRuns: { note: 'SYNTHETIC_RAW_CANARY' }, totalRuns: 6 },
    { completedRuns: 2, totalRuns: ['SYNTHETIC_RAW_CANARY'] },
    { completed: ['SYNTHETIC_RAW_CANARY'], total: 6 },
    { completed: 2, total: { note: 'SYNTHETIC_RAW_CANARY' } },
    { completedRuns: '2', totalRuns: 6 }, { completedRuns: 2, totalRuns: '6' },
    { completedRuns: true, totalRuns: 6 }, { completedRuns: -1, totalRuns: 6 },
    { completedRuns: 7, totalRuns: 6 }, { completedRuns: 1.5, totalRuns: 6 },
    { completedRuns: 2 }, { totalRuns: 6 },
  ])('keeps nonnumeric or incoherent legacy counts unavailable without raw nested fields: %j', async (progress) => {
    await open(progress);
    await waitFor(() => expect(progressText()).toBe('미제공'));
    expect(screen.queryByText(/SYNTHETIC_RAW_CANARY/)).not.toBeInTheDocument();
  });

  it('reaches the legacy-only getter branch without invoking any accessor', async () => {
    const getter = vi.fn(() => { throw new Error('SYNTHETIC_RAW_CANARY'); });
    const progress = {};
    for (const key of ['completedRuns', 'totalRuns', 'completed', 'total'])
      Object.defineProperty(progress, key, { enumerable: true, get: getter });
    expect(Object.hasOwn(progress, 'completedPairs')).toBe(false);
    expect(Object.hasOwn(progress, 'totalPairs')).toBe(false);
    const api = new FuseApi('synthetic-legacy-own-data-session', vi.fn());
    vi.spyOn(api, 'experiment').mockResolvedValue({ experimentId: ID, status: 'COMPLETED', caseOutputs: [], progress });
    render(<ExperimentsPage api={api} id={ID} />);
    await screen.findByText(ID);
    await waitFor(() => expect(progressText()).toBe('미제공'));
    expect(getter).not.toHaveBeenCalled();
    expect(screen.queryByText(/SYNTHETIC_RAW_CANARY/)).not.toBeInTheDocument();
  });

});
