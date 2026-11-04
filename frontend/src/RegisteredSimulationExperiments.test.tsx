import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { FuseApi } from './api';
import { ExperimentsPage } from './components/Experiments';

const EXPERIMENT = '00000000-0000-4000-8000-000000000901';
const metadata = () => ({
  executionMode: 'VIRTUAL_NON_DURABLE',
  fixtureSets: [{
    fixtureSetId: 'synthetic-ui-suite',
    caseIds: ['synthetic-first', 'synthetic-second'],
    modelModes: ['REPLAY'],
    resultsSource: 'VIRTUAL_SIMULATION',
  }],
});
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const receipt = (options: RequestInit) => ({
  requestId: new Headers(options.headers).get('Idempotency-Key'),
  workflowId: null, generation: null, state: 'PENDING', decision: 'ALLOW', reasonCodes: [], message: 'VIRTUAL_EXPERIMENT_ACCEPTED',
  replayed: false, experimentId: EXPERIMENT, status: 'PENDING', totalRuns: 4,
});
async function open(api: FuseApi) {
  const view = render(<ExperimentsPage api={api} />);
  await userEvent.click(screen.getByRole('button', { name: '새 실험' }));
  return { ...view, dialog: screen.getByRole('dialog') };
}
async function registered(dialog: HTMLElement) {
  await userEvent.selectOptions(within(dialog).getByLabelText('실험 자료'), 'registered');
}
const confirm = (dialog: HTMLElement) => within(dialog).getByRole('checkbox', { name: '실험 전용 Mock 업무 실행을 요청합니다.' });
const submit = (dialog: HTMLElement) => within(dialog).getByRole('button', { name: '비교 실험 접수' });

beforeEach(() => {
  vi.restoreAllMocks();
  window.location.hash = '/experiments';
});

describe('registered synthetic experiment UI, mocked transport only', () => {
  it('keeps the existing default flow free of automatic registry requests', async () => {
    const fetcher = vi.fn();
    const { dialog } = await open(new FuseApi('synthetic-session', fetcher));
    expect(within(dialog).getByLabelText('실험 자료')).toHaveValue('legacy');
    expect(within(dialog).getByLabelText('등록된 사례 묶음')).toHaveValue('mvp-security-v1');
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('sends only the explicitly selected registered cases in REPLAY with no LIVE option', async () => {
    const fetcher = vi.fn().mockImplementation((_url, options) =>
      Promise.resolve(options.method === 'POST' ? json(receipt(options)) : json(metadata())));
    const { dialog } = await open(new FuseApi('synthetic-session', fetcher));
    await registered(dialog);
    await within(dialog).findByRole('option', { name: '합성 묶음 1 · 2개 사례' });
    expect(submit(dialog)).toBeDisabled();
    await userEvent.selectOptions(within(dialog).getByLabelText('등록된 사례 묶음'), 'synthetic-ui-suite');
    expect(within(dialog).getByLabelText('모델 모드')).toBeDisabled();
    expect(within(dialog).getByLabelText('모델 모드')).toHaveValue('REPLAY');
    expect(within(dialog).queryByRole('option', { name: /LIVE · 외부 모델/ })).not.toBeInTheDocument();
    await userEvent.click(confirm(dialog));
    await userEvent.click(submit(dialog));
    await waitFor(() => expect(window.location.hash).toBe(`#/experiments/${EXPERIMENT}`));
    const posts = fetcher.mock.calls.filter(([, options]) => options.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(posts[0][0]).toBe('/api/v1/experiments');
    expect(JSON.parse(posts[0][1].body as string)).toEqual({
      fixtureSetId: 'synthetic-ui-suite', caseIds: ['synthetic-first', 'synthetic-second'],
      mode: 'PAIRED', modelMode: 'REPLAY', repeatCount: 1,
    });
    expect(fetcher.mock.calls.every(([url]) => ['/api/v1/simulation/fixtures', '/api/v1/experiments'].includes(url))).toBe(true);
  });
  it.each([401, 403, 503])('keeps registry error %s visible and never submits a legacy plan', async (status) => {
    const marker = 'synthetic-private-registry-marker';
    const fetcher = vi.fn().mockResolvedValue(json({ reasonCodes: [marker], message: marker }, status));
    const { dialog } = await open(new FuseApi('synthetic-session', fetcher));
    await registered(dialog);
    const alert = await within(dialog).findByRole('alert');
    expect(alert).not.toHaveTextContent(marker);
    expect(alert).toHaveTextContent(status === 401 ? 'UNAUTHENTICATED' : status === 403 ? 'FORBIDDEN' : 'DEPENDENCY_UNAVAILABLE');
    expect(submit(dialog)).toBeDisabled();
    expect(confirm(dialog)).toBeDisabled();
    expect(within(dialog).getByLabelText('실험 자료')).toHaveValue('registered');
    expect(within(dialog).getByLabelText('등록된 사례 묶음')).toBeDisabled();
    fireEvent.submit(dialog.querySelector('form')!);
    expect(fetcher.mock.calls.filter(([, options]) => options.method === 'POST')).toHaveLength(0);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('keeps empty and malformed registries unavailable without a historical replacement', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(json({ executionMode: 'VIRTUAL_NON_DURABLE', fixtureSets: [] }))
      .mockResolvedValueOnce(json({ ...metadata(), resultsSource: 'unknown' }));
    const { dialog } = await open(new FuseApi('synthetic-session', fetcher));
    await registered(dialog);
    await within(dialog).findByText('현재 사용할 수 있는 등록된 합성 데이터가 없어요.');
    expect(submit(dialog)).toBeDisabled();
    await userEvent.click(within(dialog).getByRole('button', { name: '등록 자료 다시 조회' }));
    await within(dialog).findByRole('alert');
    expect(submit(dialog)).toBeDisabled();
    expect(within(dialog).getByLabelText('실험 자료')).toHaveValue('registered');
    expect(fetcher.mock.calls.filter(([, options]) => options.method === 'POST')).toHaveLength(0);
  });
  it('retires selected confirmation when a new API session returns the same fixture identifier', async () => {
    const firstFetcher = vi.fn().mockResolvedValue(json(metadata()));
    const secondFetcher = vi.fn().mockResolvedValue(json(metadata()));
    const { dialog, rerender } = await open(new FuseApi('synthetic-first-session', firstFetcher));
    await registered(dialog);
    await within(dialog).findByRole('option', { name: '합성 묶음 1 · 2개 사례' });
    await userEvent.selectOptions(within(dialog).getByLabelText('등록된 사례 묶음'), 'synthetic-ui-suite');
    await userEvent.click(confirm(dialog));
    expect(submit(dialog)).toBeEnabled();
    rerender(<ExperimentsPage api={new FuseApi('synthetic-second-session', secondFetcher)} />);
    await waitFor(() => expect(secondFetcher).toHaveBeenCalledTimes(1));
    await within(dialog).findByRole('option', { name: '합성 묶음 1 · 2개 사례' });
    expect(confirm(dialog)).not.toBeChecked();
    expect(submit(dialog)).toBeDisabled();
    fireEvent.submit(dialog.querySelector('form')!);
    expect(secondFetcher.mock.calls.filter(([, options]) => options.method === 'POST')).toHaveLength(0);
  });
});
