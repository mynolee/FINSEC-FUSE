import { render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FuseApi } from './api';
import { WorkflowPage } from './components/Workflows';

const ID = '00000000-0000-4000-8000-000000000102';
const CHECKED = '2026-10-09T04:00:00Z';
async function show(temporalStatus: unknown, status = 'ACTIVE') {
  const trace = {
    workflowId: ID,
    generation: 1,
    evidenceCheckedAt: CHECKED,
    runs: [],
    results: [],
    grants: [],
    dependencies: [],
    approvals: [],
    riskEvents: [],
    payments: [],
    auditEvents: [],
    sourceUses: [],
    evidenceUses: [
      {
        runId: ID,
        evidenceId: ID,
        evidenceType: 'ID_DOC',
        outcome: 'PASS',
        status,
        issuedAt: '2026-10-09T03:00:00Z',
        expiresAt: '2026-10-09T05:00:00Z',
        temporalStatus,
      },
    ],
  };
  const fetcher = vi.fn<typeof fetch>().mockImplementation(
    async (url) =>
      new Response(
        JSON.stringify(
          String(url).endsWith('/trace')
            ? trace
            : {
                workflowId: ID,
                generation: 1,
                state: 'KYC_PENDING',
                usedRisk: 10,
                reservedRisk: 0,
                riskLimit: 40,
                canApprove: false,
                canResume: false,
              },
        ),
        { headers: { 'Content-Type': 'application/json' } },
      ),
  );
  render(<WorkflowPage api={new FuseApi('synthetic-time-token', fetcher)} id={ID} />);
  const heading = await screen.findByRole('heading', { name: '독립 확인 자료' });
  const panel = heading.closest('section');
  expect(panel).not.toBeNull();
  return { panel: within(panel!), fetcher };
}
afterEach(() => vi.restoreAllMocks());

describe('server evidence time projection', () => {
  it.each([
    ['NOT_YET_ISSUED', '발급 전'],
    ['WITHIN_PERIOD', '기한 내'],
    ['EXPIRED', '기한 경과'],
  ])('renders %s separately from stored ACTIVE/PASS', async (value, label) => {
    const { panel, fetcher } = await show(value);
    expect(panel.getByRole('columnheader', { name: '저장 상태' })).toBeInTheDocument();
    expect(panel.getByRole('columnheader', { name: '시간 상태' })).toBeInTheDocument();
    expect(panel.getByText(label)).toBeInTheDocument();
    expect(panel.getByText('ACTIVE')).toBeInTheDocument();
    expect(panel.getByText('PASS')).toBeInTheDocument();
    expect(panel.getByText('서버 조회 기준 시각 (UTC)')).toBeInTheDocument();
    expect(panel.getByText(/전체 검증 통과나 사용·승인 가능을 뜻하지 않습니다/)).toBeInTheDocument();
    expect(fetcher.mock.calls.every(([, options]) => options?.method === 'GET')).toBe(true);
  });
  it('preserves REVOKED even when its server time window is within period', async () => {
    const { panel } = await show('WITHIN_PERIOD', 'REVOKED');
    expect(panel.getByText('REVOKED')).toBeInTheDocument();
    expect(panel.getByText('기한 내')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /정확한 승인 내용 확인/ })).not.toBeInTheDocument();
  });
  it('renders the server status without recomputing from the browser clock or dates', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(Date.parse('2099-01-01T00:00:00Z'));
    const { panel } = await show('WITHIN_PERIOD');
    expect(panel.getByText('기한 내')).toBeInTheDocument();
    expect(panel.queryByText('기한 경과')).not.toBeInTheDocument();
  });
  it.each([undefined, null, 'UNKNOWN', '<img src=x onerror=alert(1)>'])(
    'keeps unsupported time status unavailable: %s',
    async (value) => {
      const { panel } = await show(value);
      expect(panel.getByText('미제공')).toBeInTheDocument();
      expect(panel.queryByText('기한 내')).not.toBeInTheDocument();
      expect(panel.queryByRole('img')).not.toBeInTheDocument();
    },
  );
});
