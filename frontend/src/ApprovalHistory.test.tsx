import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { FuseApi } from './api';
import { WorkflowPage } from './components/Workflows';
import type { Trace, Workflow } from './types';

const ID = '00000000-0000-4000-8000-000000000102';
const APPROVAL_ID = '00000000-0000-4000-8000-000000000202';

describe('persisted approval history', () => {
  it.each(['AVAILABLE', 'REJECTED'])('renders the recorded amount for %s approval', async (status) => {
    const workflow: Workflow = {
      workflowId: ID,
      generation: 1,
      state: status === 'AVAILABLE' ? 'APPROVED' : 'REJECTED',
      // Deliberately different: the history column must read its own persisted record.
      amountKrw: 3000000,
      usedRisk: 35,
      reservedRisk: 0,
      riskLimit: 40,
      canApprove: false,
      canResume: false,
    };
    const trace: Trace = {
      workflowId: ID,
      generation: 1,
      runs: [],
      results: [],
      grants: [],
      dependencies: [],
      approvals: [
        {
          approvalId: APPROVAL_ID,
          generation: 1,
          actorId: 'staff-01',
          status,
          amountKrw: 1000000,
          reviewSnapshotHash: 'a'.repeat(64),
          extraRisk: status === 'AVAILABLE' ? 45 : 0,
          riskLimit: status === 'AVAILABLE' ? 85 : 40,
          expiresAt: '2026-10-09T04:10:00Z',
          createdAt: '2026-10-09T04:00:00Z',
        },
      ],
      riskEvents: [],
      payments: [],
      auditEvents: [],
      sourceUses: [],
      evidenceUses: [],
    };
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (url) => {
      const path = String(url);
      if (![`/api/v1/workflows/${ID}`, `/api/v1/workflows/${ID}/trace`].includes(path))
        throw new Error('Unexpected request');
      return new Response(JSON.stringify(path.endsWith('/trace') ? trace : workflow), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });
    render(<WorkflowPage api={new FuseApi('synthetic-history-token', fetcher)} id={ID} />);
    await userEvent.click(await screen.findByRole('tab', { name: '권한 · 위험 장부' }));
    const row = await screen.findByRole('row', { name: /1,000,000원/ });
    expect(within(row).getByText('1,000,000원')).toBeInTheDocument();
    expect(within(row).getByTitle(status)).toBeInTheDocument();
    expect(within(row).getByText('staff-01')).toBeInTheDocument();
    expect(within(row).queryByText('3,000,000원')).not.toBeInTheDocument();
    expect(within(row).queryByText('미제공')).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain('synthetic-history-token');
    expect(fetcher.mock.calls.every(([, options]) => options?.method === 'GET')).toBe(true);
  });
});
