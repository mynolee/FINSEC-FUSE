import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FuseApi } from '../api';
import type { Row, Trace, Workflow } from '../types';
import { WorkflowPage } from './Workflows';

const WORKFLOW = '00000000-0000-4000-8000-000000000700';
const GRANT = '00000000-0000-4000-8000-000000000701';
const ACTION = '00000000-0000-4000-8000-000000000702';
const TARGET = '00000000-0000-4000-8000-000000000703';
const PRIVATE = 'SYNTHETIC_TYPED_TRACE_RAW_CANARY';
const workflow: Workflow = {
  workflowId: WORKFLOW, generation: 2, state: 'KYC_PENDING', customerId: 'synthetic-ui-customer',
  businessReference: 'synthetic-ui-business', amountKrw: 1000, usedRisk: 1, reservedRisk: 0,
  riskLimit: 20, reasonCodes: [], canApprove: false, canResume: false, activeQuarantines: [],
};
function trace(grants: Row[]): Trace {
  return { workflowId: WORKFLOW, generation: 2, runs: [], results: [], grants,
    dependencies: [], approvals: [], riskEvents: [], payments: [], auditEvents: [],
    executionMode: 'VIRTUAL_SIMULATION', cryptographicAuthorityImplemented: false };
}
async function openGrantPanel(grants: Row[]) {
  // Mock the public API methods, preserving adversarial JS descriptors for the UI boundary.
  // Transport JSON parsing and authentication are separate tests.
  const transport = vi.fn<typeof fetch>();
  const api = new FuseApi('synthetic-ui-trace', transport);
  const workflowCall = vi.spyOn(api, 'workflow').mockResolvedValue(workflow);
  const traceCall = vi.spyOn(api, 'trace').mockResolvedValue(trace(grants));
  const view = render(<WorkflowPage api={api} id={WORKFLOW} />);
  await userEvent.click(await screen.findByRole('tab', { name: '권한 · 위험 장부' }));
  const heading = await screen.findByRole('heading', { name: '전달 봉투의 허용 범위' });
  const panel = heading.closest('section')!;
  expect(workflowCall).toHaveBeenCalledWith(WORKFLOW, expect.any(AbortSignal));
  expect(traceCall).toHaveBeenCalledWith(WORKFLOW, expect.any(AbortSignal));
  expect(transport).not.toHaveBeenCalled();
  return { ...view, panel };
}
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('public Workflows typed grant trace rendering', () => {
  it('shows the finite stored grant metadata in actual primary cells and expanded details', async () => {
    const row = Object.freeze({ grantId: GRANT, actionId: ACTION, targetRunId: TARGET,
      workflowId: WORKFLOW, generation: 2, action: 'EVALUATE_KYC', state: 'ISSUED', status: 'ISSUED' });
    const { panel } = await openGrantPanel([row]);
    const scope = within(panel);
    expect(scope.getByRole('columnheader', { name: '대상 실행 ID' })).toBeInTheDocument();
    expect(scope.getByRole('columnheader', { name: '세대' })).toBeInTheDocument();
    expect(scope.getByRole('cell', { name: '00000000…0701' })).toBeInTheDocument();
    expect(scope.getByRole('cell', { name: '00000000…0703' })).toBeInTheDocument();
    expect(scope.getByRole('cell', { name: 'EVALUATE_KYC' })).toBeInTheDocument();
    expect(scope.getByRole('cell', { name: 'ISSUED' })).toBeInTheDocument();
    expect(scope.queryByRole('columnheader', { name: '위임자 → 수임자' })).not.toBeInTheDocument();
    expect(scope.queryByRole('columnheader', { name: '깊이' })).not.toBeInTheDocument();
    expect(scope.queryByRole('columnheader', { name: '만료' })).not.toBeInTheDocument();
    await userEvent.click(scope.getByText('보기', { selector: 'summary' }));
    expect(panel.querySelector('details')).toHaveAttribute('open');
    expect(JSON.parse(panel.querySelector('pre')!.textContent!)).toEqual(row);
    expect(row.state).toBe('ISSUED');
  });

  it('does not read raw accessors or serialize nested material through either public grant view', async () => {
    let calls = 0;
    const material = { value: PRIVATE, toJSON() { calls += 1; return PRIVATE; },
      toString() { calls += 1; return PRIVATE; }, *[Symbol.iterator]() { calls += 1; yield PRIVATE; } };
    const row: Row = { grantId: GRANT, targetRunId: TARGET, generation: 2, state: 'ISSUED', status: 'ISSUED',
      action: material, rawToken: PRIVATE, token: PRIVATE, body: material, canonical: material,
      canonicalBytes: PRIVATE, bindingBytes: [PRIVATE], sourceAgent: PRIVATE, targetAgent: PRIVATE,
      depth: PRIVATE, expiresAt: PRIVATE };
    Object.defineProperty(row, 'actionId', { enumerable: true, get() { calls += 1; return PRIVATE; } });
    Object.defineProperty(row, 'workflowId', { enumerable: true, get() { calls += 1; return PRIVATE; } });
    const rows: Row[] = [row, {}];
    Object.defineProperty(rows, '1', { get() { calls += 1; return { grantId: PRIVATE }; } });
    const { panel, container } = await openGrantPanel(rows);
    expect(panel.textContent).not.toContain(PRIVATE);
    for (const summary of within(panel).getAllByText('보기', { selector: 'summary' })) await userEvent.click(summary);
    const projected = JSON.parse(panel.querySelector('pre')!.textContent!);
    expect(projected).toEqual({ grantId: GRANT, targetRunId: TARGET, generation: 2, state: 'ISSUED', status: 'ISSUED' });
    expect(container.textContent).not.toContain(PRIVATE);
    expect(calls).toBe(0);
    expect(row.rawToken).toBe(PRIVATE);
  });

  it('never promotes provider validation or conflicting aliases to stored grant success', async () => {
    const rows = [
      { grantId: GRANT, targetRunId: TARGET, generation: 2, action: 'EVALUATE_KYC', state: 'VALIDATED', status: 'VALIDATED', providerStatus: 'ALLOW' },
      { grantId: ACTION, targetRunId: TARGET, generation: 2, action: 'EVALUATE_KYC', state: 'ISSUED', status: 'CONSUMED' },
    ];
    const { panel } = await openGrantPanel(rows);
    const dataRows = within(panel).getAllByRole('row').slice(1);
    const unknownState = within(dataRows[0]).getAllByRole('cell')[4];
    expect(unknownState).toHaveTextContent('미제공');
    expect(unknownState.querySelector('.status')).not.toHaveClass('green');
    expect(within(dataRows[1]).getAllByRole('cell')[4]).toHaveTextContent('ISSUED');
    expect(panel.textContent).not.toContain('VALIDATED');
    expect(panel.textContent).not.toContain('CONSUMED');
    for (const summary of within(panel).getAllByText('보기', { selector: 'summary' })) await userEvent.click(summary);
    const details = Array.from(panel.querySelectorAll('pre')).map(pre => JSON.parse(pre.textContent!));
    expect(details[0]).not.toHaveProperty('status');expect(details[0]).not.toHaveProperty('state');
    expect(details[1]).toMatchObject({ state: 'ISSUED' });expect(details[1]).not.toHaveProperty('status');
  });
});
