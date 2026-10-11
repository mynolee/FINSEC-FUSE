import { render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { FuseApi } from './api';
import { QuarantinePage } from './components/Quarantine';

const ID = '00000000-0000-4000-8000-000000000201';
const policy = {
  roles: ['LOAN', 'PAYMENT'],
  maxDownstreamDepth: 2,
  registeredCustomerCount: 999,
  perApplicationLimitKrw: 50000000,
};
async function show(potential: unknown) {
  const fetcher = vi.fn().mockResolvedValue(
    new Response(
      JSON.stringify({
        incidentId: ID,
        scope: 'WORKFLOW',
        target: { workflowId: ID },
        actual: { paidAmountKrw: 12, paymentCount: 1 },
        potential,
        currentAffectedWorkflowIds: [ID],
        historicalRunIds: [ID],
      }),
      { headers: { 'Content-Type': 'application/json' } },
    ),
  );
  render(<QuarantinePage api={new FuseApi('synthetic-unit-session', fetcher)} id={ID} />);
  const group = await screen.findByRole('group', { name: '동일 범위의 잠재 영향 금액과 대상 신청 수' });
  return { group: within(group), fetcher };
}

describe('server-derived potential application amount', () => {
  it('shows exact API amount and same-scope count without deriving them from client rows or policy limits', async () => {
    const { group, fetcher } = await show({
      ...policy,
      totalAmountKrw: '9007199254740993',
      applicationCount: 7,
      currency: 'KRW',
    });
    expect(group.getByText('잠재 영향 금액')).toBeInTheDocument();
    expect(group.getByText('9,007,199,254,740,993원')).toBeInTheDocument();
    expect(group.getByText('7건')).toBeInTheDocument();
    expect(group.getByText('영향받을 수 있는 신청 금액의 합계')).toBeInTheDocument();
    expect(screen.getByText(/실제 지급액이나 확정 손실액이 아닙니다/)).toBeInTheDocument();
    expect(screen.getByRole('region', { name: '실제 영향' })).toHaveTextContent('12원');
    expect(screen.getByText('999')).toBeInTheDocument();
    expect(screen.getByText('50,000,000원')).toBeInTheDocument();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0][1].method).toBe('GET');
  });
  it('preserves a genuine server zero amount and count', async () => {
    const { group } = await show({ ...policy, totalAmountKrw: '0', applicationCount: 0, currency: 'KRW' });
    expect(group.getByText('0원')).toBeInTheDocument();
    expect(group.getByText('0건')).toBeInTheDocument();
    expect(group.queryByText('미제공')).not.toBeInTheDocument();
  });
  it.each([
    undefined,
    null,
    {},
    { ...policy },
    { totalAmountKrw: null, applicationCount: null, currency: 'KRW' },
    { totalAmountKrw: '1.5', applicationCount: -1, currency: 'KRW' },
    { totalAmountKrw: 9007199254740992, applicationCount: {}, currency: 'KRW' },
    { totalAmountKrw: '123', applicationCount: '2' },
    { roles: {}, missingPolicyFields: {}, totalAmountKrw: {}, applicationCount: [] },
  ])('keeps missing or invalid DTO amounts/counts unavailable: %j', async (potential) => {
    const { group } = await show(potential);
    expect(group.getAllByText('미제공')).toHaveLength(2);
    expect(group.queryByText('0원')).not.toBeInTheDocument();
    expect(group.queryByText('0건')).not.toBeInTheDocument();
  });
  it('does not assume KRW when currency is unsupported, while retaining a valid count', async () => {
    const { group } = await show({ totalAmountKrw: '100', applicationCount: 2, currency: 'USD' });
    expect(group.getByText('미제공')).toBeInTheDocument();
    expect(group.getByText('2건')).toBeInTheDocument();
  });
  it('keeps a valid amount visible if only the count is absent', async () => {
    const { group } = await show({ totalAmountKrw: '123', currency: 'KRW' });
    expect(group.getByText('123원')).toBeInTheDocument();
    expect(group.getByText('미제공')).toBeInTheDocument();
  });
});
