import { expect, test } from '@playwright/test';
import { checkpoint } from './checkpoints';

// Synthetic detail responses verify browser presentation only, not backend aggregation.
const ID = '00000000-0000-4000-8000-000000000201';
const groupName = '동일 범위의 잠재 영향 금액과 대상 신청 수';
for (const width of [1440, 390]) {
  test(`potential impact displays exact API amount and count at ${width}px`, async ({ page }) => {
    checkpoint('QUARANTINE_IMPACT');
    await page.setViewportSize({ width, height: 1000 });
    await page.route(`**/api/v1/incidents/${ID}/impact`, (route) =>
      route.fulfill({
        json: {
          incidentId: ID,
          scope: 'WORKFLOW',
          target: { workflowId: ID },
          actual: { paidAmountKrw: 0, paymentCount: 0 },
          potential: {
            totalAmountKrw: '9007199254740993',
            currency: 'KRW',
            applicationCount: 7,
            registeredCustomerCount: 999,
            perApplicationLimitKrw: 50000000,
          },
        },
      }),
    );
    await page.goto(`/#/quarantine/${ID}`);
    await page.getByLabel('개발용 인증 토큰').fill('synthetic-browser-session');
    await page.getByLabel('개발용 인증 토큰').press('Enter');
    const group = page.getByRole('group', { name: groupName });
    await expect(group.getByText('잠재 영향 금액', { exact: true })).toBeVisible();
    await expect(group.getByText('9,007,199,254,740,993원', { exact: true })).toBeVisible();
    await expect(group.getByText('7건', { exact: true })).toBeVisible();
    await expect(group.getByText('영향받을 수 있는 신청 금액의 합계', { exact: true })).toBeVisible();
    await expect(group).toHaveAccessibleDescription(/실제 지급액이나 확정 손실액이 아닙니다/);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  });
}

test('potential impact distinguishes zero from absent API values in the browser', async ({ page }) => {
  checkpoint('QUARANTINE_IMPACT');
  let potential: Record<string, unknown> = { totalAmountKrw: '0', applicationCount: 0, currency: 'KRW' };
  await page.route(`**/api/v1/incidents/${ID}/impact`, (route) =>
    route.fulfill({ json: { incidentId: ID, scope: 'WORKFLOW', target: {}, potential } }),
  );
  await page.goto(`/#/quarantine/${ID}`);
  await page.getByLabel('개발용 인증 토큰').fill('synthetic-browser-session');
  await page.getByLabel('개발용 인증 토큰').press('Enter');
  const group = page.getByRole('group', { name: groupName });
  await expect(group.getByText('0원', { exact: true })).toBeVisible();
  await expect(group.getByText('0건', { exact: true })).toBeVisible();
  potential = {};
  await page.getByRole('button', { name: '영향 새로고침' }).click();
  await expect(group.getByText('미제공', { exact: true })).toHaveCount(2);
  await expect(group.getByText('0원', { exact: true })).toHaveCount(0);
  await expect(group.getByText('0건', { exact: true })).toHaveCount(0);
});
