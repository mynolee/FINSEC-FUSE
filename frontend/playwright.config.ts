import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  timeout: 45000,
  expect: { timeout: 15000 },
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  fullyParallel: false,
  reporter: [['./tests/e2e/safe-reporter.ts']],
  reportSlowTests: null,
  use: {
    baseURL: process.env.FUSE_UI_URL || 'http://127.0.0.1:5173',
    headless: true,
    // CI installs Playwright's version-matched browser. A local override is opt-in.
    ...(process.env.CHROMIUM_PATH ? { launchOptions: { executablePath: process.env.CHROMIUM_PATH } } : {}),
    // Authenticated recordings can contain bearer tokens and candidate documents.
    trace: 'off',
    screenshot: 'off',
    video: 'off',
    serviceWorkers: 'block',
  },
  webServer: process.env.FUSE_UI_URL
    ? undefined
    : {
        command: 'npm run dev -- --host 127.0.0.1',
        url: 'http://127.0.0.1:5173',
        reuseExistingServer: !process.env.CI,
        timeout: 30000,
      },
});
