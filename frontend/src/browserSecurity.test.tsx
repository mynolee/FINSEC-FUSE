import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import App from './App';
import { ApiError } from './api';
import { ErrorNotice, Json, RecordTable } from './components/ui';
const payloads = [
  '<img src=x onerror="window.syntheticExecuted=1">',
  '<svg onload="window.syntheticExecuted=1">',
  '</script><script>window.syntheticExecuted=1</script>',
  'javascript:syntheticExecuted=1',
];
describe('v2.1 browser boundaries (DOM, not real browser CSP enforcement)', () => {
  it.each(payloads)('renders untrusted data literally: %s', (payload) => {
    const { container } = render(
      <>
        <ErrorNotice error={new ApiError(payload, 400, [payload])} />
        <Json value={{ explanation: payload, note: payload, documentText: payload }} />
        <RecordTable rows={[{ comment: payload }]} columns={[{ key: 'comment', label: 'Comment' }]} />
      </>,
    );
    expect(container.textContent).toContain(payload);
    expect(container.querySelectorAll('img,svg,script,a')).toHaveLength(0);
    expect((window as unknown as Record<string, unknown>).syntheticExecuted).toBeUndefined();
  });
  it('configures enforced response headers without inline allowances', () => {
    const config = readFileSync('nginx.conf', 'utf8');
    for (const part of [
      'Cache-Control "no-store" always',
      'X-Content-Type-Options nosniff always',
      'Referrer-Policy no-referrer always',
      'X-Frame-Options DENY always',
      "base-uri 'none'",
      "frame-ancestors 'none'",
      "script-src 'self'",
      "style-src 'self'",
    ])
      expect(config).toContain(part);
    expect(config).not.toMatch(/unsafe-inline|unsafe-eval|Content-Security-Policy-Report-Only/);
  });
  it('clears private state and token on a back-forward cache restore', async () => {
    window.location.hash = '/workflows';
    const fetcher = vi
      .fn()
      .mockResolvedValue(new Response(JSON.stringify({ items: [], total: 0, page: 0, size: 20 })));
    vi.stubGlobal('fetch', fetcher);
    render(<App />);
    fireEvent.change(screen.getByLabelText('개발용 인증 토큰'), {
      target: { value: 'synthetic-session-marker' },
    });
    fireEvent.click(screen.getByRole('button', { name: /연결하고 업무 조회/ }));
    await waitFor(() => expect(fetcher).toHaveBeenCalled());
    fireEvent(window, new PageTransitionEvent('pageshow', { persisted: true }));
    expect(await screen.findByRole('heading', { name: '운영 콘솔 연결' })).toBeInTheDocument();
    expect(screen.getByLabelText('개발용 인증 토큰')).toHaveValue('');
  });
});
