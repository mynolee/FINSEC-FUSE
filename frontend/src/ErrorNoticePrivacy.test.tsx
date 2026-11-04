import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from './api';
import { ErrorNotice } from './components/ui';

const PRIVATE = 'SYNTHETIC_PRIVATE_TOKEN_MARKER';
const URL = `https://synthetic.invalid/diagnostic?token=${PRIVATE}`;
const GENERIC = '요청을 처리하지 못했어요.';

describe('ErrorNotice public message and metadata boundaries', () => {
  it('does not echo an unknown exception or its diagnostic URL in text or retry description', () => {
    const { container } = render(<ErrorNotice error={new Error(URL)} retry={vi.fn()} />);
    expect(screen.getByRole('alert')).toHaveTextContent(GENERIC);
    expect(screen.getByRole('button', { name: '다시 조회' })).toHaveAccessibleDescription(GENERIC);
    expect(container.textContent).not.toContain(PRIVATE);
    expect(container.textContent).not.toContain(URL);
  });

  it('rejects malformed ApiError status and unknown codes rather than trusting the class', () => {
    const error = new ApiError(URL, 403, [PRIVATE, URL, `FORBIDDEN:${PRIVATE}`]);
    Object.defineProperty(error, 'status', { value: URL });
    const { container } = render(<ErrorNotice error={error} />);
    expect(screen.getByRole('alert')).toHaveTextContent(GENERIC);
    expect(container.textContent).not.toContain('HTTP');
    expect(container.textContent).not.toContain('FORBIDDEN');
    expect(container.textContent).not.toContain(PRIVATE);
    expect(container.textContent).not.toContain('synthetic.invalid');
  });

  it('keeps validated HTTP status, exact public codes and the fixed public explanation', () => {
    const error = new ApiError(URL, 403, ['FORBIDDEN', PRIVATE, 'EVIDENCE_MISSING', 'FORBIDDEN', 'HTTP_503']);
    const { container } = render(<ErrorNotice error={error} retry={vi.fn()} />);
    const alert = screen.getByRole('alert');
    expect(alert).toHaveTextContent('현재 인증 주체에게 이 작업의 권한이 없어요.');
    expect(within(alert).getByText('HTTP 403')).toBeInTheDocument();
    expect(within(alert).getAllByText('FORBIDDEN')).toHaveLength(1);
    expect(within(alert).getByText('EVIDENCE_MISSING')).toBeInTheDocument();
    expect(within(alert).getByText('HTTP_503')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '다시 조회' })).toHaveAccessibleDescription('현재 인증 주체에게 이 작업의 권한이 없어요.');
    expect(container.textContent).not.toContain(PRIVATE);
    expect(container.textContent).not.toContain(URL);
  });

  it('does not invoke message/status/reason getters or custom serialization hooks', () => {
    const getter = vi.fn(() => { throw new Error(PRIVATE); });
    const error = new ApiError('unknown diagnostic', 403, []);
    for (const field of ['message', 'status', 'reasonCodes']) Object.defineProperty(error, field, { get: getter });
    Object.defineProperty(error, 'toString', { value: getter });
    Object.defineProperty(error, 'toJSON', { value: getter });
    const { container } = render(<ErrorNotice error={error} retry={vi.fn()} />);
    expect(screen.getByRole('alert')).toHaveTextContent(GENERIC);
    expect(getter).not.toHaveBeenCalled();
    expect(container.textContent).not.toContain(PRIVATE);
  });

  it('skips array index getters and inherited metadata while retaining own safe entries', () => {
    const getter = vi.fn(() => PRIVATE);
    const codes = ['unused', 'FORBIDDEN'];
    Object.defineProperty(codes, '0', { get: getter });
    const error = new ApiError(URL, 403, codes);
    const view = render(<ErrorNotice error={error} />);
    expect(screen.getByRole('alert')).toHaveTextContent('HTTP 403');
    expect(screen.getByText('FORBIDDEN')).toBeInTheDocument();
    expect(getter).not.toHaveBeenCalled();
    expect(view.container.textContent).not.toContain(PRIVATE);
    const inherited = Object.create({ message: URL, status: 403, reasonCodes: [PRIVATE, 'FORBIDDEN'] });
    view.rerender(<ErrorNotice error={inherited} />);
    expect(screen.getByRole('alert')).toHaveTextContent(GENERIC);
    expect(view.container.textContent).not.toContain('HTTP');
    expect(view.container.textContent).not.toContain('FORBIDDEN');
    expect(view.container.textContent).not.toContain(PRIVATE);
  });

  it('preserves fixed validation copy and the real accessible retry action', async () => {
    const retry = vi.fn();
    const message = '업무 ID는 유효한 UUID여야 해요.';
    render(<ErrorNotice error={new Error(message)} retry={retry} />);
    expect(screen.getByRole('alert')).toHaveTextContent(message);
    const button = screen.getByRole('button', { name: '다시 조회' });
    expect(button).toHaveAccessibleDescription(message);
    await userEvent.tab();
    expect(button).toHaveFocus();
    await userEvent.keyboard('{Enter}');
    expect(retry).toHaveBeenCalledTimes(1);
  });
});
