import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { FormEvent } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { CommandFeedback, ErrorNotice, Modal } from './components/ui';
import type { useCommand } from './hooks';

const ID = '00000000-0000-4000-8000-000000000801';
function commandState(overrides: Partial<ReturnType<typeof useCommand>> = {}): ReturnType<typeof useCommand> {
  return {
    pending: false, error: undefined, result: undefined, retryable: true,
    retryRequest: { path: '/experiments', actionId: ID,
      body: { fixtureSetId: 'synthetic-accessibility', modelMode: 'LIVE', mode: 'PAIRED', repeatCount: 1 } },
    run: vi.fn(), retry: vi.fn(), reset: vi.fn(), ...overrides,
  };
}

describe('shared action keyboard and accessible descriptions', () => {
  it('associates the real uncertain retry button with first-execution and LIVE-cost warnings', async () => {
    const retry = vi.fn();
    const submit = vi.fn((event: FormEvent) => event.preventDefault());
    render(<form onSubmit={submit}><CommandFeedback command={commandState({ retry })} /></form>);
    const button = screen.getByRole('button', { name: '같은 요청 다시 확인' });
    expect(button).toHaveAccessibleDescription(
      '첫 요청이 서버에 도착하지 않았다면 이번 재확인으로 처음 접수·실행될 수 있어요. 원래 LIVE 실행 요청입니다. 등록된 사례의 외부 모델 전송과 비용이 발생할 수 있어요.',
    );
    await userEvent.tab();
    expect(button).toHaveFocus();
    await userEvent.keyboard('{Enter}');
    expect(retry).toHaveBeenCalledTimes(1);
    expect(submit).not.toHaveBeenCalled();
  });

  it('keeps a pending retry natively disabled with its consequence description available', async () => {
    const retry = vi.fn();
    render(<CommandFeedback command={commandState({ pending: true, retry })} />);
    const button = screen.getByRole('button', { name: '같은 요청 다시 확인' });
    expect(button).toBeDisabled();
    expect(button).toHaveAccessibleDescription(/처음 접수·실행될 수 있어요/);
    expect(screen.getByRole('status')).toHaveTextContent('서버 기록을 확인하고 있어요');
    await userEvent.click(button);
    expect(retry).not.toHaveBeenCalled();
  });

  it('does not describe REPLAY recovery as a LIVE transfer or paid call', () => {
    render(<CommandFeedback command={commandState({ retryRequest: {
      path: '/experiments', actionId: ID, body: { modelMode: 'REPLAY' },
    } })} />);
    expect(screen.getByRole('button', { name: '같은 요청 다시 확인' })).toHaveAccessibleDescription(
      '첫 요청이 서버에 도착하지 않았다면 이번 재확인으로 처음 접수·실행될 수 있어요.',
    );
    expect(screen.queryByText(/원래 LIVE 실행 요청입니다/)).not.toBeInTheDocument();
  });

  it('names each error retry by the error it retries and never implicitly submits a parent form', async () => {
    const retry = vi.fn();
    const submit = vi.fn((event: FormEvent) => event.preventDefault());
    render(<form onSubmit={submit}>
      <ErrorNotice error={new Error('업무 ID는 유효한 UUID여야 해요.')} retry={retry} />
      <ErrorNotice error={new Error('격리 사건 ID는 유효한 UUID여야 해요.')} retry={vi.fn()} />
    </form>);
    const [workflowRetry, impactRetry] = screen.getAllByRole('button', { name: '다시 조회' });
    expect(workflowRetry).toHaveAccessibleDescription('업무 ID는 유효한 UUID여야 해요.');
    expect(impactRetry).toHaveAccessibleDescription('격리 사건 ID는 유효한 UUID여야 해요.');
    await userEvent.tab();
    expect(workflowRetry).toHaveFocus();
    await userEvent.keyboard('{Enter}');
    expect(retry).toHaveBeenCalledTimes(1);
    expect(submit).not.toHaveBeenCalled();
  });

  it('exposes modal busy state and preserves named read-only data while close/action controls are disabled', async () => {
    const close = vi.fn();
    const content = (busy: boolean) => <Modal title="합성 보안 작업 검토" busy={busy} onClose={close}>
      <label htmlFor="synthetic-review-id">검토 식별자</label>
      <input id="synthetic-review-id" readOnly value={ID} />
      <button type="button" disabled={busy}>확인한 작업 요청</button>
    </Modal>;
    const view = render(content(true));
    const dialog = screen.getByRole('dialog', { name: '합성 보안 작업 검토' });
    expect(dialog).toHaveAttribute('aria-busy', 'true');
    const readOnly = screen.getByRole('textbox', { name: '검토 식별자' });
    expect(readOnly).toHaveAttribute('readonly');
    await userEvent.click(readOnly);
    await userEvent.keyboard('changed');
    expect(readOnly).toHaveValue(ID);
    expect(screen.getByRole('button', { name: '확인한 작업 요청' })).toBeDisabled();
    const closeButton = screen.getByRole('button', { name: '닫기' });
    expect(closeButton).toBeDisabled();
    await userEvent.click(closeButton);
    fireEvent(dialog, new Event('cancel', { bubbles: true, cancelable: true }));
    expect(close).not.toHaveBeenCalled();
    view.rerender(content(false));
    expect(dialog).toHaveAttribute('aria-busy', 'false');
    fireEvent(dialog, new Event('cancel', { bubbles: true, cancelable: true }));
    expect(close).toHaveBeenCalledTimes(1);
  });
});
