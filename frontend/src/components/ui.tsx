import { useEffect, useRef, type ReactNode } from 'react';
import { ApiError } from '../api';
import { errorMessage, formatValue, REASON_LABELS, STATE_LABELS, text } from '../format';
import type { Row } from '../types';
import type { useCommand } from '../hooks';

export function Icon({
  name,
  size = 20,
}: {
  name: 'shield' | 'grid' | 'search' | 'flask' | 'arrow' | 'refresh' | 'close' | 'check' | 'lock';
  size?: number;
}) {
  const paths = {
    shield: (
      <>
        <path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6z" />
        <path d="m8 12 3 3 5-6" />
      </>
    ),
    grid: (
      <>
        <rect x="3" y="3" width="7" height="7" rx="1.5" />
        <rect x="14" y="3" width="7" height="7" rx="1.5" />
        <rect x="3" y="14" width="7" height="7" rx="1.5" />
        <rect x="14" y="14" width="7" height="7" rx="1.5" />
      </>
    ),
    search: (
      <>
        <circle cx="10" cy="10" r="6.5" />
        <path d="m15 15 6 6" />
      </>
    ),
    flask: (
      <>
        <path d="M8 3h8M9 3v7l-6 9a1.4 1.4 0 0 0 1.2 2h15.6a1.4 1.4 0 0 0 1.2-2l-6-9V3M6 15h12" />
      </>
    ),
    arrow: <path d="M4 12h16m-6-6 6 6-6 6" />,
    refresh: (
      <>
        <path d="M20 7v5h-5M4 17v-5h5" />
        <path d="M6 6a8 8 0 0 1 14 6M4 12a8 8 0 0 0 14 6" />
      </>
    ),
    close: <path d="m6 6 12 12M6 18 18 6" />,
    check: <path d="m4 12 5 5L20 6" />,
    lock: (
      <>
        <rect x="5" y="10" width="14" height="11" rx="2" />
        <path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2" />
      </>
    ),
  };
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {paths[name]}
    </svg>
  );
}
export function Status({ state }: { state: unknown }) {
  const name = formatValue(state);
  const style = ['PAID', 'VALIDATED', 'SUCCEEDED', 'ALLOW', 'CONSUMED', 'COMMITTED'].includes(name)
    ? 'green'
    : ['BLOCKED', 'DENY', 'INVALIDATED', 'REVOKED', 'FAILED', 'ERROR'].includes(name)
      ? 'red'
      : ['WAIT_APPROVAL', 'ON_HOLD', 'PENDING', 'RESERVED', 'APPROVAL_REQUIRED'].includes(name)
        ? 'amber'
        : 'neutral';
  return (
    <span className={`status ${style}`} title={name}>
      <span className="status-dot" />
      {STATE_LABELS[name] || name}
    </span>
  );
}
export function ErrorNotice({ error, retry }: { error: unknown; retry?: () => void }) {
  if (!error) return null;
  return (
    <div className="notice error" role="alert">
      <div>
        <strong>{errorMessage(error)}</strong>
        {error instanceof ApiError && (
          <div className="reason-codes">
            {error.status > 0 && <span>HTTP {error.status}</span>}
            {error.reasonCodes.map((code) => (
              <span key={code}>{code}</span>
            ))}
          </div>
        )}
      </div>
      {retry && (
        <button className="button small secondary" onClick={retry}>
          다시 조회
        </button>
      )}
    </div>
  );
}
export function Reason({ codes = [] }: { codes?: string[] }) {
  if (!codes.length) return <span className="muted">서버가 제공한 사유 없음</span>;
  return (
    <div className="reasons">
      {codes.map((code) => (
        <div key={code}>
          <p>{REASON_LABELS[code] || '상세 사유는 서버 기록에서 확인해 주세요.'}</p>
          <span className="code">{code}</span>
        </div>
      ))}
    </div>
  );
}
export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <span className="empty-icon">
        <Icon name="search" size={23} />
      </span>
      <strong>{title}</strong>
      {children && <p>{children}</p>}
    </div>
  );
}
export function Loading() {
  return (
    <div className="loading" role="status">
      <span className="spinner" />
      서버 기록을 확인하고 있어요
    </div>
  );
}
export function Panel({
  title,
  kicker,
  children,
  action,
  className = '',
}: {
  title: string;
  kicker?: string;
  children: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-heading">
        <div>
          {kicker && <span className="eyebrow">{kicker}</span>}
          <h2>{title}</h2>
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}
export function KeyValues({ items }: { items: Array<[string, ReactNode]> }) {
  return (
    <dl className="key-values">
      {items.map(([label, content]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd>{content ?? '미제공'}</dd>
        </div>
      ))}
    </dl>
  );
}
export function Stat({
  label,
  value,
  detail,
  accent = false,
}: {
  label: string;
  value: ReactNode;
  detail?: string;
  accent?: boolean;
}) {
  return (
    <div className={`stat ${accent ? 'accent' : ''}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      {detail && <small>{detail}</small>}
    </div>
  );
}
export function RecordTable({
  rows = [],
  columns,
  empty = '아직 기록이 없어요',
  rowDetails = false,
}: {
  rows?: Row[];
  columns: Array<{ label: string; key: string; render?: (row: Row) => ReactNode }>;
  empty?: string;
  rowDetails?: boolean;
}) {
  if (!rows.length) return <Empty title={empty} />;
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key} scope="col">
                {column.label}
              </th>
            ))}
            {rowDetails && <th scope="col">원시 기록</th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={text(row, 'id', 'runId', 'resultId', 'eventId') + index}>
              {columns.map((column) => (
                <td key={column.key}>{column.render ? column.render(row) : text(row, column.key)}</td>
              ))}
              {rowDetails && (
                <td>
                  <details className="record-details">
                    <summary>보기</summary>
                    <Json value={row} />
                  </details>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
function redact(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => !/(token|secret|password|macBytes|macBase64Url|signingKey|leaseToken)/i.test(key))
        .map(([key, item]) => [key, redact(item)]),
    );
  return value;
}
export function Json({ value }: { value: unknown }) {
  return <pre className="json">{JSON.stringify(redact(value), null, 2)}</pre>;
}
export function CommandFeedback({ command }: { command: ReturnType<typeof useCommand> }) {
  return (
    <>
      {command.pending && <Loading />}
      <ErrorNotice error={command.error} />
      {command.retryable && (
        <div className="notice warning">
          <p>처리 결과를 아직 알 수 없어요. 입력을 바꾸지 않고 같은 요청 번호로 재확인합니다.</p>
          <button
            className="button secondary"
            disabled={command.pending}
            onClick={() => void command.retry()}
          >
            같은 요청 다시 확인
          </button>
        </div>
      )}
      {command.result && (
        <div
          className={`notice ${command.result.decision === 'DENY' || command.result.decision === 'ERROR' ? 'error' : 'info'}`}
          role="status"
        >
          <div>
            <strong>
              {command.result.replayed
                ? '이전에 접수한 요청의 결과예요.'
                : command.result.message || '서버가 요청을 처리했어요.'}
            </strong>
            <p>
              처리 상태: {STATE_LABELS[command.result.state] || command.result.state} · 판단:{' '}
              {command.result.decision}
            </p>
            {command.result.reasonCodes?.length > 0 && <Reason codes={command.result.reasonCodes} />}
            <small>요청 번호 {command.result.requestId}</small>
          </div>
        </div>
      )}
    </>
  );
}
export function Modal({
  title,
  children,
  onClose,
  busy = false,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  busy?: boolean;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    return () => element?.close();
  }, []);
  return (
    <dialog
      ref={dialog}
      className="modal"
      aria-label={title}
      onCancel={(e) => {
        e.preventDefault();
        if (!busy) onClose();
      }}
    >
      <div className="modal-heading">
        <h2>{title}</h2>
        <button className="icon-button" type="button" aria-label="닫기" onClick={onClose} disabled={busy}>
          <Icon name="close" />
        </button>
      </div>
      {children}
    </dialog>
  );
}
