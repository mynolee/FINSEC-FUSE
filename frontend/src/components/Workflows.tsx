import { useCallback, useState, type FormEvent } from 'react';
import { ApiError, FuseApi } from '../api';
import { navigate } from '../App';
import { currency, formatValue, isUuid, shortId, STATE_LABELS, text, time, value } from '../format';
import { DISPLAY_MAX_ITEMS, displayRows, displayScalar, ownData, projectDisplay } from '../displayProjection';
import { useCommand, useQuery } from '../hooks';
import type { Row, Trace, Workflow } from '../types';
import {
  CommandFeedback,
  Empty,
  ErrorNotice,
  Icon,
  isCommandUuid,
  Json,
  KeyValues,
  Loading,
  Modal,
  Panel,
  Reason,
  RecordTable,
  Stat,
  Status,
} from './ui';

export function WorkflowPage({ api, id }: { api: FuseApi; id?: string }) {
  return id ? <WorkflowDetail key={id} api={api} id={id} /> : <WorkflowList api={api} />;
}
function WorkflowList({ api }: { api: FuseApi }) {
  const [filter, setFilter] = useState('');
  const [page, setPage] = useState(0);
  const [poll, setPoll] = useState(true);
  const [create, setCreate] = useState(false);
  const load = useCallback((signal: AbortSignal) => api.workflows(filter, page, signal), [api, filter, page]);
  const query = useQuery(load, true, poll ? 5000 : 0);
  const items = query.data?.items ?? [];
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">WORKFLOW OPERATIONS</span>
          <h1>업무 모니터</h1>
          <p>각 판단이 어떤 증거와 권한으로 이어졌는지 확인하세요.</p>
        </div>
        <button className="button primary" onClick={() => setCreate(true)}>
          + 등록 신청 시작
        </button>
      </div>
      <div className="stats-grid">
        <Stat
          label="조회 조건에 해당하는 업무"
          value={query.data?.total ?? '—'}
          detail="서버의 접근 가능한 범위"
        />
        <Stat
          label="현재 페이지 · 승인 대기"
          value={query.data ? items.filter((item) => item.state === 'WAIT_APPROVAL').length : '—'}
          detail="직원의 독립적인 확인 필요"
          accent
        />
        <Stat
          label="현재 페이지 · 정책 차단"
          value={query.data ? items.filter((item) => item.state === 'BLOCKED').length : '—'}
          detail="보류 · 업무 거절과 별도"
        />
        <Stat
          label="현재 페이지 · Mock 지급 완료"
          value={query.data ? items.filter((item) => item.state === 'PAID').length : '—'}
          detail="서버 상태가 PAID인 업무"
        />
      </div>
      <ErrorNotice error={query.error} retry={query.reload} />
      <Panel
        title="업무 목록"
        kicker="CURRENT WORKFLOWS"
        action={
          <div className="table-controls">
            <label className="switch-label">
              <input type="checkbox" checked={poll} onChange={(e) => setPoll(e.target.checked)} />
              5초 자동 조회
            </label>
            <button
              className="icon-button"
              aria-label="업무 목록 새로고침"
              disabled={query.loading}
              onClick={query.reload}
            >
              <Icon name="refresh" />
            </button>
          </div>
        }
      >
        <div className="filter-bar">
          <label htmlFor="state-filter">업무 상태</label>
          <select
            id="state-filter"
            value={filter}
            onChange={(e) => {
              setFilter(e.target.value);
              setPage(0);
            }}
          >
            <option value="">모든 상태</option>
            {Object.entries(STATE_LABELS).map(([key, label]) => (
              <option key={key} value={key}>
                {label}
              </option>
            ))}
          </select>
          <span className="updated-at">
            {query.error && query.data ? '마지막 성공 조회 기록 · ' : ''}
            {query.updatedAt
              ? `${query.updatedAt.toLocaleTimeString('ko-KR', { timeZone: 'UTC' })} UTC 확인`
              : '아직 조회하지 못했어요'}
          </span>
        </div>
        {query.loading && !query.data ? (
          <Loading />
        ) : !query.data && query.error ? (
          <Empty title="실시간 업무를 불러오지 못했어요">연결 오류를 해결한 뒤 다시 조회하세요.</Empty>
        ) : !items.length ? (
          <Empty title="표시할 업무가 없어요">조건을 바꾸거나 서버에 등록된 신청서를 시작하세요.</Empty>
        ) : (
          <div className="table-scroll">
            <table className="workflow-table">
              <thead>
                <tr>
                  <th scope="col">고객 · 신청서</th>
                  <th scope="col">신청 금액</th>
                  <th scope="col">현재 상태</th>
                  <th scope="col">위험 점수</th>
                  <th scope="col">마지막 사유</th>
                  <th scope="col">
                    <span className="sr-only">상세 보기</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.workflowId}>
                    <td>
                      <a className="row-title" href={`#/workflows/${item.workflowId}`}>
                        {item.customerAlias || item.customerId || shortId(item.workflowId)}
                      </a>
                      <small>{item.businessReference || shortId(item.workflowId)}</small>
                    </td>
                    <td className="number">{currency(item.amountKrw)}</td>
                    <td>
                      <Status state={item.state} />
                    </td>
                    <td>
                      <div className="risk-inline">
                        <b>{item.usedRisk}</b>
                        <span>사용</span>
                        <b>{item.reservedRisk}</b>
                        <span>예약</span>
                      </div>
                      <small>현재 유효 한도 {item.riskLimit}</small>
                    </td>
                    <td>
                      <span className="code">{item.reasonCodes?.join(' · ') || '—'}</span>
                    </td>
                    <td>
                      <a
                        className="table-link"
                        href={`#/workflows/${item.workflowId}`}
                        aria-label={`${item.customerAlias || item.customerId || item.workflowId} 업무 상세`}
                      >
                        <Icon name="arrow" size={17} />
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="pagination">
          <span>
            {query.data
              ? `${query.data.total}건 중 ${page * 20 + (items.length ? 1 : 0)}–${page * 20 + items.length}건`
              : '조회 결과 없음'}
          </span>
          <div>
            <button
              className="button small secondary"
              disabled={page === 0 || query.loading}
              onClick={() => setPage((n) => n - 1)}
            >
              이전
            </button>
            <span>{page + 1} 페이지</span>
            <button
              className="button small secondary"
              disabled={!query.data || (page + 1) * 20 >= query.data.total || query.loading}
              onClick={() => setPage((n) => n + 1)}
            >
              다음
            </button>
          </div>
        </div>
      </Panel>
      <div className="footnote">
        <Icon name="shield" size={17} />
        <p>자동 한도를 넘으면 승인을 기다려요. 예산 초과를 공격으로 판단하거나 격리하지 않습니다.</p>
      </div>
      {create && (
        <CreateWorkflow
          api={api}
          onClose={() => setCreate(false)}
          onCreated={(id) => {
            setCreate(false);
            query.reload();
            navigate('workflows', id);
          }}
        />
      )}
    </>
  );
}
function CreateWorkflow({
  api,
  onClose,
  onCreated,
}: {
  api: FuseApi;
  onClose: () => void;
  onCreated: (id: string) => void;
}) {
  const [customerId, setCustomer] = useState('customer-102');
  const [businessReference, setReference] = useState('APP-DEMO-102-001');
  const [amount, setAmount] = useState('1000000');
  const [account, setAccount] = useState('00000000-0000-4000-8000-000000000102');
  const [validationError, setValidationError] = useState('');
  const command = useCommand(api, (result) => {
    if (result.workflowId && result.decision !== 'DENY' && result.decision !== 'ERROR')
      onCreated(result.workflowId);
  }, '/workflows');
  function choose(id: string) {
    setCustomer(`customer-${id}`);
    setReference(`APP-DEMO-${id}-001`);
    setAmount('1000000');
    setAccount(`00000000-0000-4000-8000-000000000${id}`);
    command.reset();
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (command.pending || command.retryable || !event.currentTarget.checkValidity()) return;
    const amountKrw = Number(amount);
    if (!businessReference.trim() || businessReference.length > 80 || !customerId.trim() || customerId.length > 64 ||
      !isCommandUuid(account) || !Number.isSafeInteger(amountKrw) || amountKrw < 1 || amountKrw > 50000000) {
      setValidationError('고객·등록 신청·계좌와 1~50,000,000원의 정수 금액을 확인하세요.');
      return;
    }
    setValidationError('');
    void command.run('/workflows', {
      businessReference,
      customerId,
      amountKrw,
      payoutAccountId: account,
    });
  }
  return (
    <Modal title="등록된 대출 신청 시작" onClose={onClose} busy={command.pending}>
      <p className="muted">
        서버의 Mock 신청 registry와 고객·금액·계좌가 모두 일치해야 해요. 같은 신청서를 다시 보내도 새 예산을
        만들지 않습니다.
      </p>
      <form onSubmit={submit}>
        <fieldset disabled={command.pending || command.retryable}>
          <label htmlFor="demo-application">기본 데모 입력 선택</label>
          <select id="demo-application" defaultValue="102" onChange={(e) => choose(e.target.value)}>
            <option value="102">customer-102 · 정상 자료</option>
            <option value="101">customer-101 · 자료 없는 공격 재생</option>
            <option value="103">customer-103 · Mock 대출 한도 부적격</option>
            <option value="104">customer-104 · FACE_MATCH 실패</option>
          </select>
          <div className="field-grid">
            <div>
              <label htmlFor="reference">등록 신청 번호</label>
              <input
                id="reference"
                value={businessReference}
                onChange={(e) => setReference(e.target.value)}
                required
                maxLength={80}
              />
            </div>
            <div>
              <label htmlFor="customer">고객 ID</label>
              <input
                id="customer"
                value={customerId}
                onChange={(e) => setCustomer(e.target.value)}
                required
                maxLength={64}
              />
            </div>
            <div>
              <label htmlFor="amount">금액 (원)</label>
              <input
                id="amount"
                type="number"
                min={1}
                max={50000000}
                step={1}
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                required
              />
            </div>
            <div>
              <label htmlFor="account">고객 소유 Mock 계좌 UUID</label>
              <input
                id="account"
                value={account}
                onChange={(e) => setAccount(e.target.value)}
                required
                pattern="[0-9a-fA-F-]{36}"
              />
            </div>
          </div>
          <div className="notice info">
            이 화면의 예시 입력은 조회 결과가 아닙니다. 접수 후 서버 기록으로 진행 상태를 확인해요.
          </div>
          <div className="form-actions">
            <button type="button" className="button secondary" onClick={onClose}>
              취소
            </button>
            <button className="button primary" type="submit">
              신청 접수
            </button>
          </div>
        </fieldset>
      </form>
      {validationError && <ErrorNotice error={new Error(validationError)} />}
      <CommandFeedback command={command} />
    </Modal>
  );
}
function WorkflowDetail({ api, id }: { api: FuseApi; id: string }) {
  const [tab, setTab] = useState('trace');
  const [modal, setModal] = useState<'approval' | 'resume'>();
  const load = useCallback((signal: AbortSignal) => api.workflow(id, signal), [api, id]);
  const traceLoad = useCallback((signal: AbortSignal) => api.trace(id, signal), [api, id]);
  const query = useQuery(load, isUuid(id), 5000);
  const traceQuery = useQuery(traceLoad, isUuid(id), 5000);
  const workflow = query.data;
  const hasCommandIdentity = !!workflow && isCommandUuid(workflow.workflowId);
  const resumeCapability = ownData(workflow, 'resumeCapability');
  const publicResumeAvailable = workflow?.canResume === true && resumeCapability === 'LEGACY_HTTP';
  const trace = traceQuery.data;
  const refresh = () => {
    query.reload();
    traceQuery.reload();
  };
  if (!isUuid(id)) return <ErrorNotice error={new Error('업무 ID는 유효한 UUID여야 해요.')} />;
  return (
    <>
      <a className="back-link" href="#/workflows">
        ← 업무 목록
      </a>
      <div className="page-heading">
        <div>
          <span className="eyebrow">WORKFLOW DETAIL</span>
          <h1>{workflow?.customerAlias || workflow?.customerId || '업무 상세'}</h1>
          <p className="id-line">{workflow?.businessReference || id}</p>
        </div>
        <div className="heading-actions">
          {workflow && <Status state={workflow.state} />}
          <button
            className="icon-button"
            aria-label="업무 상세 새로고침"
            onClick={refresh}
            disabled={query.loading}
          >
            <Icon name="refresh" />
          </button>
        </div>
      </div>
      <ErrorNotice error={query.error} retry={refresh} />
      {query.loading && !workflow && <Loading />}
      {workflow && (
        <>
          <div className="detail-summary">
            <div className="summary-main">
              <span className="eyebrow">현재 서버 판단</span>
              <Reason codes={workflow.reasonCodes} />
              {workflow.state === 'PAID' && (
                <div className="paid-note">
                  <Icon name="check" />
                  Mock 지급 완료. 사후 격리는 지급을 되돌리지 않습니다.
                </div>
              )}
              <div className="summary-actions">
                {workflow.canApprove && (
                  <button
                    className="button primary"
                    onClick={() => setModal('approval')}
                    disabled={!!query.error || !hasCommandIdentity}
                  >
                    정확한 승인 내용 확인 <Icon name="arrow" size={16} />
                  </button>
                )}
                {publicResumeAvailable && (
                  <button
                    className="button secondary"
                    onClick={() => setModal('resume')}
                    disabled={!!query.error || !hasCommandIdentity}
                  >
                    새 회차로 명시적 재개
                  </button>
                )}
                {workflow.canResume === true && !publicResumeAvailable && (
                  <small>{resumeCapability === 'TYPED_READINESS_ONLY'
                    ? '다음 세대 재개 조건은 충족됐지만 이 화면의 재개 명령은 지원되지 않습니다.'
                    : '재개 명령 지원 여부가 확인되지 않았습니다.'}</small>
                )}
                {!workflow.canApprove && !workflow.canResume && (
                  <small>현재 상태와 인증 주체에 대해 서버가 허용한 변경 작업이 없어요.</small>
                )}
              </div>
            </div>
            <div className="summary-facts">
              <KeyValues
                items={[
                  ['신청 금액', currency(workflow.amountKrw)],
                  ['지급 계좌', workflow.payoutAccountId || '미제공'],
                  ['현재 회차', `${workflow.generation}회차`],
                  [
                    '진행 중 작업',
                    workflow.activeJob ? `${workflow.activeJob.phase} · ${workflow.activeJob.state}` : '없음',
                  ],
                ]}
              />
            </div>
          </div>
          <div className="stats-grid risk-summary">
            <Stat label="사용한 위험 점수" value={workflow.usedRisk} detail="CHARGE + CONSUME" />
            <Stat label="예약한 위험 점수" value={workflow.reservedRisk} detail="지급 성공 전 잡아 둔 점수" />
            <Stat
              label="현재 유효 한도"
              value={workflow.riskLimit}
              detail={
                workflow.state === 'PAID'
                  ? `지급 당시 승인 한도 ${workflow.historicalApprovedRiskLimit ?? '미제공'} · 현재 지급 권한 없음`
                  : '현재 정확한 승인에 따라 재계산'
              }
              accent
            />
            <Stat
              label="활성 격리"
              value={workflow.activeQuarantines?.length ?? '미제공'}
              detail="해제와 업무 재개는 별도 행동"
            />
          </div>
          {!!workflow.activeQuarantines?.length && (
            <div className="notice warning">
              <div>
                <strong>관계있는 활성 격리가 있어요.</strong>
                <div className="quarantine-links">
                  {displayRows(workflow.activeQuarantines).map((item, index) => {
                    const quarantineId =
                      typeof item === 'string' ? item : ownData(item, 'quarantineId') ?? ownData(item, 'id');
                    return typeof quarantineId === 'string' && isUuid(quarantineId) ? (
                      <a key={quarantineId} href={`#/quarantine/${quarantineId}`}>
                        {typeof item === 'object' ? `${displayScalar(ownData(item, 'scope')) ?? '미제공'} · ` : ''}
                        {shortId(quarantineId)} 조사 →
                      </a>
                    ) : (
                      <span key={index}>격리 식별자 미제공</span>
                    );
                  })}
                  {workflow.activeQuarantines.length > DISPLAY_MAX_ITEMS && <span>추가 격리 기록 표시 생략</span>}
                </div>
              </div>
            </div>
          )}
          <div className="tabs" role="tablist" aria-label="업무 상세 구역">
            {[
              ['trace', '실행 · 증거'],
              ['authority', '권한 · 위험 장부'],
              ['graph', '실제 의존 관계'],
              ['timeline', '감사 시간선'],
            ].map(([key, label]) => (
              <button
                type="button"
                role="tab"
                tabIndex={tab === key ? 0 : -1}
                onKeyDown={(event) => {
                  const keys = ['trace', 'authority', 'graph', 'timeline'];
                  const current = keys.indexOf(key);
                  const next =
                    event.key === 'ArrowRight'
                      ? keys[(current + 1) % keys.length]
                      : event.key === 'ArrowLeft'
                        ? keys[(current + keys.length - 1) % keys.length]
                        : event.key === 'Home'
                          ? keys[0]
                          : event.key === 'End'
                            ? keys[keys.length - 1]
                            : null;
                  if (next) {
                    event.preventDefault();
                    setTab(next);
                    document.getElementById(`tab-${next}`)?.focus();
                  }
                }}
                aria-selected={tab === key}
                aria-controls={`panel-${key}`}
                id={`tab-${key}`}
                className={tab === key ? 'active' : ''}
                key={key}
                onClick={() => setTab(key)}
              >
                {label}
              </button>
            ))}
          </div>
          {traceQuery.error instanceof ApiError && traceQuery.error.status === 403 ? (
            <div className="notice info">
              상세 실행·승인·조사 기록은 담당 직원 또는 보안 관리자에게만 공개됩니다.
            </div>
          ) : (
            <ErrorNotice error={traceQuery.error} retry={traceQuery.reload} />
          )}
          {traceQuery.loading && !trace && <Loading />}
          {trace && (
            <div id={`panel-${tab}`} role="tabpanel" aria-labelledby={`tab-${tab}`}>
              {!!traceQuery.error && (
                <div className="notice warning">
                  다음 기록은 마지막 성공 조회 결과예요. 현재 상태와 다를 수 있습니다.
                </div>
              )}
              {tab === 'trace' && <TracePanel trace={trace} />}
              {tab === 'authority' && <AuthorityPanel trace={trace} />}
              {tab === 'graph' && <GraphPanel trace={trace} />}
              {tab === 'timeline' && <Timeline trace={trace} />}
            </div>
          )}
          <div className="footnote">
            <p>
              업무 UUID {id} · 5초마다 서버 재조회 ·{' '}
              {query.updatedAt
                ? `${query.updatedAt.toLocaleTimeString('ko-KR', { timeZone: 'UTC' })} UTC 확인`
                : '조회 중'}
            </p>
          </div>
          {modal === 'approval' && (
            <Approval api={api} workflow={workflow} onClose={() => setModal(undefined)} onDone={refresh} />
          )}
          {modal === 'resume' && (
            <Resume api={api} workflow={workflow} onClose={() => setModal(undefined)} onDone={refresh} />
          )}
        </>
      )}
    </>
  );
}
function TracePanel({ trace }: { trace: Trace }) {
  return (
    <div className="panel-stack">
      <Panel title="실행과 제안 · 검증 결과" kicker="OBSERVED RUNS">
        <p className="panel-description">
          AI의 VERIFIED 제안과 서버의 VALIDATED 상태는 별개예요. 이전 회차도 조사 이력으로 남습니다.
        </p>
        <RecordTable
          rows={trace.runs}
          rowDetails="run"
          columns={[
            {
              label: '실행 ID',
              key: 'runId',
              render: (row) => (
                <span className="code" title={text(row, 'runId', 'id')}>
                  {shortId(value(row, 'runId', 'id'))}
                </span>
              ),
            },
            { label: '역할', key: 'role' },
            { label: '회차', key: 'generation' },
            {
              label: '상태',
              key: 'status',
              render: (row) => <Status state={value(row, 'status', 'state')} />,
            },
            { label: '실제 시작', key: 'startedAt', render: (row) => time(row.startedAt) },
          ]}
        />
        <h3 className="subheading">보존된 후보 및 결과</h3>
        <RecordTable
          rows={trace.results}
          rowDetails="result"
          columns={[
            { label: '결과 ID', key: 'resultId', render: (row) => shortId(value(row, 'resultId', 'id')) },
            { label: '실행 ID', key: 'runId', render: (row) => shortId(row.runId) },
            {
              label: '서버 결과 상태',
              key: 'status',
              render: (row) => <Status state={value(row, 'status', 'state')} />,
            },
            {
              label: '후보 제안',
              key: 'proposal',
              render: (row) => {
                const body = value(row, 'body', 'bodyJson', 'proposal');
                return body ? <Json value={body} profile="candidate" /> : '표시용 기록 참고';
              },
            },
            {
              label: '결과 지문',
              key: 'resultHash',
              render: (row) => (
                <span className="code" title={text(row, 'resultHash')}>
                  {shortId(row.resultHash)}
                </span>
              ),
            },
          ]}
        />
      </Panel>
      <div className="two-columns">
        <Panel title="독립 확인 자료" kicker="TRUSTED EVIDENCE">
          <p className="panel-description">
            실제 제공한 자료입니다. 시간 상태는 서버 조회 기준 시각의 발급·만료 구간만 나타내요. 기한 내여도
            전체 검증 통과나 사용·승인 가능을 뜻하지 않습니다. 철회 여부는 저장 상태에서 확인하고, 전체
            유효성과 권한은 승인과 지급 시 서버가 다시 검사해요.
          </p>
          <KeyValues items={[['서버 조회 기준 시각 (UTC)', time(trace.evidenceCheckedAt)]]} />
          <RecordTable
            rows={trace.evidenceUses}
            rowDetails="evidence"
            columns={[
              { label: '자료 ID', key: 'evidenceId', render: (row) => shortId(row.evidenceId) },
              { label: '종류', key: 'evidenceType', render: (row) => text(row, 'evidenceType', 'kind') },
              { label: '결과', key: 'outcome', render: (row) => text(row, 'outcome', 'result') },
              { label: '저장 상태', key: 'status' },
              {
                label: '시간 상태',
                key: 'temporalStatus',
                render: (row) =>
                  row.temporalStatus === 'NOT_YET_ISSUED'
                    ? '발급 전'
                    : row.temporalStatus === 'WITHIN_PERIOD'
                      ? '기한 내'
                      : row.temporalStatus === 'EXPIRED'
                        ? '기한 경과'
                        : '미제공',
              },
              { label: '발급 (UTC)', key: 'issuedAt', render: (row) => time(row.issuedAt) },
              { label: '만료 (UTC)', key: 'expiresAt', render: (row) => time(row.expiresAt) },
            ]}
          />
        </Panel>
        <Panel title="실제로 전달한 문서" kicker="RECORDED SOURCE USE">
          <p className="panel-description">AI의 인용 주장 대신, Spring Retriever가 저장한 출처를 표시해요.</p>
          <RecordTable
            rows={trace.sourceUses}
            rowDetails="source"
            columns={[
              { label: '문서', key: 'documentId', render: (row) => shortId(row.documentId) },
              { label: '버전', key: 'documentVersion' },
              {
                label: '내용 지문',
                key: 'contentHash',
                render: (row) => (
                  <span className="code" title={text(row, 'contentHash')}>
                    {shortId(row.contentHash)}
                  </span>
                ),
              },
              { label: '실행', key: 'runId', render: (row) => shortId(row.runId) },
            ]}
          />
        </Panel>
      </div>
    </div>
  );
}
export function GrantRecords({ rows }: { rows: unknown }) {
  const grants = displayRows(rows).map(row => projectDisplay(row, 'grant'));
  const length = ownData(rows, 'length');
  const truncated = typeof length === 'number' && length > DISPLAY_MAX_ITEMS;
  return <>{truncated ? <p className="muted">앞 {DISPLAY_MAX_ITEMS}개 기록만 표시합니다. 나머지는 표시에서 생략했습니다.</p> : null}<RecordTable rows={grants} rowDetails="grant" columns={[
    { label: '봉투 ID', key: 'grantId', render: row => shortId(row.grantId) },
    { label: '대상 실행 ID', key: 'targetRunId', render: row => shortId(row.targetRunId) },
    { label: '세대', key: 'generation' },
    { label: '허용 행동', key: 'action', render: row => <span className="code">{text(row, 'action')}</span> },
    { label: '저장 상태', key: 'status', render: row => <Status state={row.status ?? row.state} /> },
  ]} /></>;
}
function AuthorityPanel({ trace }: { trace: Trace }) {
  return (
    <div className="panel-stack">
      <Panel title="전달 봉투의 허용 범위" kicker="DELEGATION GRANTS">
        <p className="panel-description">
          봉투 하나는 행동 하나만 허용합니다. 인증 키·MAC·lease token은 화면에 표시하지 않아요.
        </p>
        <GrantRecords rows={ownData(trace, 'grants')} />
      </Panel>
      <Panel title="위험 점수 장부" kicker="APPEND-ONLY RISK LEDGER">
        <p className="panel-description">
          RESERVE는 예약, CONSUME는 사용 전환입니다. 둘을 더해 사용 점수로 계산하지 않습니다.
        </p>
        <RecordTable
          rows={trace.riskEvents}
          rowDetails="risk"
          columns={[
            { label: '시각', key: 'createdAt', render: (row) => time(row.createdAt) },
            { label: '이벤트', key: 'eventType', render: (row) => <Status state={row.eventType} /> },
            { label: '단계', key: 'stage', render: (row) => text(row, 'stage', 'role') },
            { label: '점수', key: 'points' },
            { label: '실행', key: 'runId', render: (row) => shortId(row.runId) },
          ]}
        />
      </Panel>
      <Panel title="직원 승인 기록" kicker="EXACT REVIEW BINDING">
        <RecordTable
          rows={trace.approvals}
          rowDetails="approval"
          columns={[
            { label: '승인', key: 'approvalId', render: (row) => shortId(value(row, 'approvalId', 'id')) },
            { label: '상태', key: 'status', render: (row) => <Status state={row.status} /> },
            { label: '회차', key: 'generation' },
            { label: '금액', key: 'amountKrw', render: (row) => currency(row.amountKrw) },
            { label: '승인자', key: 'approverId', render: (row) => text(row, 'approverId', 'actorId') },
            { label: '만료', key: 'expiresAt', render: (row) => time(row.expiresAt) },
          ]}
        />
      </Panel>
      <Panel title="Mock 지급 영수증" kicker="COMMITTED PAYMENTS">
        <RecordTable
          rows={trace.payments}
          empty="이 업무의 실제 Mock 지급 기록이 없어요"
          rowDetails="payment"
          columns={[
            { label: '지급 ID', key: 'paymentId', render: (row) => shortId(value(row, 'paymentId', 'id')) },
            { label: '금액', key: 'amountKrw', render: (row) => currency(row.amountKrw) },
            { label: '계좌', key: 'payoutAccountId' },
            {
              label: '지급 시각',
              key: 'createdAt',
              render: (row) => time(value(row, 'paidAt', 'createdAt')),
            },
          ]}
        />
      </Panel>
    </div>
  );
}
function GraphPanel({ trace }: { trace: Trace }) {
  const runs = trace.runs ?? [];
  const actualRuns = runs.filter((run) => !!run.startedAt);
  return (
    <div className="panel-stack">
      <Panel title="실제 실행 관계" kicker="ACTUAL DEPENDENCIES">
        <div className="notice info">
          저장된 노드와 간선만 표시해요. QUEUED 준비 실행은 실제 시작 횟수에 포함하지 않습니다. 잠재 경로는
          격리 사건의 영향 조사에서 따로 확인하세요.
        </div>
        <div className="graph-stats">
          <Stat label="실제 시작한 실행 · 과거 포함" value={actualRuns.length} />
          <Stat label="실제 결과 사용 간선" value={trace.dependencies?.length ?? 0} />
          <Stat label="실제 Mock 지급" value={trace.payments?.length ?? '미제공'} />
        </div>
        <div className="run-nodes">
          {runs.map((run, index) => (
            <div
              className={`run-node ${run.startedAt ? 'actual' : ''}`}
              key={text(run, 'runId', 'id') + index}
            >
              <span className="eyebrow">{run.startedAt ? '실제 실행' : '준비 기록 · 실제 실행 아님'}</span>
              <h3>{text(run, 'role')}</h3>
              <Status state={value(run, 'status', 'state')} />
              <span className="code">{shortId(value(run, 'runId', 'id'))}</span>
              <small>{text(run, 'generation')}회차</small>
            </div>
          ))}
        </div>
        {!runs.length && <Empty title="기록된 실행 노드가 없어요" />}
        <h3 className="subheading">실제로 사용한 결과 연결</h3>
        <RecordTable
          rows={trace.dependencies}
          columns={[
            { label: '부모 실행', key: 'parentRunId', render: (row) => shortId(row.parentRunId) },
            { label: '→', key: 'edge', render: () => <Icon name="arrow" size={16} /> },
            { label: '후속 실행', key: 'childRunId', render: (row) => shortId(row.childRunId) },
            { label: '사용한 결과', key: 'parentResultId', render: (row) => shortId(row.parentResultId) },
            { label: '회차', key: 'generation' },
          ]}
        />
      </Panel>
      <Panel title="출처에서 지급까지의 기록" kicker="SOURCE · RESULT · WORKFLOW · PAYMENT">
        <p className="panel-description">연결 대상이 없는 후속 실행이나 지급을 임의로 생성하지 않습니다.</p>
        <RecordTable
          rows={(trace.sourceUses ?? [])
            .map((row) => ({
              node: '문서 버전 → 실행',
              from: `${shortId(row.documentId)} / v${row.documentVersion}`,
              to: shortId(row.runId),
            }))
            .concat(
              (trace.results ?? []).map((row) => ({
                node: '실행 → 결과',
                from: shortId(row.runId),
                to: shortId(value(row, 'resultId', 'id')),
              })),
              (trace.payments ?? []).map((row) => ({
                node: '업무 → Mock 지급',
                from: shortId(trace.workflowId),
                to: shortId(value(row, 'paymentId', 'id')),
              })),
            )}
          columns={[
            { label: '연결 종류', key: 'node' },
            { label: '출발', key: 'from' },
            { label: '도착', key: 'to' },
          ]}
        />
      </Panel>
    </div>
  );
}
function Timeline({ trace }: { trace: Trace }) {
  return (
    <Panel title="감사 시간선" kicker="APPEND-ONLY AUDIT">
      <p className="panel-description">
        감사 기록입니다. 보안 차단·업무 거절·시스템 오류를 각각 확인하세요.
      </p>
      {!trace.auditEvents?.length ? (
        <Empty title="아직 감사 기록이 없어요" />
      ) : (
        <ol className="timeline">
          {trace.auditEvents.map((event: Row, index) => (
            <li key={text(event, 'eventId', 'id') + index}>
              <span className="timeline-point" />
              <div className="timeline-title">
                <strong>{text(event, 'eventType')}</strong>
                <time>{time(event.createdAt)}</time>
              </div>
              <p>
                {text(event, 'actorId')} {event.reasonCode ? `· ${event.reasonCode}` : ''}
              </p>
              {!!event.reasonCode && <Reason codes={[String(event.reasonCode)]} />}
              <details>
                <summary>비교 기록과 식별자</summary>
                <Json value={event} profile="audit" />
              </details>
            </li>
          ))}
        </ol>
      )}
    </Panel>
  );
}
function Approval({
  api,
  workflow,
  onClose,
  onDone,
}: {
  api: FuseApi;
  workflow: Workflow;
  onClose: () => void;
  onDone: () => void;
}) {
  const load = useCallback(
    (signal: AbortSignal) => api.preview(workflow.workflowId, signal),
    [api, workflow.workflowId],
  );
  const hasCommandIdentity = isCommandUuid(workflow.workflowId);
  const preview = useQuery(load, hasCommandIdentity);
  const [comment, setComment] = useState('');
  const [decision, setDecision] = useState('APPROVE');
  const [confirmation, setConfirmation] = useState<{ api: FuseApi; workflowId: string; generation: number; hash: string; decision: string }>();
  const command = useCommand(api, () => onDone(), `/workflows/${workflow.workflowId}/approvals`);
  const changed = command.error instanceof ApiError && command.error.reasonCodes.includes('REVIEW_CHANGED');
  const data = preview.data;
  const matchingPreview = hasCommandIdentity && !!data && data.workflowId === workflow.workflowId && data.generation === workflow.generation;
  const checked = matchingPreview && confirmation?.api === api && confirmation.workflowId === workflow.workflowId &&
    confirmation.generation === workflow.generation && confirmation.hash === data?.reviewSnapshotHash && confirmation.decision === decision;
  function reload() {
    setConfirmation(undefined);
    command.reset();
    preview.reload();
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (hasCommandIdentity && data && checked && !changed && workflow.canApprove === true && !preview.loading && !preview.error &&
      !command.pending && !command.retryable && !command.result && ['APPROVE', 'REJECT'].includes(decision) && comment.length <= 1000 &&
      /^[a-f0-9]{64}$/.test(data.reviewSnapshotHash) && event.currentTarget.checkValidity())
      void command.run(`/workflows/${workflow.workflowId}/approvals`, {
        decision,
        reviewSnapshotHash: data.reviewSnapshotHash,
        comment,
      });
  }
  return (
    <Modal title="직원 승인 · 정확한 내용 확인" onClose={onClose} busy={command.pending}>
      <p className="muted">
        서버가 만든 미리보기예요. 승인 생성 후에도 지급 직전 증거·격리·회차·금액·계좌를 다시 검사합니다.
      </p>
      <ErrorNotice error={preview.error} retry={reload} />
      {preview.loading && <Loading />}
      {data && (!matchingPreview || workflow.canApprove !== true) && <p className="notice warning">업무 회차 또는 승인 가능 상태가 바뀌었습니다. 닫고 현재 업무를 다시 확인하세요.</p>}
      {data && !command.retryable && !command.result && (
        <>
          <KeyValues
            items={[
              ['고객', data.customerId],
              ['지급 금액', <strong className="review-amount">{currency(data.amountKrw)}</strong>],
              ['정확한 지급 계좌', <span className="code">{data.payoutAccountId}</span>],
              ['회차 · 정책', `${data.generation}회차 · ${data.policyVersion}`],
              ['KYC 결과 ID', data.kycResultId],
              ['Loan 결과 ID', data.loanResultId],
              ['Loan 결과 지문', <span className="hash">{data.loanResultHash}</span>],
              ['증거 묶음 지문', <span className="hash">{data.evidenceBundleHash}</span>],
              [
                '사용 / 예약 / 승인 후 한도',
                `${data.usedRisk} / ${data.reservedRisk} / ${data.riskLimitAfterApproval}`,
              ],
              ['승인 화면 지문', <span className="hash">{data.reviewSnapshotHash}</span>],
            ]}
          />
          <form onSubmit={submit}>
            <fieldset
              disabled={
                command.pending ||
                command.retryable ||
                !!command.result ||
                changed ||
                !matchingPreview || workflow.canApprove !== true ||
                preview.loading ||
                !!preview.error
              }
            >
              <label htmlFor="approval-decision">직원 판단</label>
              <select
                id="approval-decision"
                value={decision}
                onChange={(e) => {
                  setDecision(e.target.value);
                  setConfirmation(undefined);
                }}
              >
                <option value="APPROVE">위 조건으로 승인</option>
                <option value="REJECT">직원 거절</option>
              </select>
              <label htmlFor="approval-comment">검토 의견</label>
              <textarea
                id="approval-comment"
                maxLength={1000}
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                placeholder="확인한 내용과 판단 사유"
              />
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={checked}
                  onChange={(e) => setConfirmation(e.target.checked ? { api, workflowId: workflow.workflowId, generation: workflow.generation, hash: data.reviewSnapshotHash, decision } : undefined)}
                  required
                />
                정확한 고객·금액·계좌·결과를 확인했으며 위 판단으로 제출합니다.
              </label>
              <div className="form-actions">
                <button type="button" className="button secondary" onClick={onClose}>
                  닫기
                </button>
                <button
                  className={`button ${decision === 'REJECT' ? 'danger' : 'primary'}`}
                  type="submit"
                  disabled={!checked || !/^[a-f0-9]{64}$/.test(data.reviewSnapshotHash)}
                >
                  {decision === 'REJECT' ? '직원 거절 제출' : '정확한 조건으로 승인'}
                </button>
              </div>
            </fieldset>
          </form>
        </>
      )}
      <div className="notice info">
        승인 접수는 지급 완료가 아닙니다. 실제 완료는 업무가 PAID로 바뀐 뒤 확인할 수 있어요.
      </div>
      <CommandFeedback command={command} />
      {changed && (
        <button className="button primary" onClick={reload}>
          새 미리보기 확인
        </button>
      )}
      {command.result && (
        <button className="button secondary full" onClick={onClose}>
          업무 상태 확인
        </button>
      )}
    </Modal>
  );
}
function Resume({
  api,
  workflow,
  onClose,
  onDone,
}: {
  api: FuseApi;
  workflow: Workflow;
  onClose: () => void;
  onDone: () => void;
}) {
  const [reason, setReason] = useState('');
  const command = useCommand(api, () => onDone(), `/workflows/${workflow.workflowId}/resume`);
  const [reviewed] = useState({ api, workflowId: workflow.workflowId, generation: workflow.generation, resumeCapability: ownData(workflow, 'resumeCapability') });
  const generation = reviewed.generation;
  const capability = ownData(workflow, 'resumeCapability');
  const stale = !isCommandUuid(workflow.workflowId) || reviewed.api !== api || reviewed.workflowId !== workflow.workflowId || generation !== workflow.generation || workflow.canResume !== true || reviewed.resumeCapability !== 'LEGACY_HTTP' || capability !== reviewed.resumeCapability;
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (stale || command.pending || command.retryable || command.result || !reason.trim() || reason.length > 1000 || !event.currentTarget.checkValidity()) return;
    void command.run(`/workflows/${workflow.workflowId}/resume`, { expectedGeneration: generation, reason });
  }
  return (
    <Modal title="새 회차로 명시적 재개" onClose={onClose} busy={command.pending}>
      <div className="notice warning">
        격리 해제만으로 기존 결과·승인·실패한 작업이 살아나지 않습니다. 원인을 해결하고 자료를 확인한 뒤
        재개하세요.
      </div>
      <KeyValues
        items={[
          ['현재 확인 회차', `${generation}회차`],
          ['이미 사용한 점수', workflow.usedRisk],
          ['재개 후 동작', '새 회차에서 KYC를 다시 시작하고 새 직원 승인을 받아요.'],
        ]}
      />
      <p className="muted">
        사용 점수와 단계별 실행 횟수는 유지됩니다. 세 번째 자동 KYC가 필요하면 수동 조사로 넘어갑니다.
      </p>
      <form onSubmit={submit}>
        {stale && <p className="notice warning">세션·업무 회차 또는 재개 가능 상태가 바뀌었습니다. 닫고 현재 업무를 다시 확인하세요.</p>}
        <fieldset disabled={stale || command.pending || command.retryable || !!command.result}>
          <label htmlFor="resume-reason">원인 해결 및 재개 사유</label>
          <textarea
            id="resume-reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            maxLength={1000}
            required
          />
          <div className="form-actions">
            <button className="button secondary" type="button" onClick={onClose}>
              취소
            </button>
            <button className="button primary" type="submit">
              서버 검증 후 재개 요청
            </button>
          </div>
        </fieldset>
      </form>
      {!stale && <CommandFeedback command={command} />}
      {command.result && (
        <button className="button secondary full" onClick={onClose}>
          현재 상태 확인
        </button>
      )}
    </Modal>
  );
}
