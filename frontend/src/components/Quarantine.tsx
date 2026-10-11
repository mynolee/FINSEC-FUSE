import { useCallback, useState, type FormEvent } from 'react';
import { FuseApi } from '../api';
import { navigate } from '../App';
import { applicationCount, currency, formatValue, integerKrw, isUuid, shortId } from '../format';
import { useCommand, useQuery } from '../hooks';
import type { QuarantineScope } from '../types';
import {
  CommandFeedback,
  Empty,
  ErrorNotice,
  Icon,
  Json,
  KeyValues,
  Loading,
  Modal,
  Panel,
  Stat,
} from './ui';

const SCOPES: Record<QuarantineScope, string> = {
  RUN: '특정 실행',
  RESULT: '특정 결과',
  WORKFLOW: '업무 전체',
  SOURCE_VERSION: '문서의 특정 버전',
  AGENT_VERSION: 'Agent의 특정 버전',
};
export function QuarantinePage({ api, id }: { api: FuseApi; id?: string }) {
  const [lookup, setLookup] = useState(id ?? '');
  const [create, setCreate] = useState(false);
  const [release, setRelease] = useState(false);
  const load = useCallback((signal: AbortSignal) => api.impact(id || '', signal), [api, id]);
  const query = useQuery(load, !!id && isUuid(id), 10000);
  const impact = query.data;
  function lookupIncident(event: FormEvent) {
    event.preventDefault();
    if (isUuid(lookup)) navigate('quarantine', lookup);
  }
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">CONTAINMENT & IMPACT</span>
          <h1>격리 · 영향 조사</h1>
          <p>실제로 연결된 영향을 조사하고, 필요한 범위만 격리하세요.</p>
        </div>
        <button className="button danger" onClick={() => setCreate(true)}>
          <Icon name="shield" size={17} />
          격리 범위 지정
        </button>
      </div>
      <div className="notice info">
        <Icon name="lock" />
        <p>
          보안 관리자 권한이 필요합니다. 격리·해제 요청은 서버가 권한과 범위를 다시 검증해요. 이미 완료한 Mock
          지급은 되돌아가지 않습니다.
        </p>
      </div>
      <Panel title="격리 사건 조회" kicker="INCIDENT LOOKUP">
        <form className="lookup-form" onSubmit={lookupIncident}>
          <div>
            <label htmlFor="incident-id">격리 ID (quarantineId)</label>
            <input
              id="incident-id"
              value={lookup}
              onChange={(e) => setLookup(e.target.value)}
              placeholder="업무 상세의 활성 격리에서 확인할 수 있어요"
              required
              pattern="[0-9a-fA-F-]{36}"
            />
          </div>
          <button className="button primary" type="submit" disabled={!isUuid(lookup)}>
            영향 조사
          </button>
          {id && (
            <button
              className="icon-button"
              type="button"
              aria-label="영향 새로고침"
              disabled={query.loading}
              onClick={query.reload}
            >
              <Icon name="refresh" />
            </button>
          )}
        </form>
      </Panel>
      {id && !isUuid(id) && <ErrorNotice error={new Error('격리 사건 ID는 유효한 UUID여야 해요.')} />}
      <ErrorNotice error={query.error} retry={query.reload} />
      {query.loading && id && <Loading />}
      {!id && (
        <Empty title="조사할 격리 사건을 선택하세요">
          업무 상세의 활성 격리 링크를 열거나 격리 ID를 입력하세요. 영향 수치는 서버 조회 후 표시됩니다.
        </Empty>
      )}
      {impact && (
        <div className="panel-stack">
          <Panel
            title="격리 대상"
            kicker="SCOPE & TARGET"
            action={
              <button className="button secondary" onClick={() => setRelease(true)} disabled={!!query.error}>
                조치 검증 후 격리 해제
              </button>
            }
          >
            <KeyValues
              items={[
                ['격리 사건', impact.incidentId],
                ['범위', SCOPES[impact.scope] || impact.scope],
                ['대상', formatValue(impact.target)],
                ['격리 전 완료 지급 존재', formatValue(impact.paidBeforeQuarantine)],
              ]}
            />
            <p className="panel-description">
              사건은 격리 기록을 가리킵니다. 과거 회차 연결은 조사 이력에 남고, 현재 회차의 실행 차단 범위와
              구분됩니다.
            </p>
          </Panel>
          <section aria-labelledby="actual-impact">
            <div className="section-heading">
              <span className="section-indicator actual" />
              <h2 id="actual-impact">실제 영향</h2>
              <span className="code">ACTUAL · 저장된 실행과 원장</span>
            </div>
            <div className="stats-grid">
              <Stat label="실제로 연결된 실행" value={impact.actual?.runCount ?? '미제공'} />
              <Stat
                label="영향 업무 / 고객"
                value={`${impact.actual?.workflowCount ?? '—'} / ${impact.actual?.customerCount ?? '—'}`}
              />
              <Stat
                label="실제 Mock 지급"
                value={impact.actual?.paymentCount ?? '미제공'}
                detail={currency(impact.actual?.paidAmountKrw)}
              />
              <Stat
                label="영향 업무의 미지급 신청액"
                value={currency(impact.actual?.atRiskPendingAmountKrw)}
                detail="신청서 한 건을 한 번만 합산"
              />
            </div>
          </section>
          <section className="potential-section" aria-labelledby="potential-impact">
            <div className="section-heading">
              <span className="section-indicator potential" />
              <h2 id="potential-impact">정책상 잠재 영향</h2>
              <span className="code">POTENTIAL · 영향받을 수 있는 범위</span>
            </div>
            <p className="panel-description" id="potential-amount-description">
              영향받을 수 있는 신청 금액의 합계. 실제 지급액이나 확정 손실액이 아닙니다.
            </p>
            <div
              className="stats-grid potential-summary"
              role="group"
              aria-label="동일 범위의 잠재 영향 금액과 대상 신청 수"
              aria-describedby="potential-amount-description"
            >
              <Stat
                label="잠재 영향 금액"
                value={integerKrw(impact.potential?.totalAmountKrw, impact.potential?.currency)}
                detail="영향받을 수 있는 신청 금액의 합계"
              />
              <Stat
                label="잠재 영향 대상 신청 수"
                value={applicationCount(impact.potential?.applicationCount)}
                detail="금액과 동일한 범위 · 서버에서 신청별 중복 제외"
              />
            </div>
            <div className="stats-grid">
              <Stat
                label="도달 가능한 역할"
                value={
                  Array.isArray(impact.potential?.roles) &&
                  impact.potential.roles.every((role) => typeof role === 'string')
                    ? impact.potential.roles.join(' → ') || '미제공'
                    : '미제공'
                }
              />
              <Stat label="최대 후속 깊이" value={impact.potential?.maxDownstreamDepth ?? '계산 불가'} />
              <Stat
                label="등록된 고객 접근 범위"
                value={impact.potential?.registeredCustomerCount ?? '계산 불가'}
              />
              <Stat
                label="신청 한 건당 정책 상한"
                value={currency(impact.potential?.perApplicationLimitKrw)}
                detail="전체 고객 합계가 아닙니다"
              />
            </div>
            {Array.isArray(impact.potential?.missingPolicyFields) &&
              impact.potential.missingPolicyFields.every((field) => typeof field === 'string') &&
              !!impact.potential.missingPolicyFields.length && (
                <p className="muted">
                  계산에 필요한 정책 필드 미제공: {impact.potential.missingPolicyFields.join(', ')}
                </p>
              )}
          </section>
          <div className="two-columns">
            <Panel title="현재 차단 대상 업무" kicker="CURRENT GENERATION">
              {Boolean(impact.policyHeldWorkflowIds?.length) && (
                <p className="panel-description">
                  실행 전 정책 보류 업무도 복구 대상에 포함됩니다. 아직 실제 문서 소비나 실행 간선은 없습니다.
                </p>
              )}
              {impact.currentAffectedWorkflowIds?.length ? (
                <ul className="entity-list">
                  {impact.currentAffectedWorkflowIds.map((workflowId) => (
                    <li key={workflowId}>
                      <a href={`#/workflows/${workflowId}`}>
                        <span className="code">{workflowId}</span>
                        {impact.policyHeldWorkflowIds?.includes(workflowId) && (
                          <small className="policy-held-label">실행 전 정책 보류</small>
                        )}
                        <Icon name="arrow" size={16} />
                      </a>
                    </li>
                  ))}
                </ul>
              ) : (
                <Empty title="현재 회차의 영향 업무 없음" />
              )}
            </Panel>
            <Panel title="과거를 포함한 실행 계보" kicker="HISTORICAL LINEAGE">
              {impact.historicalRunIds?.length ? (
                <ul className="entity-list">
                  {impact.historicalRunIds.map((runId) => (
                    <li key={runId}>
                      <span className="code">{runId}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <Empty title="기록된 영향 실행 없음" />
              )}
            </Panel>
          </div>
          <Panel title="계산 근거" kicker="TRACEABLE CALCULATION">
            <Json value={impact.calculationRefs ?? { message: '서버가 계산 근거를 제공하지 않았어요.' }} />
            <details className="raw-response">
              <summary>영향 조회 전체 응답</summary>
              <Json value={impact} />
            </details>
          </Panel>
        </div>
      )}
      {create && (
        <CreateQuarantine
          api={api}
          onClose={() => setCreate(false)}
          onCreated={(quarantineId) => {
            setCreate(false);
            setLookup(quarantineId);
            navigate('quarantine', quarantineId);
          }}
        />
      )}
      {release && id && (
        <ReleaseQuarantine
          api={api}
          id={id}
          scope={impact?.scope}
          requireEvidence={impact?.actual?.atRiskPendingAmountKrw !== 0}
          onClose={() => setRelease(false)}
          onDone={query.reload}
        />
      )}
    </>
  );
}
function CreateQuarantine({
  api,
  onClose,
  onCreated,
}: {
  api: FuseApi;
  onClose: () => void;
  onCreated: (id: string) => void;
}) {
  const [scope, setScope] = useState<QuarantineScope>('RUN');
  const [targetId, setTarget] = useState('');
  const [version, setVersion] = useState('1');
  const [reasonCode, setReasonCode] = useState('EVIDENCE_MISSING');
  const [note, setNote] = useState('');
  const [confirm, setConfirm] = useState(false);
  const command = useCommand(api, (result) => {
    if (result.quarantineId && result.decision !== 'DENY' && result.decision !== 'ERROR')
      onCreated(result.quarantineId);
  });
  function submit(event: FormEvent) {
    event.preventDefault();
    if (!confirm) return;
    const target =
      scope === 'RUN'
        ? { runId: targetId }
        : scope === 'RESULT'
          ? { resultId: targetId }
          : scope === 'WORKFLOW'
            ? { workflowId: targetId }
            : scope === 'SOURCE_VERSION'
              ? { documentId: targetId, documentVersion: Number(version) }
              : { agentId: targetId, agentVersion: Number(version) };
    void command.run('/quarantines', { scope, ...target, reasonCode, note });
  }
  return (
    <Modal title="선택한 범위 격리" onClose={onClose} busy={command.pending}>
      <p className="muted">
        관계있는 미지급 업무·결과·승인·작업이 차단됩니다. 더 넓은 Agent 버전 격리는 실제 조사 후 선택하세요.
      </p>
      <form onSubmit={submit}>
        <fieldset disabled={command.pending || command.retryable}>
          <label htmlFor="quarantine-scope">격리 범위</label>
          <select
            id="quarantine-scope"
            value={scope}
            onChange={(e) => {
              setScope(e.target.value as QuarantineScope);
              setTarget('');
              setConfirm(false);
            }}
          >
            {Object.entries(SCOPES).map(([key, label]) => (
              <option key={key} value={key}>
                {key} · {label}
              </option>
            ))}
          </select>
          <label htmlFor="quarantine-target">
            {SCOPES[scope]} ID{scope === 'AGENT_VERSION' ? '' : ' (UUID)'}
          </label>
          <input
            id="quarantine-target"
            value={targetId}
            onChange={(e) => {
              setTarget(e.target.value);
              setConfirm(false);
            }}
            required
            pattern={scope === 'AGENT_VERSION' ? undefined : '[0-9a-fA-F-]{36}'}
          />
          {['SOURCE_VERSION', 'AGENT_VERSION'].includes(scope) && (
            <>
              <label htmlFor="target-version">정확한 버전</label>
              <input
                id="target-version"
                type="number"
                min={1}
                step={1}
                value={version}
                onChange={(e) => {
                  setVersion(e.target.value);
                  setConfirm(false);
                }}
                required
              />
            </>
          )}
          <label htmlFor="quarantine-reason">정책 사유</label>
          <select id="quarantine-reason" value={reasonCode} onChange={(e) => setReasonCode(e.target.value)}>
            {[
              'EVIDENCE_MISSING',
              'EVIDENCE_INVALID',
              'SCOPE_EXCEEDED',
              'CONTEXT_MISMATCH',
              'SIGNATURE_INVALID',
              'QUARANTINED',
              'SECURITY_INVESTIGATION',
              'SOURCE_COMPROMISED',
              'AGENT_COMPROMISED',
              'POLICY_VIOLATION',
            ].map((code) => (
              <option key={code}>{code}</option>
            ))}
          </select>
          <label htmlFor="quarantine-note">조사 내용</label>
          <textarea
            id="quarantine-note"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            maxLength={1000}
            required
          />
          <div className="notice warning">
            이미 PAID인 업무는 완료 상태로 남고 사후 영향에 포함됩니다. 지급 취소 기능이 아닙니다.
          </div>
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={confirm}
              onChange={(e) => setConfirm(e.target.checked)}
              required
            />
            위 범위와 대상 ID를 확인했습니다.
          </label>
          <div className="form-actions">
            <button className="button secondary" type="button" onClick={onClose}>
              취소
            </button>
            <button className="button danger" type="submit" disabled={!confirm}>
              선택한 범위 격리
            </button>
          </div>
        </fieldset>
      </form>
      <CommandFeedback command={command} />
    </Modal>
  );
}
function ReleaseQuarantine({
  api,
  id,
  scope,
  requireEvidence,
  onClose,
  onDone,
}: {
  api: FuseApi;
  id: string;
  scope?: QuarantineScope;
  requireEvidence: boolean;
  onClose: () => void;
  onDone: () => void;
}) {
  const [documentId, setDocumentId] = useState('');
  const [documentVersion, setDocumentVersion] = useState('1');
  const [evidenceIds, setEvidenceIds] = useState('');
  const [agentId, setAgentId] = useState('');
  const [agentVersion, setAgentVersion] = useState('');
  const [note, setNote] = useState('');
  const [checked, setChecked] = useState(false);
  const [validationError, setValidationError] = useState('');
  const command = useCommand(api, () => onDone());
  function submit(event: FormEvent) {
    event.preventDefault();
    const ids = [...new Set(evidenceIds.split(/[\s,]+/).filter(Boolean))];
    if ((requireEvidence && !ids.length) || ids.some((item) => !isUuid(item))) {
      setValidationError('확인 자료는 유효한 UUID를 한 개 이상 입력하세요.');
      return;
    }
    setValidationError('');
    void command.run(`/quarantines/${id}/release`, {
      remediation: {
        safeDocumentId: documentId,
        safeDocumentVersion: Number(documentVersion),
        checkEvidenceIds: ids,
        note,
        ...(scope === 'AGENT_VERSION'
          ? { safeAgentId: agentId, safeAgentVersion: Number(agentVersion) }
          : {}),
      },
    });
  }
  return (
    <Modal title="안전 조치 검증 · 격리 해제" onClose={onClose} busy={command.pending}>
      <p className="id-line">격리 사건 {shortId(id)}</p>
      <div className="notice warning">
        해제는 금지 표시만 없앱니다. 기존 INVALIDATED 결과·REVOKED 승인·FAILED 작업은 되살리지 않습니다. 이후
        업무 상세에서 담당 직원이 명시적으로 재개해야 해요.
      </div>
      <form onSubmit={submit}>
        <fieldset disabled={command.pending || command.retryable || !!command.result}>
          <div className="field-grid">
            <div>
              <label htmlFor="safe-document">검토된 안전 문서 UUID</label>
              <input
                id="safe-document"
                value={documentId}
                onChange={(e) => setDocumentId(e.target.value)}
                pattern="[0-9a-fA-F-]{36}"
                required
              />
            </div>
            <div>
              <label htmlFor="safe-version">안전 문서 버전</label>
              <input
                id="safe-version"
                value={documentVersion}
                onChange={(e) => setDocumentVersion(e.target.value)}
                type="number"
                min={1}
                step={1}
                required
              />
            </div>
          </div>
          {scope === 'AGENT_VERSION' && (
            <div className="field-grid">
              <div>
                <label htmlFor="safe-agent">검토된 안전 Agent ID</label>
                <input
                  id="safe-agent"
                  value={agentId}
                  onChange={(e) => setAgentId(e.target.value)}
                  required
                />
              </div>
              <div>
                <label htmlFor="safe-agent-version">안전 Agent 버전</label>
                <input
                  id="safe-agent-version"
                  value={agentVersion}
                  onChange={(e) => setAgentVersion(e.target.value)}
                  type="number"
                  min={1}
                  step={1}
                  required
                />
              </div>
            </div>
          )}
          <label htmlFor="check-evidence">영향 고객 전원의 유효한 확인 자료 UUID</label>
          <textarea
            id="check-evidence"
            value={evidenceIds}
            onChange={(e) => setEvidenceIds(e.target.value)}
            placeholder="UUID를 줄바꿈 또는 쉼표로 구분"
            required={requireEvidence}
          />
          <small className="field-help">
            미지급 영향 고객의 ID_DOC와 FACE_MATCH가 필요합니다. 여러 고객이면 모두 포함하세요. 미지급 영향
            업무가 없으면 빈 목록을 검증 요청할 수 있어요.
          </small>
          <label htmlFor="remediation-note">원인 제거 및 조치 사유</label>
          <textarea
            id="remediation-note"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            maxLength={1000}
            required
          />
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={checked}
              onChange={(e) => setChecked(e.target.checked)}
              required
            />
            원인을 해결했으며 안전 출처와 독립 확인 자료의 재검증을 요청합니다.
          </label>
          <div className="form-actions">
            <button className="button secondary" type="button" onClick={onClose}>
              취소
            </button>
            <button className="button primary" type="submit" disabled={!checked}>
              검증 후 격리 해제
            </button>
          </div>
        </fieldset>
      </form>
      {validationError && <ErrorNotice error={new Error(validationError)} />}
      <CommandFeedback command={command} />
      {command.result && (
        <div className="form-actions">
          <button className="button secondary" onClick={onClose}>
            영향 업무 확인
          </button>
        </div>
      )}
    </Modal>
  );
}
