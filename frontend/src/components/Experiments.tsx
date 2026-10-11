import { useCallback, useState, useRef, useEffect, type FormEvent } from 'react';
import { ApiError, FuseApi } from '../api';
import { navigate } from '../App';
import { formatValue, isUuid, text, value } from '../format';
import { useCommand, useQuery } from '../hooks';
import type { Experiment, Row } from '../types';
import { experimentCsv, sanitizedExperiment } from '../experimentExport';
export { csvCell } from '../experimentExport';
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
  RecordTable,
  Stat,
  Status,
} from './ui';

export const MVP_CASES = [
  'T01_NORMAL_PAYMENT',
  'T02_MISSING_EVIDENCE',
  'T03_WRONG_CUSTOMER_EVIDENCE',
  'T04_PRIVILEGE_REQUEST',
  'T05_APPROVAL_RISK_WAIT',
  'T06_SELECTIVE_QUARANTINE',
];
function download(contents: string, name: string, mime: string) {
  const url = URL.createObjectURL(new Blob([contents], { type: mime }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = name;
  try {
    anchor.click();
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}
function exportCsv(experiment: Experiment) {
  download(
    experimentCsv(experiment),
    `finsec-${experiment.experimentId}-cases.csv`,
    'text/csv;charset=utf-8',
  );
}
export function ExperimentsPage({ api, id }: { api: FuseApi; id?: string }) {
  const [exportError, setExportError] = useState<unknown>();
  const [exporting, setExporting] = useState(false);
  const exportingRef = useRef(false);
  const exportController = useRef<AbortController | undefined>(undefined);
  useEffect(() => () => exportController.current?.abort(), [api, id]);
  async function exportCurrent(kind: 'csv' | 'json') {
    if (!id || !isUuid(id) || exportingRef.current) return;
    exportingRef.current = true;
    setExporting(true);
    setExportError(undefined);
    const controller = new AbortController();
    exportController.current = controller;
    try {
      // Recheck current server auth/scope before emitting any downloadable bytes.
      const current = await api.experiment(id, controller.signal);
      if (controller.signal.aborted) return;
      if (current.experimentId !== id) throw new Error('실험 응답의 대상이 일치하지 않아요.');
      if (kind === 'csv') exportCsv(current);
      else
        download(
          JSON.stringify(sanitizedExperiment(current), null, 2),
          `finsec-${id}-sanitized.json`,
          'application/json',
        );
    } catch (error) {
      if (!controller.signal.aborted) {
        setExportError(error);
        if (error instanceof ApiError && [401, 403, 404].includes(error.status)) query.clear();
      }
    } finally {
      exportingRef.current = false;
      if (!controller.signal.aborted) setExporting(false);
    }
  }
  const [lookup, setLookup] = useState(id ?? '');
  const [create, setCreate] = useState(false);
  const [interval, setInterval] = useState(5000);
  const load = useCallback(
    async (signal: AbortSignal) => {
      const result = await api.experiment(id || '', signal);
      if (!['PENDING', 'RUNNING', 'QUEUED'].includes(result.status || result.state || '')) setInterval(0);
      return result;
    },
    [api, id],
  );
  const query = useQuery(load, !!id && isUuid(id), interval);
  const experiment = query.data;
  const rows = experiment?.caseOutputs || experiment?.results || [];
  const metrics = experiment?.metrics;
  const progress = experiment?.progress;
  const syntheticOutputs =
    typeof experiment?.syntheticModelOutputs === 'boolean'
      ? experiment.syntheticModelOutputs
      : typeof metrics?.syntheticModelOutputs === 'boolean'
        ? metrics.syntheticModelOutputs
        : undefined;
  const liveMeasured =
    typeof experiment?.liveRobustnessMeasured === 'boolean'
      ? experiment.liveRobustnessMeasured
      : typeof metrics?.liveRobustnessMeasured === 'boolean'
        ? metrics.liveRobustnessMeasured
        : undefined;
  const capturedRows = rows.flatMap((row) => {
    const trace = row.trace && typeof row.trace === 'object' ? (row.trace as Row) : undefined;
    const capture =
      trace?.modelCapture && typeof trace.modelCapture === 'object' ? (trace.modelCapture as Row) : undefined;
    return capture
      ? [{ caseId: row.caseId, repeat: row.repeat, environment: row.environment, ...capture }]
      : [];
  });
  const sourceLabel =
    syntheticOutputs === true
      ? '합성 후보 응답 재생 (서버 메타데이터)'
      : syntheticOutputs === false && capturedRows.length > 0
        ? '실제 모델 캡처 응답 (서버 기록)'
        : syntheticOutputs === false
          ? 'LIVE 요청 · 아직 유효한 캡처 기록 없음'
          : '출력 출처 메타데이터 미제공';
  const metricExclusions = metrics && Array.isArray(metrics.exclusions) ? (metrics.exclusions as Row[]) : [];
  const exclusions = experiment?.exclusions || metricExclusions;
  const excludedPairs = new Set(
    exclusions.map((row) => String(row.pair ?? `${row.caseId}:${row.repeat ?? 1}`)),
  );
  const environments =
    metrics?.environments && typeof metrics.environments === 'object'
      ? (metrics.environments as Record<string, Row>)
      : undefined;
  const comparableKeys = environments ? [...new Set(Object.values(environments).flatMap(Object.keys))] : [];
  const pairedMetrics: Row[] = comparableKeys.map((key) => ({
    metric: metricLabel(key),
    BASELINE: metricValue(key, environments?.BASELINE?.[key]),
    FUSE: metricValue(key, environments?.FUSE?.[key]),
  }));
  const otherMetrics = Object.entries(metrics || {}).filter(
    ([key]) => !['environments', 'exclusions'].includes(key),
  );
  function search(event: FormEvent) {
    event.preventDefault();
    if (isUuid(lookup)) {
      setInterval(5000);
      navigate('experiments', lookup);
    }
  }
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">EVIDENCE-BASED EVALUATION</span>
          <h1>비교 실험</h1>
          <p>동일한 입력으로 Baseline과 FUSE의 실제 정책 결과를 비교합니다.</p>
        </div>
        <button className="button primary" onClick={() => setCreate(true)}>
          <Icon name="flask" size={17} />새 실험
        </button>
      </div>
      <div className="notice info">
        <p>
          {experiment?.modelMode === 'LIVE'
            ? 'LIVE는 사례별로 한 번 캡처한 같은 모델 응답을 양쪽 환경에 적용합니다. 호출 실패와 공격 유도 실패는 공통 평가 분모에서 제외하며 방어 성공으로 세지 않아요.'
            : 'REPLAY는 저장된 후보 응답을 사용합니다. LIVE 공격 성공률이 아닙니다. 선택형 LIVE는 설정된 외부 모델을 호출하며 비용이 발생할 수 있어요. 업무 부적격·유도 실패·환경 오류는 정책 차단과 구분해 읽어 주세요.'}
        </p>
      </div>
      <Panel title="실험 기록 조회" kicker="EXPERIMENT LOOKUP">
        <form className="lookup-form" onSubmit={search}>
          <div>
            <label htmlFor="experiment-id">실험 UUID</label>
            <input
              id="experiment-id"
              value={lookup}
              onChange={(e) => setLookup(e.target.value)}
              placeholder="실험 접수 시 반환된 experimentId"
              pattern="[0-9a-fA-F-]{36}"
              required
            />
          </div>
          <button className="button primary" disabled={!isUuid(lookup)} type="submit">
            결과 조회
          </button>
          {id && (
            <button
              className="icon-button"
              type="button"
              aria-label="실험 새로고침"
              onClick={query.reload}
              disabled={query.loading}
            >
              <Icon name="refresh" />
            </button>
          )}
        </form>
      </Panel>
      <ErrorNotice error={query.error} retry={query.reload} />
      <ErrorNotice error={exportError} />
      {id && !isUuid(id) && <ErrorNotice error={new Error('실험 ID는 유효한 UUID여야 해요.')} />}
      {query.loading && id && !experiment && <Loading />}
      {!id && (
        <Empty title="아직 선택한 실험이 없어요">
          실험을 접수하거나 기존 기록의 ID를 입력하세요. 계획된 기대값을 측정 결과로 표시하지 않아요.
        </Empty>
      )}
      {experiment && (
        <div className="panel-stack">
          <Panel
            title="실험 실행 상태"
            kicker="EXECUTION STATUS"
            action={<Status state={experiment.status || experiment.state} />}
          >
            <KeyValues
              items={[
                ['실험 ID', experiment.experimentId],
                ['등록 fixture', experiment.fixtureSetId || '미제공'],
                ['모델 모드', experiment.modelMode || '미제공'],
                ['후보 출력 출처', sourceLabel],
                [
                  'LIVE 평가 완료 여부',
                  liveMeasured === true
                    ? '공통 평가 공격 쌍의 실제 모델 결과로 측정됨'
                    : liveMeasured === false
                      ? '아직 측정되지 않음'
                      : '미제공',
                ],
                [
                  '진행',
                  typeof progress === 'object' && progress
                    ? `${formatValue(progress.completedRuns ?? progress.completed)} / ${formatValue(progress.totalRuns ?? progress.total)} 환경 실행`
                    : formatValue(progress),
                ],
              ]}
            />
            {['INTERRUPTED', 'FAILED', 'ERROR'].includes(experiment.status || experiment.state || '') && (
              <div className="notice warning">
                전체 실험이 성공적으로 끝나지 않았습니다. 중간 결과를 전체 성공으로 해석하지 마세요.
              </div>
            )}
          </Panel>
          <Panel title="서버가 계산한 측정 지표" kicker="MEASURED METRICS">
            <p className="panel-description">
              분모와 제외 사유를 함께 확인하세요. 계산되지 않은 지표는 성공률 0%나 100%로 대신하지 않습니다.
            </p>
            {!!pairedMetrics.length && (
              <RecordTable
                rows={pairedMetrics}
                columns={[
                  { label: '지표 · 분모', key: 'metric' },
                  { label: 'BASELINE', key: 'BASELINE' },
                  { label: 'FUSE', key: 'FUSE' },
                ]}
              />
            )}
            {metrics && Object.keys(metrics).length ? (
              <div className="metric-grid">
                {otherMetrics.map(([key, item]) => (
                  <div key={key}>
                    {typeof item === 'number' || typeof item === 'string' || typeof item === 'boolean' ? (
                      <Stat label={metricLabel(key)} value={formatValue(item)} />
                    ) : (
                      <section className="metric-object">
                        <h3>{metricLabel(key)}</h3>
                        <Json value={item} />
                      </section>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <Empty title="아직 계산된 지표가 없어요" />
            )}
          </Panel>
          <Panel
            title="사례별 Baseline / FUSE 결과"
            kicker="PAIRED CASE OUTPUTS"
            action={
              <div className="table-controls">
                <button
                  className="button small secondary"
                  disabled={!rows.length || exporting || !!query.error}
                  onClick={() => void exportCurrent('csv')}
                >
                  CSV 내보내기
                </button>
                <button
                  className="button small secondary"
                  disabled={exporting || !!query.error}
                  onClick={() => void exportCurrent('json')}
                >
                  정제 JSON 내보내기
                </button>
              </div>
            }
          >
            <p className="notice info">
              CSV와 JSON은 정제된 근거만 내보냅니다. 프롬프트·문서·모델 설명·DB 원문은 제외하며, 알려지지 않은
              식별 라벨은 null로 표시합니다. 파일 지문과 전체 계획 대조는 Python 근거 묶음을 사용하세요.
            </p>
            <p className="panel-description">
              전용 보안 검사 시간은 증거·위임·격리 일치 검사의 전용 실행 시간입니다. 모델·직원 대기와 공통
              승인·장부 처리는 제외하며, 전체 지연이나 두 환경의 시간 차이가 아닙니다. 측정 범위와 횟수는 원시
              기록의 securityMeasurement에서 확인하세요.
            </p>
            <RecordTable
              rows={rows}
              rowDetails
              columns={[
                { label: '사례', key: 'caseId' },
                {
                  label: '환경',
                  key: 'environment',
                  render: (row) => text(row, 'environment', 'mode', 'variant'),
                },
                { label: '업무 판단', key: 'decision', render: (row) => <Status state={row.decision} /> },
                {
                  label: '실제 상태',
                  key: 'state',
                  render: (row) => <Status state={value(row, 'state', 'actualState')} />,
                },
                {
                  label: '전용 보안 검사 시간',
                  key: 'securityCheckDurationMs',
                  render: (row) =>
                    typeof row.securityCheckDurationMs === 'number'
                      ? `${row.securityCheckDurationMs.toFixed(3)} ms`
                      : '미측정',
                },
                {
                  label: '격리 적용 시간',
                  key: 'quarantineLatencyMs',
                  render: (row) =>
                    typeof row.quarantineLatencyMs === 'number'
                      ? `${row.quarantineLatencyMs.toFixed(3)} ms`
                      : '미측정',
                },
                {
                  label: '평가 포함 여부',
                  key: 'eligible',
                  render: (row) =>
                    excludedPairs.has(`${row.caseId}:${row.repeat ?? 1}`) ||
                    row.status === 'ERROR' ||
                    row.excluded === true ||
                    row.eligible === false
                      ? '공통 분모 제외'
                      : row.eligible === true || row.excluded === false
                        ? '평가 포함'
                        : row.status === 'COMPLETED' &&
                            rows.filter(
                              (other) =>
                                other.caseId === row.caseId && (other.repeat ?? 1) === (row.repeat ?? 1),
                            ).length === 2
                          ? '완료한 비교 쌍'
                          : '집계 중 / 원시 결과 참고',
                },
                {
                  label: '제외 / 오류 사유',
                  key: 'exclusionReason',
                  render: (row) =>
                    describeExperimentIssue(value(row, 'exclusionReason', 'reasonCode', 'reasonCodes')),
                },
              ]}
            />
          </Panel>
          {experiment.modelMode === 'LIVE' && (
            <Panel title="모델 캡처 근거" kicker="ONE CAPTURE · TWO ARMS">
              <p className="panel-description">
                각 사례·반복의 한 캡처를 Baseline과 FUSE가 공유합니다. 같은 캡처 ID가 두 환경에 표시되어도 두
                번 호출했다는 뜻은 아닙니다. 비-RAG 주입은 별도 시험 도구의 변조이며 모델이 생성한 행동으로
                해석하지 마세요.
              </p>
              <RecordTable
                rows={capturedRows}
                rowDetails
                empty="아직 유효한 모델 캡처 기록이 없어요"
                columns={[
                  { label: '사례', key: 'caseId' },
                  { label: '반복', key: 'repeat' },
                  { label: '환경', key: 'environment' },
                  { label: '실제 모델', key: 'model' },
                  { label: '프롬프트 버전', key: 'promptVersion' },
                  {
                    label: '출력 지문',
                    key: 'modelOutputHash',
                    render: (row) => <span className="hash">{text(row, 'modelOutputHash')}</span>,
                  },
                  { label: '공유 캡처 ID', key: 'captureRequestId' },
                ]}
              />
            </Panel>
          )}
          <Panel title="평가 제외와 실패" kicker="COMMON DENOMINATOR EXCLUSIONS">
            <RecordTable
              rows={exclusions}
              rowDetails
              columns={[
                { label: '사례 · 비교 쌍', key: 'caseId', render: (row) => text(row, 'caseId', 'pair') },
                {
                  label: '제외 사유',
                  key: 'reason',
                  render: (row) =>
                    describeExperimentIssue(value(row, 'reason', 'reasons', 'reasonCode', 'exclusionReason')),
                },
              ]}
              empty="서버가 별도의 제외 목록을 제공하지 않았어요"
            />
            <details className="raw-response">
              <summary>실험 전체 응답과 버전 정보</summary>
              <Json value={experiment} />
            </details>
          </Panel>
        </div>
      )}
      {create && (
        <CreateExperiment
          api={api}
          onClose={() => setCreate(false)}
          onCreated={(experimentId) => {
            setCreate(false);
            setLookup(experimentId);
            setInterval(5000);
            navigate('experiments', experimentId);
          }}
        />
      )}
    </>
  );
}
export function describeExperimentIssue(issue: unknown): string {
  if (Array.isArray(issue)) return issue.length ? issue.map(describeExperimentIssue).join(' · ') : '없음';
  if (typeof issue !== 'string' || !issue) return formatValue(issue);
  const code = issue.split(':', 1)[0];
  const descriptions: Record<string, string> = {
    LIVE_NOT_AVAILABLE:
      '서버에서 LIVE가 활성화되지 않았어요. 서버 설정과 제공자 연결을 확인하거나 REPLAY를 선택하세요.',
    MODEL_OUTPUT_INVALID:
      '모델 응답 형식 또는 캡처 연결 검증에 실패했어요. 양쪽 결과를 제외하며 방어 성공이 아닙니다.',
    DEPENDENCY_UNAVAILABLE:
      '모델 호출 또는 의존 서비스가 응답하지 않았어요. 양쪽 결과를 제외하며 방어 성공이 아닙니다.',
    INDUCTION_FAILED: '등록된 공격 후보가 유도되지 않았어요. 양쪽을 공통 공격 분모에서 제외합니다.',
    CAPTURE_ERROR: '모델 응답 캡처에 실패했어요. 양쪽 결과를 제외하며 방어 성공이 아닙니다.',
    ENVIRONMENT_ERROR: '실험 환경 오류로 양쪽 결과를 평가에서 제외합니다.',
    UNSUPPORTED_SCENARIO: '지원되지 않는 시험 주입으로 양쪽 결과를 평가에서 제외합니다.',
  };
  return descriptions[code] ? `${descriptions[code]} (${issue})` : issue;
}
function metricValue(key: string, item: unknown) {
  return item === null || item === undefined
    ? '계산되지 않음'
    : key.endsWith('Rate') && typeof item === 'number'
      ? `${(item * 100).toFixed(1)}%`
      : formatValue(item);
}
function metricLabel(key: string) {
  const labels: Record<string, string> = {
    eligibleAttackCount: '공통 평가 공격 수 (분모)',
    policyBlockCount: '정책으로 차단한 공격 수',
    normalEvaluableCount: '평가 가능한 정상 사례 수',
    normalFalseBlockCount: '정상 오차단 수',
    forbiddenPaidAmountKrw: '실제 금지 지급액 (원)',
    excludedPairCount: '공통 분모에서 제외한 비교 쌍',
    syntheticModelOutputs: '합성 후보 출력 사용 여부',
    liveRobustnessMeasured: '실제 LIVE 강건성 측정 여부',
    forbiddenActionBlockRate: '금지 행동 차단률',
    normalFalseBlockRate: '정상 오차단률',
    unrelatedNormalRetentionRate: '독립 정상 유지율',
    forbiddenPaymentCount: '실제 금지 지급 건수',
    forbiddenPaymentAmountKrw: '실제 금지 지급액 (원)',
    commonAttackDenominator: '공통 평가 공격 분모',
    excludedCount: '평가 제외 사례 수',
    additionalSecurityLatencyMs: '전용 보안 검사 시간 (ms)',
    securityCheckDurationMs: '전용 보안 검사 시간 (ms)',
    quarantineLatencyMs: '격리 적용 시간 (미측정 항목은 null)',
  };
  return labels[key] || key;
}
function CreateExperiment({
  api,
  onClose,
  onCreated,
}: {
  api: FuseApi;
  onClose: () => void;
  onCreated: (id: string) => void;
}) {
  const [fixture, setFixture] = useState('mvp-security-v1');
  const [modelMode, setModelMode] = useState<'REPLAY' | 'LIVE'>('REPLAY');
  const [liveConsent, setLiveConsent] = useState(false);
  const isLive = modelMode === 'LIVE';
  const repeatCount = isLive ? 3 : 1;
  const caseCount = fixture === 'mvp-security-v1' ? MVP_CASES.length : 60;
  const [checked, setChecked] = useState(false);
  const command = useCommand(api, (result) => {
    if (result.experimentId && result.decision !== 'ERROR' && result.decision !== 'DENY')
      onCreated(result.experimentId);
  });
  function submit(event: FormEvent) {
    event.preventDefault();
    if (!checked || (isLive && !liveConsent)) return;
    void command.run('/experiments', {
      fixtureSetId: fixture,
      caseIds: fixture === 'mvp-security-v1' ? MVP_CASES : [],
      mode: 'PAIRED',
      modelMode,
      repeatCount,
    });
  }
  return (
    <Modal title="동일 입력 비교 실험" onClose={onClose} busy={command.pending}>
      <p className="muted">
        DEVELOPER 역할과 demo/test 환경에서만 실행할 수 있어요. 업무 DB와 분리된 실험 공간을 사용합니다.
      </p>
      <form onSubmit={submit}>
        <fieldset disabled={command.pending || command.retryable}>
          <label htmlFor="fixture-set">등록된 사례 묶음</label>
          <select
            id="fixture-set"
            value={fixture}
            onChange={(e) => {
              setFixture(e.target.value);
              setChecked(false);
              setLiveConsent(false);
              command.reset();
            }}
          >
            <option value="mvp-security-v1">핵심 6개 사례</option>
            <option value="security-evaluation-v1">전체 평가 · 공격 40개 + 정상 20개</option>
          </select>
          <label htmlFor="experiment-model-mode">모델 모드</label>
          <select
            id="experiment-model-mode"
            value={modelMode}
            onChange={(event) => {
              setModelMode(event.target.value as 'REPLAY' | 'LIVE');
              setLiveConsent(false);
              setChecked(false);
              command.reset();
            }}
          >
            <option value="REPLAY">REPLAY · 저장된 후보 응답 재생 (기본)</option>
            <option value="LIVE">LIVE · 외부 모델 응답 캡처 (선택 · 비용 가능)</option>
          </select>
          <KeyValues
            items={[
              ['비교 모드', 'PAIRED · 같은 후보 출력을 양쪽에 사용'],
              [
                '모델 모드',
                isLive ? 'LIVE · 사례·반복마다 한 캡처를 양쪽에 공유' : 'REPLAY · 등록된 응답 재생',
              ],
              ['반복 횟수', `${repeatCount}회 (고정)`],
              [
                '환경 실행 계획',
                `${caseCount * 2 * repeatCount}개 · ${caseCount}개 사례 × ${repeatCount}회 × 두 환경`,
              ],
              ['직원 승인 가정', '양쪽에 동일한 Mock 직원 규칙 적용'],
            ]}
          />
          {isLive ? (
            <>
              <div className="notice warning" id="live-cost-warning">
                <div>
                  <strong>외부 모델 호출 비용이 발생할 수 있어요.</strong>
                  <p>
                    선택한 {caseCount}개 사례를 3회씩 실행하며, 사례·반복마다 한 번 캡처한 응답을 두 환경이
                    공유합니다. 지원되지 않는 사례는 제외될 수 있어요.
                  </p>
                  <p>
                    서버에 설정된 모델 제공자에게 등록된 합성 사례 문서와 Mock 확인 자료가 전달됩니다.
                    제공자·모델·요금은 서버 설정에서 확인하세요. 브라우저에는 제공자 키를 입력하지 않습니다.
                  </p>
                  <p>
                    서버의 FUSE_EXPERIMENT_LIVE_ENABLED=true 설정과 제공자 연결이 필요합니다. 요청 접수만으로
                    호출 또는 평가 완료를 뜻하지 않아요.
                  </p>
                </div>
              </div>
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={liveConsent}
                  onChange={(event) => setLiveConsent(event.target.checked)}
                  required
                  aria-describedby="live-cost-warning"
                />
                선택한 사례 입력의 외부 모델 전송과 발생 가능한 비용을 확인했으며 LIVE 실행에 동의합니다.
              </label>
            </>
          ) : (
            <div className="notice info">
              REPLAY는 저장된 합성 후보 응답을 사용하며 이 실험을 위한 외부 모델 호출을 요청하지 않습니다.
              실제 모델 공격 성공률로 해석하지 마세요.
            </div>
          )}
          <p className="field-help">
            호출·캡처 실패와 공격 유도 실패는 양쪽의 공통 평가 분모에서 제외하며 방어 성공으로 세지 않습니다.
          </p>
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={checked}
              onChange={(e) => setChecked(e.target.checked)}
              required
            />
            실험 전용 Mock 업무 실행을 요청합니다.
          </label>
          <div className="form-actions">
            <button className="button secondary" type="button" onClick={onClose}>
              취소
            </button>
            <button className="button primary" type="submit" disabled={!checked || (isLive && !liveConsent)}>
              {isLive ? '비용 확인 후 LIVE 실험 접수' : '비교 실험 접수'}
            </button>
          </div>
        </fieldset>
      </form>
      <CommandFeedback command={command} />
      {command.error instanceof ApiError &&
        command.error.reasonCodes.some(
          (code) =>
            code === 'LIVE_NOT_AVAILABLE' ||
            code.startsWith('CAPTURE_ERROR') ||
            ['MODEL_OUTPUT_INVALID', 'DEPENDENCY_UNAVAILABLE'].includes(code),
        ) && (
          <div className="notice warning" role="note">
            {command.error.reasonCodes.map((code) => (
              <p key={code}>{describeExperimentIssue(code)}</p>
            ))}
          </div>
        )}
    </Modal>
  );
}
