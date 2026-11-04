import { useId, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { ApiError, FuseApi } from '../api';
import type { ExperimentCancelReceipt } from '../types';
import { ErrorNotice, Modal } from './ui';

/** Server EXPERIMENT authorization and stored ownership remain authoritative. */
export function CancelExperiment({ api, id, active, onComplete, onDenied }: {
  api: FuseApi; id: string; active: boolean; onComplete: () => void; onDenied: (error: unknown) => void;
}) {
  const owner = useMemo(() => ({ api, id, running: false }), [api, id]);
  const current = useRef<typeof owner | undefined>(owner);
  const warningId = useId();
  const [view, setView] = useState<{ owner: typeof owner; open: boolean; pending: boolean; error?: unknown; result?: ExperimentCancelReceipt }>({ owner, open: false, pending: false });
  const state = view.owner === owner ? view : { owner, open: false, pending: false };
  useLayoutEffect(() => {
    current.current = owner;
    return () => { if (current.current === owner) current.current = undefined; };
  }, [owner]);
  const recovery = api.unresolvedExperimentCancel(id);
  async function submit() {
    if (current.current !== owner || owner.running || (!active && !api.unresolvedExperimentCancel(id))) return;
    owner.running = true;
    setView({ owner, open: true, pending: true });
    try {
      const result = await api.cancelExperiment(id);
      if (current.current !== owner) return;
      setView({ owner, open: true, pending: false, result });
      try { onComplete(); }
      catch { setView({ owner, open: true, pending: false, result, error: new Error('요청을 처리하지 못했어요.') }); }
    } catch (error) {
      if (current.current !== owner) return;
      setView({ owner, open: true, pending: false, error });
      if (error instanceof ApiError && [401, 403, 404].includes(error.status)) onDenied(error);
    } finally { owner.running = false; }
  }
  if (!active && !recovery && !state.open) return null;
  return <>
    <button className="button" type="button" onClick={() => setView({ ...state, owner, open: true })}>
      {recovery ? '취소 요청 재확인' : '실험 취소 요청'}
    </button>
    {state.open && <Modal title="실험 취소 요청" busy={state.pending} onClose={() => setView({ ...state, owner, open: false })}>
      <p>서버가 현재 권한과 실험 소유자를 확인합니다. 이미 저장된 비교 쌍은 보존하며 실행 중인 제공자의 종료를 보장하지 않습니다.</p>
      <p>대상 실험: {id}</p>
      <ErrorNotice error={state.error} />
      {state.result && <div className="notice info" role="status">
        <p>처리 상태: {state.result.status} · 보존된 비교 쌍: {state.result.completedPairs}</p>
        <p>요청 번호: {state.result.requestId}{state.result.replayed ? ' · 기존 처리 결과' : ''}</p>
      </div>}
      {recovery && <p id={warningId}>원래 빈 입력과 요청 번호로 재확인합니다. 첫 요청이 도착하지 않았다면 이번에 처음 취소될 수 있습니다. 요청 번호: {recovery}</p>}
      {!state.result && <button className="button" type="button" disabled={state.pending || (!active && !recovery)}
        aria-describedby={recovery ? warningId : undefined} onClick={() => void submit()}>
        {state.pending ? '처리 중' : recovery ? '원래 취소 요청 재확인' : '이 실험 취소 요청'}
      </button>}
    </Modal>}
  </>;
}
