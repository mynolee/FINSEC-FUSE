import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { ApiError, FuseApi } from './api';
import type { DecisionResponse } from './types';

export function useQuery<T>(load: (signal: AbortSignal) => Promise<T>, enabled = true, interval = 0) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<unknown>();
  const [loading, setLoading] = useState(enabled);
  const [updatedAt, setUpdatedAt] = useState<Date>();
  const [revision, setRevision] = useState(0);
  const [viewIdentity, setViewIdentity] = useState({ load, enabled });
  const committedIdentity = useRef({ load, enabled });
  // An abandoned concurrent render must not retire the still-committed query.
  // Layout effects run only on commit, before passive cleanup and async callbacks.
  useLayoutEffect(() => {
    committedIdentity.current = { load, enabled };
  }, [load, enabled]);
  type QueryIdentity = { load: typeof load; enabled: boolean; revision: number };
  const owner = useRef<(QueryIdentity & { dispose: () => void }) | undefined>(undefined);
  const suspended = useRef<QueryIdentity | undefined>(undefined);
  const mounted = useRef(false);
  useLayoutEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      owner.current?.dispose();
    };
  }, []);
  const reload = useCallback(() => {
    if (!mounted.current) return;
    owner.current?.dispose();
    suspended.current = undefined;
    setRevision((n) => n + 1);
  }, []);
  useEffect(() => {
    setViewIdentity({ load, enabled });
    setData(undefined);
    setError(undefined);
    setUpdatedAt(undefined);
  }, [load, enabled]);
  useEffect(() => {
    const paused = suspended.current;
    if (paused && paused.load === load && paused.enabled === enabled && paused.revision === revision) {
      setLoading(false);
      return;
    }
    suspended.current = undefined;
    if (!enabled) {
      setLoading(false);
      return;
    }
    let disposed = false;
    const isCurrent = () => mounted.current && !disposed && committedIdentity.current.load === load && committedIdentity.current.enabled === enabled;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const controller = new AbortController();
    const current = {
      load,
      enabled,
      revision,
      dispose: () => {
        // Retire ownership before abort: completed or abort-ignoring loads stay inert.
        disposed = true;
        controller.abort();
        if (timer) clearTimeout(timer);
      },
    };
    owner.current = current;
    async function fetchOnce() {
      if (!isCurrent()) return;
      setLoading(true);
      try {
        const result = await load(controller.signal);
        if (isCurrent()) {
          setData(result);
          setError(undefined);
          setUpdatedAt(new Date());
        }
      } catch (e) {
        if (isCurrent() && !(e instanceof DOMException && e.name === 'AbortError')) {
          setError(e);
          if (e instanceof ApiError && [401, 403, 404].includes(e.status)) {
            setData(undefined);
            setUpdatedAt(undefined);
          }
        }
      } finally {
        if (isCurrent()) {
          setLoading(false);
          if (interval) timer = setTimeout(fetchOnce, interval);
        }
      }
    }
    void fetchOnce();
    return () => {
      current.dispose();
      if (owner.current === current) owner.current = undefined;
    };
  }, [load, enabled, interval, revision]);
  const clear = useCallback(() => {
    if (!mounted.current) return;
    const current = owner.current;
    if (current) {
      suspended.current = current;
      current.dispose();
    }
    setData(undefined);
    setUpdatedAt(undefined);
    setLoading(false);
  }, []);
  const ownsView = viewIdentity.load === load && viewIdentity.enabled === enabled;
  return {
    data: ownsView ? data : undefined,
    error: ownsView ? error : undefined,
    loading: ownsView ? loading : enabled,
    reload,
    updatedAt: ownsView ? updatedAt : undefined,
    clear,
  };
}

interface PendingCommand {
  path: string;
  body: unknown;
  actionId: string;
}
/** A transport/5xx failure is uncertain, so retries retain the exact body and action ID. */
export function useCommand(api: FuseApi, onComplete?: (result: DecisionResponse) => void, scope?: string) {
  const owner = useMemo(
    () => ({
      api,
      scope,
      request: scope ? api.unresolved(scope) : (undefined as PendingCommand | undefined),
      running: false,
      active: true,
    }),
    [api, scope],
  );
  type View = {
    owner: typeof owner;
    pending: boolean;
    error?: unknown;
    result?: DecisionResponse;
    retryable: boolean;
  };
  const [state, setState] = useState<View>({ owner, pending: false, retryable: !!owner.request });
  // A new API session or endpoint must never display or execute the previous owner's command.
  const currentOwner = useRef(owner);
  const view: View = state.owner === owner ? state : { owner, pending: false, retryable: !!owner.request };
  useLayoutEffect(() => {
    // Speculative/suspended renders cannot retire the committed command owner.
    currentOwner.current = owner;
    owner.active = true;
    // Retire before any replacement layout effect can invoke a retained callback.
    return () => { owner.active = false; };
  }, [owner]);
  const current = () => owner.active && currentOwner.current === owner;
  async function execute(command: PendingCommand) {
    if (!current() || owner.running) return;
    owner.running = true;
    owner.request = command;
    // Keep the recovery context visible while its exact request is being retried.
    setState({ owner, pending: true, retryable: view.retryable });
    try {
      const response = await api.mutate(command.path, command.body, command.actionId);
      if (current()) {
        owner.request = undefined;
        setState({ owner, pending: false, retryable: false, result: response });
        try {
          onComplete?.(response);
        } catch {
          // A local completion callback cannot change a definitive server receipt
          // into an unknown mutation or discard its original request identity.
          if (current()) setState({
            owner, pending: false, retryable: false, result: response,
            error: new Error('요청을 처리하지 못했어요.'),
          });
        }
      }
    } catch (error) {
      if (current()) {
        const unresolved = api.unresolved(command.path);
        if (unresolved) owner.request = unresolved;
        setState({
          owner,
          pending: false,
          error,
          retryable: !!unresolved || (error instanceof ApiError && error.uncertain),
        });
      }
    } finally {
      owner.running = false;
    }
  }
  return {
    pending: view.pending,
    error: view.error,
    result: view.result,
    retryable: view.retryable,
    retryRequest:
      view.retryable && owner.request
        ? { ...owner.request, body: JSON.parse(JSON.stringify(owner.request.body)) as unknown }
        : undefined,
    run: (path: string, body: unknown) => {
      if (scope && path !== scope) return;
      if (!owner.request || !view.retryable) return execute({ path, body, actionId: crypto.randomUUID() });
    },
    retry: () => (current() && view.retryable && owner.request ? execute(owner.request) : undefined),
    reset: () => {
      if (current() && !owner.running && !view.retryable) {
        owner.request = undefined;
        setState({ owner, pending: false, retryable: false });
      }
    },
  };
}
