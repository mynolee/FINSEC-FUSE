import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ApiError, FuseApi } from './api';
import type { DecisionResponse } from './types';

export function useQuery<T>(load: (signal: AbortSignal) => Promise<T>, enabled = true, interval = 0) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<unknown>();
  const [loading, setLoading] = useState(enabled);
  const [updatedAt, setUpdatedAt] = useState<Date>();
  const [revision, setRevision] = useState(0);
  type QueryIdentity = { load: typeof load; enabled: boolean; revision: number };
  const owner = useRef<(QueryIdentity & { dispose: () => void }) | undefined>(undefined);
  const suspended = useRef<QueryIdentity | undefined>(undefined);
  const reload = useCallback(() => {
    owner.current?.dispose();
    suspended.current = undefined;
    setRevision((n) => n + 1);
  }, []);
  useEffect(() => {
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
      setLoading(true);
      try {
        const result = await load(controller.signal);
        if (!disposed) {
          setData(result);
          setError(undefined);
          setUpdatedAt(new Date());
        }
      } catch (e) {
        if (!disposed && !(e instanceof DOMException && e.name === 'AbortError')) {
          setError(e);
          if (e instanceof ApiError && [401, 403, 404].includes(e.status)) {
            setData(undefined);
            setUpdatedAt(undefined);
          }
        }
      } finally {
        if (!disposed) {
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
    const current = owner.current;
    if (current) {
      suspended.current = current;
      current.dispose();
    }
    setData(undefined);
    setUpdatedAt(undefined);
    setLoading(false);
  }, []);
  return { data, error, loading, reload, updatedAt, clear };
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
  currentOwner.current = owner;
  const view: View = state.owner === owner ? state : { owner, pending: false, retryable: !!owner.request };
  useEffect(() => {
    owner.active = true;
    return () => {
      owner.active = false;
    };
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
        onComplete?.(response);
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
