import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError, FuseApi } from './api';
import type { DecisionResponse } from './types';

export function useQuery<T>(load: (signal: AbortSignal) => Promise<T>, enabled = true, interval = 0) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<unknown>();
  const [loading, setLoading] = useState(enabled);
  const [updatedAt, setUpdatedAt] = useState<Date>();
  const [revision, setRevision] = useState(0);
  const reload = useCallback(() => setRevision((n) => n + 1), []);
  useEffect(() => {
    setData(undefined);
    setError(undefined);
    setUpdatedAt(undefined);
  }, [load, enabled]);
  useEffect(() => {
    if (!enabled) {
      setLoading(false);
      return;
    }
    let disposed = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const controller = new AbortController();
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
      disposed = true;
      controller.abort();
      if (timer) clearTimeout(timer);
    };
  }, [load, enabled, interval, revision]);
  const clear = useCallback(() => {
    setData(undefined);
    setUpdatedAt(undefined);
  }, []);
  return { data, error, loading, reload, updatedAt, clear };
}

interface PendingCommand {
  path: string;
  body: unknown;
  actionId: string;
}
/** A transport/5xx failure is uncertain, so retries retain the exact body and action ID. */
export function useCommand(api: FuseApi, onComplete?: (result: DecisionResponse) => void) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>();
  const [result, setResult] = useState<DecisionResponse>();
  const [retryable, setRetryable] = useState(false);
  const request = useRef<PendingCommand | undefined>(undefined);
  const running = useRef(false);
  const active = useRef(true);
  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);
  async function execute(command: PendingCommand) {
    if (running.current) return;
    running.current = true;
    request.current = command;
    setPending(true);
    setError(undefined);
    setResult(undefined);
    setRetryable(false);
    try {
      const response = await api.mutate(command.path, command.body, command.actionId);
      if (active.current) {
        setResult(response);
        request.current = undefined;
        onComplete?.(response);
      }
    } catch (e) {
      if (active.current) {
        setError(e);
        const unresolved = api.unresolved(command.path);
        if (unresolved) request.current = unresolved;
        setRetryable(!!unresolved || (e instanceof ApiError && e.uncertain));
      }
    } finally {
      running.current = false;
      if (active.current) setPending(false);
    }
  }
  return {
    pending,
    error,
    result,
    retryable,
    run: (path: string, body: unknown) => {
      if (!request.current || !retryable) return execute({ path, body, actionId: crypto.randomUUID() });
    },
    retry: () => request.current && execute(request.current),
    reset: () => {
      if (!running.current && !retryable) {
        request.current = undefined;
        setError(undefined);
        setResult(undefined);
        setRetryable(false);
      }
    },
  };
}
