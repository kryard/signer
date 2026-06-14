import { useCallback, useEffect, useRef, useState } from "react";
import { getErrorMessage } from "./format";

export interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  reload: () => void;
}

/**
 * Tiny data-fetching hook: runs `fn` whenever `deps` change, exposes
 * loading/error/reload, and ignores stale responses from superseded runs.
 */
export function useAsync<T>(fn: () => Promise<T>, deps: readonly unknown[]): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const runIdRef = useRef(0);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  useEffect(() => {
    const runId = ++runIdRef.current;
    setLoading(true);
    setError(null);
    fnRef
      .current()
      .then((result) => {
        if (runIdRef.current !== runId) return;
        setData(result);
        setLoading(false);
      })
      .catch((err: unknown) => {
        if (runIdRef.current !== runId) return;
        setError(getErrorMessage(err));
        setLoading(false);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);

  return { data, loading, error, reload };
}
