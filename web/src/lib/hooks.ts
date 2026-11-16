import { useCallback, useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient, type QueryKey } from "@tanstack/react-query";
import { toast } from "sonner";
import { api } from "./api";

export function useApi<T = any>(path: string | null, key?: QueryKey) {
  return useQuery<T>({ queryKey: key ?? [path], queryFn: () => api<T>(path as string), enabled: !!path });
}

/** Mutation that toasts errors/success and refetches everything under the given keys. */
export function useAction<V = any, R = any>(fn: (v: V) => Promise<R>, opts: { success?: string | ((r: R) => string); invalidate?: string[]; onSuccess?: (r: R) => void } = {}) {
  const qc = useQueryClient();
  return useMutation<R, Error, V>({
    mutationFn: fn,
    onSuccess: (r) => {
      if (opts.success) toast.success(typeof opts.success === "function" ? opts.success(r) : opts.success);
      (opts.invalidate ?? [""]).forEach((k) => { void qc.invalidateQueries({ predicate: (q) => String(q.queryKey[0] ?? "").startsWith(k) }); });
      opts.onSuccess?.(r);
    },
    onError: (e) => toast.error(e.message),
  });
}

export type Person = { id: number; display_name: string; role: string };

export function usePeople() {
  const q = useApi<Person[]>("/people-directory");
  const byId = new Map((q.data ?? []).map((p) => [p.id, p.display_name]));
  return { people: q.data ?? [], name: (id?: number | null) => (id ? byId.get(id) ?? `User ${id}` : "—") };
}

/**
 * Warns before unsaved edits are lost: `confirmDiscard()` asks when `dirty`, and leaving or reloading the page
 * triggers the browser's own prompt.
 */
export function useUnsavedGuard(dirty: boolean) {
  useEffect(() => {
    if (!dirty) return;
    const fn = (e: BeforeUnloadEvent) => { e.preventDefault(); };
    window.addEventListener("beforeunload", fn);
    return () => window.removeEventListener("beforeunload", fn);
  }, [dirty]);
  return () => !dirty || window.confirm("Discard your unsaved changes?");
}

/** One filter kept in the URL query string (shareable, and linkable from the dashboard). */
export function useUrlFilter(key: string) {
  const [params, setParams] = useSearchParams();
  const set = useCallback((v: string | null) => setParams((prev) => {
    const next = new URLSearchParams(prev);
    if (v) next.set(key, v); else next.delete(key);
    return next;
  }), [key, setParams]);
  return [params.get(key), set] as const;
}
