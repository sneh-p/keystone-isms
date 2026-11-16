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
