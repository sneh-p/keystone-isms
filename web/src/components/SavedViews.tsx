import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Bookmark, X } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi } from "@/lib/hooks";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Menu } from "@/components/ui/dropdown";

/** Your own named filter sets for a register page (filters live in the address). */
export function SavedViews({ page, filters }: { page: "controls" | "tasks"; filters: string[] }) {
  const [params, setParams] = useSearchParams();
  const key = `/views/${page}`;
  const { data } = useApi<{ id: number; name: string; query: string }[]>(key);
  const [naming, setNaming] = useState(false);
  const [name, setName] = useState("");
  const current = new URLSearchParams([...params].filter(([k]) => filters.includes(k))).toString();
  const save = useAction(() => api(key, { body: { name, query: current } }), { success: "View saved.", invalidate: [key], onSuccess: () => { setNaming(false); setName(""); } });
  const del = useAction((id: number) => api(`${key}/${id}`, { method: "DELETE" }), { success: "View deleted.", invalidate: [key] });
  const apply = (q: string) => setParams(new URLSearchParams(q));
  if (naming) {
    return (
      <form className="flex items-center gap-1" onSubmit={(e) => { e.preventDefault(); if (name.trim()) save.mutate(undefined); }}>
        <Input autoFocus aria-label="View name" placeholder="Name this view" className="h-9 w-44" value={name} maxLength={80} onChange={(e) => setName(e.target.value)} />
        <Button size="sm" type="submit" loading={save.isPending} disabled={!name.trim()}>Save</Button>
        <Button size="icon" variant="ghost" type="button" aria-label="Cancel" onClick={() => setNaming(false)}><X /></Button>
      </form>
    );
  }
  return (
    <Menu
      trigger={<Button variant="outline" size="sm" aria-label="Saved views"><Bookmark /> Views{data?.length ? ` (${data.length})` : ""}</Button>}
      items={[
        ...(data ?? []).map((v) => ({ label: v.name, onSelect: () => apply(v.query) })),
        ...((data ?? []).length ? ["sep" as const] : []),
        { label: current ? "Save current filters…" : "Set filters to save a view", onSelect: () => current && setNaming(true) },
        ...(data ?? []).map((v) => ({ label: `Delete “${v.name}”`, danger: true, onSelect: () => { if (confirm(`Delete the view “${v.name}”?`)) del.mutate(v.id); } })),
      ]}
    />
  );
}
