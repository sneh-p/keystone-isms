import { useMemo, useState, type ReactNode } from "react";
import { useLocation, useParams } from "react-router";
import { ClipboardList, Pencil, Plus, Trash2 } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi, usePeople, useUrlFilter } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, Sheet } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Empty, KeyValue, PageHeader, Section, Skeleton } from "@/components/ui/misc";
import { MultiSelect } from "@/components/ui/multiselect";
import { Select } from "@/components/ui/select";
import { DataTable } from "@/components/ui/table";
import { DateInput } from "@/components/forms";
import { Comments } from "@/components/Comments";

type FieldSpec = { key: string; label: string; type: string; required: boolean; listed: boolean; hint?: string; min?: number; max?: number; ref?: string; choices: { value: string; label: string }[] };
type MoveSpec = { to: string; label: string; from: string[]; sod: boolean; needs: string[]; note: boolean; allowed: boolean };
type Spec = {
  key: string; title: string; singular: string; description: string; iso: string; title_label: string; owner: boolean; due: string | null; due_label: string;
  comments: boolean; statuses: { key: string; label: string; tone: string }[]; closed: string[]; initial: string; can_write: boolean; fields: FieldSpec[]; moves: MoveSpec[];
};
type Entry = { id: number; ref: string; title: string; status: string; owner_id: number | null; due_on: string | null; data: Record<string, any>; decisions: any[]; created_by_id: number | null };

/** Labels for the records that register fields point at (people, assets, controls, vendors, other registers). */
function useLookups(spec: Spec | undefined) {
  const types = new Set((spec?.fields ?? []).map((f) => f.type));
  const refs = [...new Set((spec?.fields ?? []).filter((f) => f.type === "entry").map((f) => f.ref as string))];
  const { people: users, name } = usePeople();
  const persons = useApi<any>(types.has("person") ? "/people" : null);
  const assets = useApi<any[]>(types.has("assets") ? "/assets" : null);
  const controls = useApi<any[]>(types.has("controls") ? "/controls" : null);
  const vendors = useApi<any>(types.has("vendors") ? "/vendors" : null);
  const entries = useApi<any>(refs[0] ? `/registers/${refs[0]}` : null);
  return useMemo(() => {
    const opts: Record<string, { value: string; label: string }[]> = {
      user: users.map((u) => ({ value: String(u.id), label: u.display_name })),
      person: (persons.data?.people ?? []).map((p: any) => ({ value: String(p.id), label: p.full_name })),
      assets: (assets.data ?? []).map((a: any) => ({ value: String(a.id), label: a.name })),
      controls: (controls.data ?? []).map((c: any) => ({ value: String(c.id), label: `${c.code} ${c.title}` })),
      vendors: (vendors.data?.vendors ?? []).map((v: any) => ({ value: String(v.id), label: v.name })),
      entry: (entries.data?.entries ?? []).map((e: any) => ({ value: String(e.id), label: `${e.ref} ${e.title}` })),
    };
    const label = (type: string, id: any) => (type === "user" ? name(id) : opts[type]?.find((o) => o.value === String(id))?.label ?? `#${id}`);
    return { opts, label };
  }, [users, name, persons.data, assets.data, controls.data, vendors.data, entries.data]);
}

function showValue(f: FieldSpec, v: any, label: (type: string, id: any) => string): ReactNode {
  if (v === null || v === undefined || v === "" || (Array.isArray(v) && !v.length)) return <span className="text-muted-foreground">—</span>;
  switch (f.type) {
    case "date": return fmtDate(v);
    case "bool": return v ? "Yes" : "No";
    case "choice": return f.choices.find((c) => c.value === v)?.label ?? v;
    case "long": return <span className="whitespace-pre-wrap">{v}</span>;
    case "user": case "person": case "entry": return label(f.type, v);
    case "assets": case "controls": case "vendors": return (v as number[]).map((id) => label(f.type, id)).join(", ");
    default: return String(v);
  }
}

/** A register declared on the server (keystone/registers/spec.py): its table, a record panel with its workflow, and a form. */
export default function RegisterPage() {
  const params = useParams();
  const { pathname } = useLocation();
  const key = params.key ?? pathname.split("/").pop() ?? "";
  const { data, isError } = useApi<{ register: Spec; entries: Entry[] }>(`/registers/${key}`);
  const [open, setOpen] = useUrlFilter("open");
  const [editing, setEditing] = useState<Entry | "new" | null>(null);
  const spec = data?.register;
  const { label } = useLookups(spec);
  const { name } = usePeople();
  if (isError) return <Empty title="Register not found">It may not exist, or your role can't see it.</Empty>;
  if (!data || !spec) return <Skeleton className="h-96" />;
  const status = (k: string) => spec.statuses.find((s) => s.key === k);
  const current = open ? data.entries.find((e) => String(e.id) === open) : undefined;
  const listed = spec.fields.filter((f) => f.listed);
  return (
    <div className="animate-fade-in">
      <PageHeader icon={ClipboardList} title={spec.title} description={<>{spec.description}{spec.iso && <span className="block text-xs">ISO/IEC 27001: {spec.iso}</span>}</>}
        actions={spec.can_write && <Button onClick={() => setEditing("new")}><Plus /> New {spec.singular}</Button>} />
      <DataTable rows={data.entries} rowKey={(e) => e.id} onRowClick={(e) => setOpen(String(e.id))} exportName={spec.key} empty={`No ${spec.title.toLowerCase()} yet.`}
        search={(e) => `${e.ref} ${e.title} ${listed.map((f) => String(e.data[f.key] ?? "")).join(" ")}`}
        columns={[
          { key: "t", header: spec.title_label, cell: (e) => <span><span className="font-medium">{e.title}</span><span className="block font-mono text-xs text-muted-foreground">{e.ref}</span></span> },
          ...listed.filter((f) => f.key !== spec.due).map((f) => ({ key: f.key, header: f.label, cell: (e: Entry) => showValue(f, e.data[f.key], label) })),
          ...(spec.owner ? [{ key: "owner", header: "Owner", cell: (e: Entry) => (e.owner_id ? name(e.owner_id) : <span className="text-muted-foreground">No owner</span>) }] : []),
          ...(spec.due ? [{ key: "due", header: spec.due_label, cell: (e: Entry) => (e.due_on ? <span className={!spec.closed.includes(e.status) && e.due_on < new Date().toISOString().slice(0, 10) ? "font-medium text-critical" : undefined}>{fmtDate(e.due_on)}</span> : "—") }] : []),
          { key: "s", header: "Status", cell: (e) => <Badge tone={(status(e.status)?.tone ?? "neutral") as any}>{status(e.status)?.label ?? e.status}</Badge> },
        ]} />
      {current && <EntryPanel spec={spec} entry={current} onClose={() => setOpen(null)} onEdit={() => setEditing(current)} label={label} />}
      {editing && <EntryForm spec={spec} entry={editing === "new" ? null : editing} onClose={() => setEditing(null)} onSaved={(id) => { setEditing(null); setOpen(String(id)); }} />}
    </div>
  );
}

function EntryPanel({ spec, entry, onClose, onEdit, label }: { spec: Spec; entry: Entry; onClose: () => void; onEdit: () => void; label: (type: string, id: any) => string }) {
  const { name } = usePeople();
  const [moving, setMoving] = useState<MoveSpec | null>(null);
  const [note, setNote] = useState("");
  const inv = [`/registers`, "/calendar", "/exceptions", "/dashboard"];
  const move = useAction(() => api(`/registers/${spec.key}/${entry.id}/move`, { body: { to: moving!.to, note: note || null } }),
    { success: "Saved.", invalidate: inv, onSuccess: () => { setMoving(null); setNote(""); } });
  const remove = useAction(() => api(`/registers/${spec.key}/${entry.id}`, { method: "DELETE" }), { success: "Deleted.", invalidate: inv, onSuccess: onClose });
  const { me } = useAuth();
  const closed = spec.closed.includes(entry.status);
  const available = spec.moves.filter((m) => m.from.includes(entry.status) && m.allowed);
  // Decisions the person who raised the record can't take (segregation of duties) are left out, with a note why.
  const own = !!me && entry.created_by_id === me.id;
  const moves = available.filter((m) => !(m.sod && own));
  const waiting = available.some((m) => m.sod && own);
  const st = spec.statuses.find((s) => s.key === entry.status);
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={`${entry.ref} · ${entry.title}`} subtitle={<Badge tone={(st?.tone ?? "neutral") as any}>{st?.label ?? entry.status}</Badge>}
      actions={spec.can_write && !closed && <Button size="sm" variant="outline" onClick={onEdit}><Pencil /> Edit</Button>}>
      <div className="space-y-6">
        {waiting && <p className="rounded-md border bg-muted/40 px-3 py-2 text-sm text-muted-foreground">You raised this {spec.singular}, so someone else decides it.</p>}
        {moves.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {moves.map((m) => <Button key={m.to + m.label} size="sm" variant={/reject|concern|issue/i.test(m.label) ? "outline" : "default"} onClick={() => setMoving(m)}>{m.label}</Button>)}
          </div>
        )}
        <KeyValue items={[
          ...(spec.owner ? [["Owner", entry.owner_id ? name(entry.owner_id) : "No owner"] as [ReactNode, ReactNode]] : []),
          ...spec.fields.map((f) => [f.label, showValue(f, entry.data[f.key], label)] as [ReactNode, ReactNode]),
          ["Raised by", entry.created_by_id ? name(entry.created_by_id) : "—"],
        ]} />
        {entry.decisions.length > 0 && (
          <Section title="Decisions" level={3}>
            <ol className="space-y-2 text-sm">
              {entry.decisions.map((d, i) => (
                <li key={i} className="rounded-md border px-3 py-2">
                  <span className="font-medium">{spec.statuses.find((s) => s.key === d.to)?.label ?? d.to}</span>
                  <span className="text-muted-foreground"> · {d.by} · {fmtDate(d.at)}</span>
                  {d.note && <p className="mt-1 whitespace-pre-wrap text-muted-foreground">{d.note}</p>}
                </li>
              ))}
            </ol>
          </Section>
        )}
        {spec.can_write && entry.status === spec.initial && entry.decisions.length === 0 && (
          <Button size="sm" variant="ghost" className="text-critical" onClick={() => { if (window.confirm(`Delete ${entry.ref}? Only for records created by mistake.`)) remove.mutate(undefined); }}><Trash2 /> Delete</Button>
        )}
        {spec.comments && <Comments kind="register_entry" id={entry.id} />}
      </div>
      {moving && (
        <Dialog open onOpenChange={(o) => !o && setMoving(null)} title={`${moving.label}: ${entry.title}`}
          description={moving.sod ? `Segregation of duties: whoever raised this ${spec.singular} can't do this.` : undefined}
          footer={<Button disabled={moving.note && !note.trim()} loading={move.isPending} onClick={() => move.mutate(undefined)}>{moving.label}</Button>}>
          <Field label={moving.note ? "Note (required)" : "Note"} hint={moving.needs.length ? `Needs: ${moving.needs.map((k) => spec.fields.find((f) => f.key === k)?.label).join(", ")}.` : undefined}>
            <Textarea value={note} onChange={(e) => setNote(e.target.value)} maxLength={2000} />
          </Field>
        </Dialog>
      )}
    </Sheet>
  );
}

function EntryForm({ spec, entry, onClose, onSaved }: { spec: Spec; entry: Entry | null; onClose: () => void; onSaved: (id: number) => void }) {
  const { opts } = useLookups(spec);
  const [title, setTitle] = useState(entry?.title ?? "");
  const [owner, setOwner] = useState<string | null>(entry?.owner_id ? String(entry.owner_id) : null);
  const [v, setV] = useState<Record<string, any>>({ ...(entry?.data ?? {}) });
  const save = useAction(() => {
    const fields = Object.fromEntries(spec.fields.map((f) => [f.key, v[f.key] === "" ? null : v[f.key] ?? null]));
    const body = { title, ...(spec.owner ? { owner_id: owner ? Number(owner) : null } : {}), fields };
    return entry ? api<Entry>(`/registers/${spec.key}/${entry.id}`, { method: "PATCH", body }) : api<Entry>(`/registers/${spec.key}`, { body });
  }, { success: "Saved.", invalidate: ["/registers", "/calendar", "/exceptions"], onSuccess: (e) => onSaved(e.id) });
  const set = (k: string, value: any) => setV((cur) => ({ ...cur, [k]: value }));
  const input = (f: FieldSpec) => {
    const val = v[f.key];
    switch (f.type) {
      case "long": return <Textarea value={val ?? ""} onChange={(e) => set(f.key, e.target.value)} maxLength={8000} />;
      case "date": return <DateInput ariaLabel={f.label} value={val ?? null} onChange={(x) => set(f.key, x)} />;
      case "bool": return <span className="flex items-center gap-2 text-sm"><input type="checkbox" aria-label={f.label} checked={!!val} onChange={(e) => set(f.key, e.target.checked)} /> Yes</span>;
      case "int": return <Input type="number" min={f.min} max={f.max} value={val ?? ""} onChange={(e) => set(f.key, e.target.value === "" ? null : Number(e.target.value))} />;
      case "choice": return <Select ariaLabel={f.label} value={val ?? null} allowEmpty={!f.required} onChange={(x) => set(f.key, x)} options={f.choices} placeholder="Choose…" />;
      case "user": case "person": case "entry":
        return <Select ariaLabel={f.label} value={val != null ? String(val) : null} allowEmpty={!f.required} onChange={(x) => set(f.key, x ? Number(x) : null)} options={opts[f.type] ?? []} placeholder="Choose…" />;
      case "assets": case "controls": case "vendors":
        return <MultiSelect value={(val ?? []).map(String)} onChange={(x) => set(f.key, x.map(Number))} options={opts[f.type] ?? []} placeholder="None" />;
      default: return <Input value={val ?? ""} maxLength={f.max ?? 300} onChange={(e) => set(f.key, e.target.value)} />;
    }
  };
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} wide title={entry ? `Edit ${entry.ref}` : `New ${spec.singular}`}
      footer={<Button disabled={!title.trim()} loading={save.isPending} onClick={() => save.mutate(undefined)}>{entry ? "Save" : "Create"}</Button>}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={spec.title_label} required className="sm:col-span-2"><Input value={title} maxLength={300} onChange={(e) => setTitle(e.target.value)} /></Field>
        {spec.owner && <Field label="Owner"><Select ariaLabel="Owner" value={owner} allowEmpty emptyLabel="No owner" onChange={setOwner} options={opts.user} /></Field>}
        {spec.fields.map((f) => (
          <Field key={f.key} label={f.label} required={f.required} hint={f.hint} className={f.type === "long" || f.type === "assets" || f.type === "controls" ? "sm:col-span-2" : undefined}>
            {input(f)}
          </Field>
        ))}
      </div>
    </Dialog>
  );
}
