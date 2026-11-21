import { useState } from "react";
import { CheckSquare, Download, FileUp, Plus, Square } from "lucide-react";
import { api, saveDownload, upload } from "@/lib/api";
import { useAction, usePeople } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Section } from "@/components/ui/misc";
import { DateInput, OwnerSelect } from "@/components/forms";

const INV = ["/incidents", "/dashboard", "/calendar"];

/** The category's playbook (ISO/IEC 27035 response) and response actions with owners and due dates. */
export function IncidentResponse({ incident }: { incident: any }) {
  const { can } = useAuth();
  const { name } = usePeople();
  const ed = can("incident.write") && incident.status !== "closed";
  const [add, setAdd] = useState<{ title: string; owner_id: number | null; due_date: string | null } | null>(null);
  const tick = useAction((v: { index: number; done: boolean }) => api(`/incidents/${incident.id}/playbook`, { body: v }), { invalidate: INV });
  const done = useAction((v: { id: number; done: boolean }) => api(`/incident-actions/${v.id}/done`, { body: { done: v.done } }), { invalidate: INV });
  const save = useAction(() => api(`/incidents/${incident.id}/actions`, { body: add }), { success: "Action added.", invalidate: INV, onSuccess: () => setAdd(null) });
  const today = new Date().toISOString().slice(0, 10);
  return (
    <>
      {incident.playbook.length > 0 && (
        <Section title="Playbook">
          <ul className="space-y-1">
            {incident.playbook.map((s: any) => (
              <li key={s.index}>
                <button type="button" disabled={!ed} onClick={() => tick.mutate({ index: s.index, done: !s.done })}
                  className="flex w-full items-start gap-2 rounded-md px-2 py-1.5 text-left text-sm hover:bg-muted/50 disabled:cursor-default disabled:hover:bg-transparent">
                  {s.done ? <CheckSquare className="mt-0.5 size-4 shrink-0 text-good-fg" aria-label="Done" /> : <Square className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-label="Not done" />}
                  <span className={s.done ? "text-muted-foreground line-through" : ""}>{s.step}</span>
                  {s.done && <span className="ml-auto shrink-0 text-xs text-muted-foreground">{s.done.by}</span>}
                </button>
              </li>
            ))}
          </ul>
        </Section>
      )}
      <Section title="Response actions" action={ed && <Button size="sm" variant="outline" onClick={() => setAdd({ title: "", owner_id: incident.owner_id, due_date: null })}><Plus /> Add</Button>}>
        {incident.actions.length === 0 ? <p className="text-sm text-muted-foreground">No actions yet. Open actions must be done before the incident closes as resolved.</p> : (
          <ul className="divide-y rounded-md border">
            {incident.actions.map((a: any) => (
              <li key={a.id} className="flex items-center justify-between gap-3 px-3 py-2 text-sm">
                <label className="flex min-w-0 items-center gap-2">
                  <input type="checkbox" checked={a.status === "done"} disabled={!can("incident.write")} onChange={(e) => done.mutate({ id: a.id, done: e.target.checked })} />
                  <span className={a.status === "done" ? "text-muted-foreground line-through" : ""}>{a.title}</span>
                </label>
                <span className="shrink-0 text-xs text-muted-foreground">{name(a.owner_id)}{a.due_date && <> · <span className={a.status === "open" && a.due_date < today ? "font-medium text-critical" : ""}>due {fmtDate(a.due_date)}</span></>}</span>
              </li>
            ))}
          </ul>
        )}
      </Section>
      {add && (
        <Dialog open onOpenChange={(o) => !o && setAdd(null)} title="Add a response action" footer={<Button disabled={!add.title.trim()} loading={save.isPending} onClick={() => save.mutate(undefined)}>Add</Button>}>
          <div className="space-y-4">
            <Field label="Action" required><Input value={add.title} onChange={(e) => setAdd({ ...add, title: e.target.value })} placeholder="e.g. Reset the finance team's passwords" /></Field>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Owner"><OwnerSelect value={add.owner_id} onChange={(v) => setAdd({ ...add, owner_id: v })} /></Field>
              <Field label="Due"><DateInput ariaLabel="Due" value={add.due_date} onChange={(v) => setAdd({ ...add, due_date: v })} /></Field>
            </div>
          </div>
        </Dialog>
      )}
    </>
  );
}

/** Evidence collected during the incident (A.5.28): hash at collection, source, and chain of custody. */
export function IncidentEvidence({ incident }: { incident: any }) {
  const { can } = useAuth();
  const ed = can("incident.write");
  const [adding, setAdding] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [description, setDescription] = useState("");
  const [source, setSource] = useState("");
  const [custody, setCustody] = useState<any>(null);
  const add = useAction(async () => {
    const fd = new FormData();
    fd.append("file", file as File);
    fd.append("description", description);
    if (source.trim()) fd.append("source", source.trim());
    return upload(`/incidents/${incident.id}/evidence`, fd);
  }, { success: "Evidence stored with its hash.", invalidate: INV, onSuccess: () => { setAdding(false); setFile(null); setDescription(""); setSource(""); } });
  const download = useAction((e: any) => saveDownload(`/incident-evidence/${e.id}/download`), { invalidate: INV });
  if (!ed) return null;
  return (
    <Section title={`Evidence (${incident.evidence.length})`} action={<Button size="sm" variant="outline" onClick={() => setAdding(true)}><FileUp /> Add</Button>}>
      {incident.evidence.length === 0 ? <p className="text-sm text-muted-foreground">No evidence collected. Files are hashed when added, and every download is recorded.</p> : (
        <ul className="divide-y rounded-md border">
          {incident.evidence.map((e: any) => (
            <li key={e.id} className="space-y-1 px-3 py-2 text-sm">
              <div className="flex items-center justify-between gap-3">
                <span className="min-w-0 truncate font-medium">{e.filename}</span>
                <span className="flex shrink-0 gap-1">
                  <Button size="sm" variant="ghost" onClick={() => setCustody(e)}>Custody ({e.custody.length})</Button>
                  <Button size="icon" variant="ghost" aria-label={`Download ${e.filename}`} onClick={() => download.mutate(e)}><Download /></Button>
                </span>
              </div>
              <div className="text-xs">{e.description}</div>
              <div className="break-all font-mono text-xs text-muted-foreground">SHA-256 {e.sha256}</div>
              <div className="text-xs text-muted-foreground">Collected {fmtDate(e.collected_at, true)} by {e.collected_by}{e.source ? ` · from ${e.source}` : ""}</div>
            </li>
          ))}
        </ul>
      )}
      {adding && (
        <Dialog open onOpenChange={(o) => !o && setAdding(false)} title="Add evidence" description="Keystone stores the file's SHA-256 now and checks it again on every download."
          footer={<Button disabled={!file || !description.trim()} loading={add.isPending} onClick={() => add.mutate(undefined)}>Store</Button>}>
          <div className="space-y-4">
            <Field label="File" required><input type="file" aria-label="Evidence file" className="text-sm" onChange={(e) => setFile(e.target.files?.[0] ?? null)} /></Field>
            <Field label="What it is" required><Textarea value={description} onChange={(e) => setDescription(e.target.value)} placeholder="e.g. Firewall log export for 14:00-16:00 UTC" /></Field>
            <Field label="Where it came from" hint="System, who exported it, how."><Input value={source} onChange={(e) => setSource(e.target.value)} /></Field>
          </div>
        </Dialog>
      )}
      {custody && (
        <Dialog open onOpenChange={(o) => !o && setCustody(null)} title={`Chain of custody: ${custody.filename}`}>
          <ol className="space-y-2 text-sm">
            {custody.custody.map((c: any, i: number) => <li key={i} className="rounded-md border px-3 py-2"><Badge tone="outline">{fmtDate(c.at, true)}</Badge> <span className="font-medium">{c.by}</span>: {c.action}</li>)}
          </ol>
        </Dialog>
      )}
    </Section>
  );
}
