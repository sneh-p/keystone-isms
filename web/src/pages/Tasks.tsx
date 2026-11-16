import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { CalendarClock, Check, Columns3, List, ListChecks, Paperclip, Play, Plus, Repeat, Send, Undo2, X } from "lucide-react";
import { api, downloadUrl, upload } from "@/lib/api";
import { useAction, useApi, usePeople } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { cn, fmtDate, titleCase } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, Sheet } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Empty, PageHeader, Section, Skeleton, Stat } from "@/components/ui/misc";
import { MultiSelect } from "@/components/ui/multiselect";
import { StatusBadge } from "@/components/ui/status";
import { DataTable } from "@/components/ui/table";
import { DateInput, EnumSelect, OwnerSelect } from "@/components/forms";

const COLS = [
  { key: "todo", label: "To do" },
  { key: "in_progress", label: "In progress" },
  { key: "in_review", label: "In review" },
  { key: "done", label: "Done" },
];
const FREQ = ["once", "monthly", "quarterly", "semiannual", "yearly"];

export default function Tasks() {
  const { can, me } = useAuth();
  const { name } = usePeople();
  const [params, setParams] = useSearchParams();
  const [mine, setMine] = useState(false);
  const [view, setView] = useState<"board" | "list">("board");
  const { data } = useApi<any[]>(`/tasks?mine=${mine}`, ["/tasks", mine]);
  const [nt, setNt] = useState<any>(null);
  const create = useAction((b: any) => api("/tasks", { body: b }), { success: "Task created.", invalidate: ["/tasks", "/dashboard"], onSuccess: (r: any) => { setNt(null); setParams({ open: String(r.id) }); } });
  if (!data) return <Skeleton className="h-96" />;
  const open = data.filter((t) => ["todo", "in_progress", "in_review"].includes(t.status));
  const doneRecent = data.filter((t) => t.status === "done").slice(-20);
  return (
    <div className="animate-fade-in">
      <PageHeader icon={ListChecks} title="Tasks" description="Recurring compliance work that produces evidence for your controls. Approved tasks file their evidence automatically and schedule the next occurrence."
        actions={<>
          <div className="flex rounded-md border p-0.5">
            <button onClick={() => setView("board")} className={cn("rounded px-2 py-1", view === "board" && "bg-muted")} aria-label="Board view"><Columns3 className="size-4" /></button>
            <button onClick={() => setView("list")} className={cn("rounded px-2 py-1", view === "list" && "bg-muted")} aria-label="List view"><List className="size-4" /></button>
          </div>
          <Button variant={mine ? "secondary" : "outline"} onClick={() => setMine(!mine)}>{mine ? "Showing my tasks" : "Show my tasks"}</Button>
          {can("task.write") && <Button onClick={() => setNt({ title: "", description: "", frequency: "once", assignee_id: me?.id, due_date: null, control_ids: [] })}><Plus /> New task</Button>}
        </>} />
      <div className="mb-5 grid gap-4 sm:grid-cols-4">
        <Stat label="Open" value={open.length} />
        <Stat label="Overdue" value={open.filter((t) => t.overdue).length} tone={open.some((t) => t.overdue) ? "critical" : undefined} />
        <Stat label="Waiting for review" value={open.filter((t) => t.status === "in_review").length} />
        <Stat label="Due in 30 days" value={open.filter((t) => t.due_date && !t.overdue && new Date(t.due_date).getTime() - Date.now() < 30 * 864e5).length} />
      </div>
      {data.length === 0 ? <Empty icon={ListChecks} title="No tasks yet" action={<Link to="/onboarding"><Button>Run setup to generate tasks</Button></Link>}>The setup wizard schedules recurring evidence tasks for your controls.</Empty> : view === "board" ? (
        <div className="grid gap-4 lg:grid-cols-4">
          {COLS.map((c) => {
            const items = c.key === "done" ? doneRecent : open.filter((t) => t.status === c.key);
            return (
              <div key={c.key} className="rounded-lg bg-muted/40 p-2">
                <div className="mb-2 flex items-center justify-between px-2 pt-1 text-sm font-medium">{c.label}<span className="rounded-full bg-card px-2 text-xs text-muted-foreground">{items.length}</span></div>
                <div className="space-y-2">
                  {items.map((t) => (
                    <button key={t.id} onClick={() => setParams({ open: String(t.id) })} className="w-full rounded-md border bg-card p-3 text-left shadow-sm transition-shadow hover:shadow-md">
                      <div className="text-sm font-medium leading-snug">{t.title}</div>
                      <div className="mt-2 flex flex-wrap gap-1">{t.controls.slice(0, 3).map((x: any) => <Badge key={x.id} tone="primary" className="font-mono text-[10px]">{x.code}</Badge>)}{t.controls.length > 3 && <Badge tone="outline">+{t.controls.length - 3}</Badge>}</div>
                      <div className="mt-2 flex items-center justify-between text-xs text-muted-foreground">
                        <span className="flex items-center gap-1">{t.frequency !== "once" && <Repeat className="size-3" />}{titleCase(t.frequency)}</span>
                        <span className={cn("flex items-center gap-1", t.overdue && "font-medium text-critical")}><CalendarClock className="size-3" />{fmtDate(t.due_date)}</span>
                      </div>
                      <div className="mt-1 text-xs text-muted-foreground">{name(t.assignee_id)}</div>
                    </button>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <DataTable rows={data} rowKey={(t: any) => t.id} onRowClick={(t: any) => setParams({ open: String(t.id) })} search={(t: any) => `${t.title} ${t.controls.map((c: any) => c.code).join(" ")}`} columns={[
          { key: "t", header: "Task", cell: (t: any) => <div><div className="font-medium">{t.title}</div><div className="text-xs text-muted-foreground">{t.controls.map((c: any) => c.code).join(", ")}</div></div>, sort: (t: any) => t.title },
          { key: "f", header: "Frequency", cell: (t: any) => titleCase(t.frequency) },
          { key: "a", header: "Assignee", cell: (t: any) => name(t.assignee_id), sort: (t: any) => name(t.assignee_id) },
          { key: "d", header: "Due", cell: (t: any) => <span className={t.overdue ? "font-medium text-critical" : ""}>{fmtDate(t.due_date)}</span>, sort: (t: any) => t.due_date ?? "9" },
          { key: "s", header: "Status", cell: (t: any) => <StatusBadge status={t.status} />, sort: (t: any) => t.status },
        ]} />
      )}
      {nt && <NewTask t={nt} setT={setNt} onSave={() => create.mutate({ ...nt, control_ids: nt.control_ids.map(Number) })} busy={create.isPending} />}
      {params.get("open") && <TaskDrawer id={Number(params.get("open"))} onClose={() => setParams({})} />}
    </div>
  );
}

function NewTask({ t, setT, onSave, busy }: any) {
  const controls = useApi<any[]>("/controls");
  return (
    <Dialog open onOpenChange={(o) => !o && setT(null)} title="New task" wide footer={<Button loading={busy} onClick={onSave}>Create task</Button>}>
      <div className="grid gap-4 sm:grid-cols-3">
        <Field label="Title" required className="sm:col-span-3"><Input value={t.title} onChange={(e) => setT({ ...t, title: e.target.value })} /></Field>
        <Field label="Frequency"><EnumSelect value={t.frequency} onChange={(v) => setT({ ...t, frequency: v })} values={FREQ} /></Field>
        <Field label="Assignee"><OwnerSelect value={t.assignee_id} onChange={(v) => setT({ ...t, assignee_id: v })} /></Field>
        <Field label="Due"><DateInput value={t.due_date} onChange={(v) => setT({ ...t, due_date: v })} /></Field>
        <Field label="Description" className="sm:col-span-3"><Textarea value={t.description} onChange={(e) => setT({ ...t, description: e.target.value })} /></Field>
        <Field label="Produces evidence for" className="sm:col-span-3"><MultiSelect value={t.control_ids} onChange={(v) => setT({ ...t, control_ids: v })} options={(controls.data ?? []).map((c) => ({ value: String(c.id), label: `${c.code} ${c.title}` }))} /></Field>
      </div>
    </Dialog>
  );
}

function TaskDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const { can, me } = useAuth();
  const { name } = usePeople();
  const { data } = useApi<any>(`/tasks/${id}`);
  const [notes, setNotes] = useState<string | null>(null);
  const [comment, setComment] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const inv = ["/tasks", "/dashboard", "/controls", "/evidence"];
  const start = useAction(() => api(`/tasks/${id}/start`, { method: "POST" }), { invalidate: inv });
  const attach = useAction(async () => { const fd = new FormData(); fd.append("file", file as File); return upload(`/tasks/${id}/attachments`, fd); }, { success: "File attached.", invalidate: inv, onSuccess: () => setFile(null) });
  const submit = useAction(() => api(`/tasks/${id}/submit`, { body: { notes: notes ?? data?.completion_notes ?? "" } }), { success: "Submitted for review.", invalidate: inv });
  const approve = useAction(() => api(`/tasks/${id}/approve`, { body: { comment: comment || null } }), { success: "Approved. Evidence filed and next occurrence scheduled.", invalidate: inv });
  const ret = useAction(() => api(`/tasks/${id}/return`, { body: { comment } }), { success: "Returned to assignee.", invalidate: inv });
  const nr = useAction(() => api(`/tasks/${id}/not-relevant`, { body: { comment } }), { success: "Marked not relevant.", invalidate: inv });
  if (!data) return <Sheet open onOpenChange={(o) => !o && onClose()} title="Loading…"><Skeleton className="h-64" /></Sheet>;
  const openState = ["todo", "in_progress"].includes(data.status);
  const reviewer = can("task.approve") && data.status === "in_review" && me?.id !== data.submitted_by_id && me?.id !== data.assignee_id;
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={data.title} subtitle={<span className="flex items-center gap-2"><StatusBadge status={data.status} />{titleCase(data.frequency)} · due {fmtDate(data.due_date)} · {name(data.assignee_id)}</span>}
      actions={data.status === "todo" && can("task.write") && <Button size="sm" variant="outline" onClick={() => start.mutate(undefined)}><Play /> Start</Button>}>
      <div className="space-y-6">
        {data.description && <p className="text-sm">{data.description}</p>}
        {data.evidence_hint && <div className="rounded-lg border border-primary/20 bg-accent/50 px-4 py-3 text-sm"><span className="font-medium">Evidence to provide:</span> {data.evidence_hint}</div>}
        {data.review_comment && <div className="rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm"><span className="font-medium">Reviewer:</span> {data.review_comment}</div>}
        <Section title="Controls">
          <div className="flex flex-wrap gap-2">{data.controls.map((c: any) => <Link key={c.id} to={`/controls?open=${c.id}`}><Badge tone="primary">{c.code} · {c.title}</Badge></Link>)}</div>
        </Section>
        <Section title="Evidence">
          {data.attachments.length > 0 && <ul className="mb-3 divide-y rounded-md border">{data.attachments.map((a: any) => <li key={a.id} className="flex items-center justify-between px-3 py-2 text-sm"><span className="flex items-center gap-2"><Paperclip className="size-4 text-muted-foreground" />{a.filename}</span><a href={downloadUrl(`/attachments/${a.id}`)} className="text-primary hover:underline">Download</a></li>)}</ul>}
          {openState && can("task.write") && (
            <div className="space-y-3">
              <div className="flex items-center gap-2"><input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="text-sm" /><Button size="sm" variant="outline" disabled={!file} loading={attach.isPending} onClick={() => attach.mutate(undefined)}>Attach</Button></div>
              <Field label="Notes for the reviewer"><Textarea value={notes ?? data.completion_notes ?? ""} onChange={(e) => setNotes(e.target.value)} placeholder="What did you do, and what does the evidence show?" /></Field>
              <Button loading={submit.isPending} onClick={() => submit.mutate(undefined)}><Send /> Submit for review</Button>
            </div>
          )}
          {!openState && data.completion_notes && <p className="whitespace-pre-wrap rounded-md bg-muted p-3 text-sm">{data.completion_notes}</p>}
        </Section>
        {data.status === "in_review" && (
          <Section title="Review">
            {reviewer ? (
              <div className="space-y-3">
                <Textarea placeholder="Comment (required to return)" value={comment} onChange={(e) => setComment(e.target.value)} />
                <div className="flex flex-wrap gap-2"><Button loading={approve.isPending} onClick={() => approve.mutate(undefined)}><Check /> Approve</Button><Button variant="outline" onClick={() => ret.mutate(undefined)}><Undo2 /> Return</Button><Button variant="ghost" onClick={() => nr.mutate(undefined)}><X /> Not relevant</Button></div>
              </div>
            ) : <p className="text-sm text-muted-foreground">Submitted {fmtDate(data.submitted_at, true)} by {name(data.submitted_by_id)}. A reviewer other than the assignee approves it.</p>}
          </Section>
        )}
        {data.status === "done" && <p className="text-sm text-muted-foreground">Approved {fmtDate(data.approved_at, true)} by {name(data.approved_by_id)}{data.review_comment ? `: ${data.review_comment}` : "."}</p>}
        {data.status === "not_relevant" && <p className="text-sm text-muted-foreground">Not relevant: {data.not_relevant_reason}</p>}
      </div>
    </Sheet>
  );
}
