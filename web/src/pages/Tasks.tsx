import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { CalendarClock, Check, Columns3, List, ListChecks, Paperclip, Play, Plus, Repeat, Send, Undo2, X } from "lucide-react";
import { api, downloadUrl, upload } from "@/lib/api";
import { useAction, useApi, usePeople, useUrlFilter } from "@/lib/hooks";
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
import { Select } from "@/components/ui/select";
import { DateInput, EnumSelect, OwnerSelect } from "@/components/forms";

const COLS = [
  { key: "todo", label: "To do" },
  { key: "in_progress", label: "In progress" },
  { key: "in_review", label: "In review" },
  { key: "done", label: "Done" },
];
const FREQ = ["once", "monthly", "quarterly", "semiannual", "yearly"];

const DUE = [
  { value: "overdue", label: "Overdue" },
  { value: "7", label: "Due in 7 days" },
  { value: "30", label: "Due in 30 days" },
  { value: "90", label: "Due in 90 days" },
  { value: "none", label: "No due date" },
];

function dueMatch(t: any, window: string | null): boolean {
  if (!window) return true;
  if (window === "overdue") return !!t.overdue;
  if (window === "none") return !t.due_date;
  if (!t.due_date || t.overdue) return false;
  return new Date(t.due_date).getTime() - Date.now() <= Number(window) * 864e5;
}

const monthOf = (d: string | null) => (d ? new Date(d).toLocaleDateString(undefined, { month: "long", year: "numeric" }) : "No due date");

export default function Tasks() {
  const { can, me } = useAuth();
  const { people, name } = usePeople();
  const [, setParams] = useSearchParams();
  const [openId, setOpenId] = useUrlFilter("open");
  const [assignee, setAssignee] = useUrlFilter("assignee");
  const [framework, setFramework] = useUrlFilter("framework");
  const [control, setControl] = useUrlFilter("control");
  const [due, setDue] = useUrlFilter("due");
  const [view, setView] = useState<"board" | "list">("board");
  const [selected, setSelected] = useState<Set<string | number>>(new Set());
  const { data } = useApi<any[]>("/tasks");
  const controls = useApi<any[]>("/controls");
  const [nt, setNt] = useState<any>(null);
  const create = useAction((b: any) => api("/tasks", { body: b }), { success: "Task created.", invalidate: ["/tasks", "/dashboard"], onSuccess: (r: any) => { setNt(null); setOpenId(String(r.id)); } });
  const ctlFrameworks = useMemo(() => new Map((controls.data ?? []).map((c) => [c.id, Object.keys(c.frameworks)])), [controls.data]);
  const frameworks = useMemo(() => [...new Set((controls.data ?? []).flatMap((c) => Object.keys(c.frameworks)))].sort(), [controls.data]);
  const rows = useMemo(() => (data ?? []).filter((t) =>
    (!assignee || (assignee === "none" ? !t.assignee_id : String(t.assignee_id) === (assignee === "me" ? String(me?.id) : assignee)))
    && (!framework || t.controls.some((c: any) => ctlFrameworks.get(c.id)?.includes(framework)))
    && (!control || t.controls.some((c: any) => String(c.id) === control))
    && dueMatch(t, due)), [data, assignee, framework, control, due, ctlFrameworks, me]);
  if (!data) return <Skeleton className="h-96" />;
  const open = rows.filter((t) => ["todo", "in_progress", "in_review"].includes(t.status));
  const doneRecent = rows.filter((t) => t.status === "done").slice(-20);
  const filtered = !!(assignee || framework || control || due);
  const editable = can("task.write");
  const card = (t: any) => (
    <button key={t.id} onClick={() => setOpenId(String(t.id))} className="w-full rounded-md border bg-card p-3 text-left shadow-sm transition-shadow hover:shadow-md">
      <div className="text-sm font-medium leading-snug">{t.title}</div>
      <div className="mt-2 flex flex-wrap gap-1">{t.controls.slice(0, 3).map((x: any) => <Badge key={x.id} tone="primary" className="font-mono text-[10px]">{x.code}</Badge>)}{t.controls.length > 3 && <Badge tone="outline">+{t.controls.length - 3}</Badge>}</div>
      <div className="mt-2 flex items-center justify-between text-xs text-muted-foreground">
        <span className="flex items-center gap-1">{t.frequency !== "once" && <Repeat className="size-3" aria-hidden />}{titleCase(t.frequency)}</span>
        <span className={cn("flex items-center gap-1", t.overdue && "font-medium text-critical")}><CalendarClock className="size-3" aria-hidden />{t.overdue && "Overdue · "}{fmtDate(t.due_date)}</span>
      </div>
      <div className="mt-1 text-xs text-muted-foreground">{t.assignee_id ? name(t.assignee_id) : "Unassigned"}</div>
    </button>
  );
  return (
    <div className="animate-fade-in">
      <PageHeader icon={ListChecks} title="Tasks" description="Recurring compliance work that produces evidence for your controls. Approved tasks file their evidence automatically and schedule the next occurrence."
        actions={<>
          <div className="flex rounded-md border p-0.5" role="group" aria-label="View">
            <button onClick={() => setView("board")} className={cn("rounded px-2 py-1", view === "board" && "bg-muted")} aria-label="Board view" aria-pressed={view === "board"}><Columns3 className="size-4" /></button>
            <button onClick={() => setView("list")} className={cn("rounded px-2 py-1", view === "list" && "bg-muted")} aria-label="List view" aria-pressed={view === "list"}><List className="size-4" /></button>
          </div>
          <Button variant={assignee === "me" ? "secondary" : "outline"} onClick={() => setAssignee(assignee === "me" ? null : "me")}>{assignee === "me" ? "Showing my tasks" : "Show my tasks"}</Button>
          {editable && <Button onClick={() => setNt({ title: "", description: "", frequency: "once", assignee_id: me?.id, due_date: null, control_ids: [] })}><Plus /> New task</Button>}
        </>} />
      <div className="mb-5 grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
        <Stat label="Open" value={open.length} hint={filtered ? "Matching the filters" : undefined} />
        <Stat label="Overdue" value={open.filter((t) => t.overdue).length} tone={open.some((t) => t.overdue) ? "critical" : undefined} to="/tasks?due=overdue" />
        <Stat label="Waiting for review" value={open.filter((t) => t.status === "in_review").length} />
        <Stat label="Due in 30 days" value={open.filter((t) => dueMatch(t, "30")).length} to="/tasks?due=30" />
      </div>
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="min-w-0 basis-[calc(50%-0.25rem)] sm:basis-auto sm:w-44"><Select value={assignee} onChange={setAssignee} allowEmpty emptyLabel="Anyone" placeholder="Assignee" ariaLabel="Assignee" options={[{ value: "me", label: "Me" }, { value: "none", label: "Unassigned" }, ...people.map((p) => ({ value: String(p.id), label: p.display_name }))]} /></div>
        <div className="min-w-0 basis-[calc(50%-0.25rem)] sm:basis-auto sm:w-44"><Select value={framework} onChange={setFramework} allowEmpty emptyLabel="All frameworks" placeholder="Framework" ariaLabel="Framework" options={frameworks.map((f) => ({ value: f, label: f.replace(/_/g, " ") }))} /></div>
        <div className="min-w-0 basis-[calc(50%-0.25rem)] sm:basis-auto sm:w-56"><Select value={control} onChange={setControl} allowEmpty emptyLabel="All controls" placeholder="Control" ariaLabel="Control" options={(controls.data ?? []).map((c) => ({ value: String(c.id), label: `${c.code} ${c.title}` }))} /></div>
        <div className="min-w-0 basis-[calc(50%-0.25rem)] sm:basis-auto sm:w-44"><Select value={due} onChange={setDue} allowEmpty emptyLabel="Any due date" placeholder="Due" ariaLabel="Due" options={DUE} /></div>
        {filtered && <Button variant="ghost" size="sm" onClick={() => setParams((p) => { const n = new URLSearchParams(p); ["assignee", "framework", "control", "due"].forEach((k) => n.delete(k)); return n; })}><X /> Clear filters</Button>}
      </div>
      {data.length === 0 ? <Empty icon={ListChecks} title="No tasks yet" action={<Link to="/onboarding"><Button>Run setup to generate tasks</Button></Link>}>The setup wizard schedules recurring evidence tasks for your controls.</Empty> : view === "board" ? (
        <div className="grid gap-4 lg:grid-cols-4">
          {COLS.map((c) => {
            const items = c.key === "done" ? doneRecent : open.filter((t) => t.status === c.key);
            const months = c.key === "done" ? [] : [...new Set(items.map((t) => monthOf(t.due_date)))];
            return (
              <section key={c.key} aria-label={c.label} className="rounded-lg bg-muted/40 p-2">
                <h2 className="mb-2 flex items-center justify-between px-2 pt-1 text-sm font-medium">{c.label}<span className="rounded-full bg-card px-2 text-xs text-muted-foreground">{items.length}</span></h2>
                {months.length > 1 ? (
                  <div className="space-y-3">
                    {months.map((m) => (
                      <div key={m}>
                        <h3 className="mb-1.5 px-2 text-xs font-medium text-muted-foreground">{m}</h3>
                        <div className="space-y-2">{items.filter((t) => monthOf(t.due_date) === m).map(card)}</div>
                      </div>
                    ))}
                  </div>
                ) : <div className="space-y-2">{items.map(card)}</div>}
              </section>
            );
          })}
        </div>
      ) : (
        <DataTable rows={rows} rowKey={(t: any) => t.id} rowLabel={(t: any) => t.title} onRowClick={(t: any) => setOpenId(String(t.id))} search={(t: any) => `${t.title} ${t.controls.map((c: any) => c.code).join(" ")}`}
          selected={editable ? selected : undefined} onSelectedChange={editable ? setSelected : undefined}
          bulkBar={(ids) => <BulkTasks ids={ids as number[]} rows={rows} onDone={() => setSelected(new Set())} />}
          columns={[
          { key: "t", header: "Task", cell: (t: any) => <div><div className="font-medium">{t.title}</div><div className="text-xs text-muted-foreground">{t.controls.map((c: any) => c.code).join(", ")}</div></div>, sort: (t: any) => t.title },
          { key: "f", header: "Frequency", cell: (t: any) => titleCase(t.frequency) },
          { key: "a", header: "Assignee", cell: (t: any) => (t.assignee_id ? name(t.assignee_id) : <span className="text-muted-foreground">Unassigned</span>), sort: (t: any) => name(t.assignee_id) },
          { key: "d", header: "Due", cell: (t: any) => <span className={t.overdue ? "font-medium text-critical" : ""}>{t.overdue && "Overdue · "}{fmtDate(t.due_date)}</span>, sort: (t: any) => t.due_date ?? "9" },
          { key: "s", header: "Status", cell: (t: any) => <StatusBadge status={t.status} />, sort: (t: any) => t.status },
        ]} />
      )}
      {nt && <NewTask t={nt} setT={setNt} onSave={() => create.mutate({ ...nt, control_ids: nt.control_ids.map(Number) })} busy={create.isPending} />}
      {openId && <TaskDrawer id={Number(openId)} onClose={() => setOpenId(null)} />}
    </div>
  );
}

function BulkTasks({ ids, rows, onDone }: { ids: number[]; rows: any[]; onDone: () => void }) {
  const { people } = usePeople();
  const [assignee, setAssignee] = useState<string | null>(null);
  const [due, setDue] = useState<string | null>(null);
  const closed = rows.filter((t) => ids.includes(t.id) && ["done", "not_relevant"].includes(t.status)).length;
  const run = useAction((body: any) => api<{ updated: number }>("/tasks/bulk", { method: "POST", body }), {
    success: (r) => `${r.updated} task${r.updated === 1 ? "" : "s"} updated.`, invalidate: ["/tasks", "/dashboard"], onSuccess: onDone,
  });
  const body: any = { ids };
  if (assignee) body.assignee_id = assignee === "none" ? null : Number(assignee);
  if (due) body.due_date = due;
  return (
    <>
      <div className="min-w-0 basis-[calc(50%-0.25rem)] sm:basis-auto sm:w-48"><Select value={assignee} onChange={setAssignee} allowEmpty emptyLabel="Keep assignee" placeholder="Set assignee…" ariaLabel="Set assignee for selected tasks" options={[{ value: "none", label: "Unassign" }, ...people.map((p) => ({ value: String(p.id), label: p.display_name }))]} /></div>
      <div className="w-44"><DateInput value={due} onChange={setDue} ariaLabel="Set due date for selected tasks" /></div>
      <Button size="sm" disabled={(!assignee && !due) || closed > 0} loading={run.isPending} onClick={() => run.mutate(body)}>Apply to {ids.length}</Button>
      {closed > 0 && <span className="text-xs text-muted-foreground">{closed} completed task{closed === 1 ? " is" : "s are"} selected; completed tasks can't change.</span>}
    </>
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
