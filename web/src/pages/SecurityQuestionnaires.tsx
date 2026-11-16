import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { BookMarked, CheckCircle2, ChevronLeft, Download, FileUp, Library, MessageSquareText, Plus, Quote, Sparkles, Stamp, Trash2, Undo2 } from "lucide-react";
import { api, downloadUrl, upload } from "@/lib/api";
import { useAction, useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { cn, fmtDate } from "@/lib/utils";
import { Badge, type Tone } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Dialog, Sheet } from "@/components/ui/dialog";
import { Menu } from "@/components/ui/dropdown";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Empty, PageHeader, Progress, Section, Skeleton, Stat } from "@/components/ui/misc";
import { StatusBadge } from "@/components/ui/status";
import { Tabs } from "@/components/ui/tabs";
import { DataTable } from "@/components/ui/table";
import { DateInput } from "@/components/forms";

const CONF: Record<string, { tone: Tone; label: string }> = {
  high: { tone: "good", label: "High confidence" },
  medium: { tone: "primary", label: "Medium confidence" },
  low: { tone: "warning", label: "Low confidence" },
  none: { tone: "critical", label: "No verified source" },
};
const confLabel = (i: any) => (i.confidence === "none" && !i.answer ? "Not covered by sources" : CONF[i.confidence].label);
const ORIGIN: Record<string, string> = { ai: "AI draft", knowledge: "Knowledge base", manual: "Written by a person" };

export default function SecurityQuestionnaires() {
  const { can } = useAuth();
  const nav = useNavigate();
  const { data } = useApi<any[]>("/security-questionnaires");
  const ai = useApi<any>("/ai/status");
  const [creating, setCreating] = useState(false);
  return (
    <div className="animate-fade-in">
      <PageHeader icon={MessageSquareText} title="Security questionnaires" description="Answer customers' security questionnaires from your approved policies and knowledge base. Every answer is reviewed by a person before it is exported."
        actions={can("questionnaire.write") && <Button onClick={() => setCreating(true)}><FileUp /> New questionnaire</Button>} />
      {ai.data && !ai.data.available && (
        <p className="mb-4 rounded-lg border bg-muted/40 px-4 py-3 text-sm text-muted-foreground">AI drafting is off, so answers are written by hand or filled from the knowledge base. {can("ai.manage") ? "You can turn it on under Settings → AI." : "An administrator can turn it on."}</p>
      )}
      <Tabs tabs={[
        { value: "q", label: "Questionnaires", content: !data ? <Skeleton className="h-64" /> : data.length === 0 ? (
          <Empty icon={MessageSquareText} title="No questionnaires yet" action={can("questionnaire.write") && <Button onClick={() => setCreating(true)}><FileUp /> Upload a questionnaire</Button>}>Upload the customer's spreadsheet (.xlsx or .csv). Keystone finds the questions and, when you export, writes the answers back into the same file.</Empty>
        ) : (
          <DataTable rows={data} rowKey={(q: any) => q.id} onRowClick={(q: any) => nav(`/security-questionnaires/${q.id}`)} search={(q: any) => `${q.title} ${q.requester ?? ""}`} columns={[
            { key: "t", header: "Questionnaire", cell: (q: any) => <div><div className="font-medium">{q.title}</div><div className="text-xs text-muted-foreground">{q.requester ?? "—"}</div></div>, sort: (q: any) => q.title },
            { key: "p", header: "Approved", cell: (q: any) => <div className="w-40"><Progress label={`${q.title}: answers approved`} value={q.progress.pct} tone={q.progress.pct === 100 ? "good" : "primary"} /><div className="mt-1 text-xs text-muted-foreground">{q.progress.approved} of {q.progress.total}</div></div>, sort: (q: any) => q.progress.pct },
            { key: "d", header: "Due", cell: (q: any) => fmtDate(q.due_date), sort: (q: any) => q.due_date ?? "" },
            { key: "s", header: "Status", cell: (q: any) => q.job_status === "running" ? <Badge tone="primary"><Sparkles className="size-3" /> Drafting</Badge> : <StatusBadge status={q.status} /> },
          ]} />
        ) },
        { value: "kb", label: "Knowledge base", content: <KnowledgeBase /> },
      ]} />
      {creating && <NewQuestionnaire onClose={() => setCreating(false)} onCreated={(id) => nav(`/security-questionnaires/${id}`)} />}
    </div>
  );
}

function NewQuestionnaire({ onClose, onCreated }: { onClose: () => void; onCreated: (id: number) => void }) {
  const [title, setTitle] = useState("");
  const [requester, setRequester] = useState("");
  const [due, setDue] = useState<string | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [pasted, setPasted] = useState("");
  const create = useAction(() => {
    const fd = new FormData();
    fd.append("title", title);
    if (requester) fd.append("requester", requester);
    if (due) fd.append("due_date", due);
    if (file) fd.append("file", file); else fd.append("pasted", pasted);
    return upload("/security-questionnaires", fd);
  }, { success: (r: any) => `${r.progress.total} questions imported.`, invalidate: ["/security-questionnaires"], onSuccess: (r: any) => onCreated(r.id) });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title="New security questionnaire" description="Upload the customer's file, or paste the questions one per line."
      footer={<Button loading={create.isPending} disabled={!title.trim() || (!file && !pasted.trim())} onClick={() => create.mutate(undefined)}>Import questions</Button>}>
      <div className="space-y-4">
        <Field label="Title" required><Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Contoso vendor security review 2026" /></Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Requested by"><Input value={requester} onChange={(e) => setRequester(e.target.value)} placeholder="Customer name" /></Field>
          <Field label="Due"><DateInput value={due} onChange={setDue} /></Field>
        </div>
        <Field label="Spreadsheet (.xlsx or .csv)" hint="Questions are read from the column headed 'Question'. A column headed 'Answer' or 'Response' is filled in on export.">
          <input type="file" accept=".xlsx,.csv" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="text-sm" />
        </Field>
        {!file && <Field label="Or paste questions"><Textarea className="min-h-28" value={pasted} onChange={(e) => setPasted(e.target.value)} placeholder={"Do you encrypt data at rest?\nDo you run annual penetration tests?"} /></Field>}
      </div>
    </Dialog>
  );
}

type Filter = "all" | "open" | "drafted" | "approved" | "weak";
const FILTERS: { key: Filter; label: string; test: (i: any) => boolean }[] = [
  { key: "all", label: "All", test: () => true },
  { key: "open", label: "Needs an answer", test: (i) => i.status === "open" },
  { key: "drafted", label: "Needs review", test: (i) => i.status === "drafted" },
  { key: "weak", label: "Weak sources", test: (i) => i.status !== "approved" && ["low", "none"].includes(i.confidence) },
  { key: "approved", label: "Approved", test: (i) => i.status === "approved" },
];

export function QuestionnaireDetail() {
  const { id } = useParams();
  const nav = useNavigate();
  const { can } = useAuth();
  const path = `/security-questionnaires/${id}`;
  const q = useQuery<any>({ queryKey: [path], queryFn: () => api(path), refetchInterval: (query) => ((query.state.data as any)?.job_status === "running" ? 2000 : false) });
  const ai = useApi<any>("/ai/status");
  const [filter, setFilter] = useState<Filter>("all");
  const [open, setOpen] = useState<number | null>(null);
  const inv = ["/security-questionnaires"];
  const draft = useAction(() => api(`${path}/ai-draft`, { body: {} }), { success: "Drafting started. Answers appear as they are ready.", invalidate: inv });
  const fill = useAction(() => api(`${path}/fill-from-kb`, { method: "POST" }), { success: (r: any) => (r.filled ? `${r.filled} answer(s) filled from the knowledge base.` : "No close knowledge-base matches for the open questions."), invalidate: inv });
  const status = useAction((s: string) => api(`${path}/status`, { body: { status: s } }), { success: "Status updated.", invalidate: inv });
  const del = useAction(() => api(path, { method: "DELETE" }), { success: "Questionnaire deleted.", invalidate: inv, onSuccess: () => nav("/security-questionnaires") });
  const d = q.data;
  const items = useMemo(() => (d?.items ?? []).filter(FILTERS.find((f) => f.key === filter)!.test), [d, filter]);
  if (!d) return <Skeleton className="h-96" />;
  const running = d.job_status === "running";
  const weak = d.items.filter(FILTERS[3].test).length;
  const editable = d.status === "open";
  return (
    <div className="animate-fade-in">
      <button onClick={() => nav("/security-questionnaires")} className="mb-3 flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"><ChevronLeft className="size-4" /> Security questionnaires</button>
      <PageHeader icon={MessageSquareText} title={d.title} description={[d.requester, d.due_date && `due ${fmtDate(d.due_date)}`, `${d.source_kind === "xlsx" ? "Excel" : d.source_kind === "csv" ? "CSV" : "Pasted"} questionnaire`].filter(Boolean).join(" · ")}
        actions={<>
          {editable && can("questionnaire.write") && ai.data?.available && <Button loading={draft.isPending} disabled={running || !d.progress.open} onClick={() => draft.mutate(undefined)}><Sparkles /> Draft open answers with AI</Button>}
          {editable && can("questionnaire.write") && <Button variant="outline" loading={fill.isPending} disabled={running || !d.progress.open} onClick={() => fill.mutate(undefined)}><Library /> Fill from knowledge base</Button>}
          <Menu trigger={<Button variant="outline"><Download /> Export</Button>} items={[
            { label: "Approved answers (.xlsx)", onSelect: () => { window.location.href = downloadUrl(`${path}/export`); } },
            { label: "Include unapproved drafts (.xlsx)", onSelect: () => { window.location.href = downloadUrl(`${path}/export?include_drafts=true`); } },
          ]} />
          {can("questionnaire.approve") && <Menu trigger={<Button variant="ghost" aria-label="More actions">⋯</Button>} items={[
            editable ? { label: "Mark completed", icon: CheckCircle2, onSelect: () => status.mutate("completed") } : { label: "Reopen", icon: Undo2, onSelect: () => status.mutate("open") },
            "sep",
            { label: "Delete questionnaire", icon: Trash2, danger: true, onSelect: () => { if (confirm("Delete this questionnaire and all its answers?")) del.mutate(undefined); } },
          ]} />}
        </>} />
      {running && (
        <div className="mb-4 rounded-lg border border-primary/30 bg-accent/40 px-4 py-3" role="status" aria-live="polite">
          <div className="flex items-center gap-2 text-sm font-medium"><Sparkles className="size-4 animate-pulse text-primary" /> Drafting answers from your approved policies and knowledge base… {d.job_progress} of {d.job_total}</div>
          <Progress label="AI drafting progress" className="mt-2" value={d.job_total ? (100 * d.job_progress) / d.job_total : 0} />
        </div>
      )}
      {d.job_status === "failed" && <div className="mb-4 rounded-lg border border-critical/30 bg-critical/5 px-4 py-3 text-sm">AI drafting stopped: {d.job_error}</div>}
      <div className="mb-5 grid gap-4 sm:grid-cols-4">
        <Stat label="Approved" value={`${d.progress.approved} / ${d.progress.total}`} tone={d.progress.pct === 100 ? "good" : undefined} hint={<Progress label="Answers approved" value={d.progress.pct} tone="good" />} />
        <Stat label="Need review" value={d.progress.drafted} />
        <Stat label="Need an answer" value={d.progress.open} tone={d.progress.open ? "warning" : undefined} />
        <Stat label="Weak or no source" value={weak} tone={weak ? "critical" : undefined} />
      </div>
      <div className="mb-3 flex flex-wrap gap-2" role="tablist" aria-label="Filter questions">
        {FILTERS.map((f) => {
          const n = d.items.filter(f.test).length;
          return <button key={f.key} role="tab" aria-selected={filter === f.key} onClick={() => setFilter(f.key)} className={cn("rounded-full border px-3 py-1 text-sm transition", filter === f.key ? "border-primary bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-accent")}>{f.label} <span className="ml-1 tabular-nums opacity-70">{n}</span></button>;
        })}
      </div>
      <Card>
        <ul className="divide-y">
          {items.length === 0 && <li className="px-5 py-10 text-center text-sm text-muted-foreground">Nothing in this view.</li>}
          {items.map((it: any) => (
            <li key={it.id}>
              <button onClick={() => setOpen(it.id)} className="flex w-full items-start gap-4 px-5 py-4 text-left transition hover:bg-muted/50">
                <span className="mt-0.5 w-8 shrink-0 text-right font-mono text-xs text-muted-foreground">{it.position}</span>
                <div className="min-w-0 flex-1">
                  {it.section && <div className="mb-0.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">{it.section}</div>}
                  <div className="font-medium">{it.question}</div>
                  {it.answer ? <p className="mt-1 line-clamp-2 text-sm text-muted-foreground">{it.answer}</p> : <p className="mt-1 text-sm italic text-muted-foreground">No answer yet</p>}
                </div>
                <div className="flex shrink-0 flex-col items-end gap-1">
                  <StatusBadge status={it.status} label={it.status === "drafted" ? "Needs review" : undefined} />
                  {it.confidence && it.status !== "approved" && <Badge tone={CONF[it.confidence].tone}>{confLabel(it)}</Badge>}
                </div>
              </button>
            </li>
          ))}
        </ul>
      </Card>
      {open && <ItemSheet item={d.items.find((i: any) => i.id === open)} editable={editable && !running} path={path} onClose={() => setOpen(null)} onNext={() => {
        const idx = items.findIndex((i: any) => i.id === open);
        setOpen(items[idx + 1]?.id ?? null);
      }} />}
    </div>
  );
}

function ItemSheet({ item, editable, path, onClose, onNext }: { item: any; editable: boolean; path: string; onClose: () => void; onNext: () => void }) {
  const { can } = useAuth();
  const [answer, setAnswer] = useState(item?.answer ?? "");
  useEffect(() => setAnswer(item?.answer ?? ""), [item?.id, item?.answer]);
  const sugg = useApi<any[]>(item ? `/questionnaire-items/${item.id}/suggestions` : null);
  const inv = [path];
  const save = useAction(() => api(`/questionnaire-items/${item.id}`, { method: "PATCH", body: { answer } }), { success: "Answer saved.", invalidate: inv });
  const approve = useAction(async () => {
    if (answer !== (item.answer ?? "")) await api(`/questionnaire-items/${item.id}`, { method: "PATCH", body: { answer } });
    return api(`/questionnaire-items/${item.id}/approve`, { method: "POST" });
  }, { success: "Answer approved.", invalidate: inv, onSuccess: onNext });
  const unapprove = useAction(() => api(`/questionnaire-items/${item.id}/unapprove`, { method: "POST" }), { success: "Approval withdrawn.", invalidate: inv });
  const toKb = useAction(() => api(`/questionnaire-items/${item.id}/to-knowledge-base`, { method: "POST" }), { success: "Added to the knowledge base.", invalidate: ["/knowledge-base"] });
  if (!item) return null;
  const approved = item.status === "approved";
  const canEdit = editable && can("questionnaire.write") && !approved;
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={`Question ${item.position}`} subtitle={<span className="flex flex-wrap items-center gap-2"><StatusBadge status={item.status} label={item.status === "drafted" ? "Needs review" : undefined} />{item.origin && <Badge tone="outline">{ORIGIN[item.origin]}</Badge>}{item.confidence && <Badge tone={CONF[item.confidence].tone}>{confLabel(item)}</Badge>}</span>}
      actions={<>
        {approved && can("questionnaire.approve") && <Button size="sm" variant="outline" onClick={() => toKb.mutate(undefined)}><BookMarked /> Add to knowledge base</Button>}
        {approved && editable && can("questionnaire.approve") && <Button size="sm" variant="ghost" onClick={() => unapprove.mutate(undefined)}><Undo2 /> Withdraw approval</Button>}
      </>}>
      <div className="space-y-6">
        <div>
          {item.section && <div className="mb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">{item.section}</div>}
          <p className="text-base font-medium">{item.question}</p>
          {item.sheet && <p className="mt-1 text-xs text-muted-foreground">Sheet “{item.sheet}”, row {item.row}</p>}
        </div>
        {item.note && <div className={cn("rounded-lg border px-4 py-3 text-sm", item.confidence === "none" ? "border-critical/30 bg-critical/5" : "bg-muted/40")}>{item.note}</div>}
        <Field label="Answer">
          <Textarea className="min-h-36" value={answer} readOnly={!canEdit} onChange={(e) => setAnswer(e.target.value)} placeholder="Write the answer to send to the customer" />
        </Field>
        {approved && <p className="text-sm text-muted-foreground">Approved by {item.reviewed_by ?? "—"} on {fmtDate(item.reviewed_at, true)}.</p>}
        {canEdit && (
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" loading={save.isPending} disabled={answer === (item.answer ?? "")} onClick={() => save.mutate(undefined)}>Save</Button>
            {can("questionnaire.approve") && <Button loading={approve.isPending} disabled={!answer.trim()} onClick={() => approve.mutate(undefined)}><Stamp /> Approve and next</Button>}
          </div>
        )}
        <Section title="Sources">
          {item.citations?.length ? (
            <ul className="space-y-2">{item.citations.map((c: any, i: number) => (
              <li key={i} className="rounded-lg border p-3 text-sm">
                <div className="flex items-center gap-2"><Badge tone="primary" className="font-mono text-[10px]">{c.ref}</Badge><span className="font-medium">{c.title}</span></div>
                {c.quote && <blockquote className="mt-2 flex gap-2 border-l-2 border-primary/40 pl-3 text-muted-foreground"><Quote className="mt-0.5 size-3 shrink-0" aria-hidden />{c.quote}</blockquote>}
              </li>
            ))}</ul>
          ) : <p className="text-sm text-muted-foreground">No sources cited.</p>}
        </Section>
        {canEdit && !!sugg.data?.length && (
          <Section title="Similar answers in the knowledge base">
            <ul className="space-y-2">{sugg.data.map((s) => (
              <li key={s.id} className="rounded-lg border p-3 text-sm">
                <div className="flex items-start justify-between gap-2"><span className="font-medium">{s.question}</span><Badge tone="outline">{s.score}% match</Badge></div>
                <p className="mt-1 text-muted-foreground">{s.answer}</p>
                <Button size="sm" variant="ghost" className="mt-1" onClick={() => setAnswer(s.answer)}>Use this answer</Button>
              </li>
            ))}</ul>
          </Section>
        )}
      </div>
    </Sheet>
  );
}

function KnowledgeBase() {
  const { can } = useAuth();
  const { data } = useApi<any[]>("/knowledge-base");
  const [edit, setEdit] = useState<any>(null);
  const inv = ["/knowledge-base"];
  const save = useAction((e: any) => (e.id ? api(`/knowledge-base/${e.id}`, { method: "PATCH", body: { question: e.question, answer: e.answer, tags: e.tags || null } }) : api("/knowledge-base", { body: { question: e.question, answer: e.answer, tags: e.tags || null } })), { success: "Saved. It is used once approved.", invalidate: inv, onSuccess: () => setEdit(null) });
  const approve = useAction((id: number) => api(`/knowledge-base/${id}/approve`, { method: "POST" }), { success: "Approved.", invalidate: inv });
  const del = useAction((id: number) => api(`/knowledge-base/${id}`, { method: "DELETE" }), { success: "Deleted.", invalidate: inv });
  if (!data) return <Skeleton className="h-64" />;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-2xl text-sm text-muted-foreground">Reusable, approved answers. They fill matching questions automatically, are offered as suggestions, and are a source for AI drafts alongside your approved policies.</p>
        {can("questionnaire.write") && <Button onClick={() => setEdit({ question: "", answer: "", tags: "" })}><Plus /> Add answer</Button>}
      </div>
      {data.length === 0 ? <Empty icon={Library} title="The knowledge base is empty">Add answers you give often, or add approved questionnaire answers from the question panel.</Empty> : (
        <DataTable rows={data} rowKey={(e: any) => e.id} search={(e: any) => `${e.question} ${e.answer} ${e.tags ?? ""}`} onRowClick={can("questionnaire.write") ? (e: any) => setEdit({ ...e, tags: e.tags ?? "" }) : undefined} columns={[
          { key: "r", header: "Ref", cell: (e: any) => <span className="font-mono text-xs">KB-{e.id}</span> },
          { key: "q", header: "Question and answer", cell: (e: any) => <div className="max-w-2xl"><div className="font-medium">{e.question}</div><p className="mt-0.5 line-clamp-2 text-sm text-muted-foreground">{e.answer}</p>{e.tags && <div className="mt-1 flex flex-wrap gap-1">{e.tags.split(",").map((t: string) => <Badge key={t} tone="outline">{t.trim()}</Badge>)}</div>}</div> },
          { key: "s", header: "Status", cell: (e: any) => <StatusBadge status={e.status} /> },
          { key: "a", header: "", cell: (e: any) => <div className="flex justify-end gap-1" onClick={(ev) => ev.stopPropagation()}>
            {e.status !== "approved" && can("questionnaire.approve") && <Button size="sm" variant="outline" onClick={() => approve.mutate(e.id)}>Approve</Button>}
            {can("questionnaire.approve") && <Button size="sm" variant="ghost" aria-label="Delete" onClick={() => { if (confirm("Delete this answer?")) del.mutate(e.id); }}><Trash2 /></Button>}
          </div> },
        ]} />
      )}
      <Dialog open={!!edit} onOpenChange={(o) => !o && setEdit(null)} title={edit?.id ? `Edit KB-${edit.id}` : "New knowledge-base answer"} description={edit?.status === "approved" ? "Changing an approved answer sends it back for approval." : undefined}
        footer={<Button loading={save.isPending} onClick={() => save.mutate(edit)}>Save</Button>}>
        {edit && <div className="space-y-4">
          <Field label="Question" required><Textarea value={edit.question} onChange={(e) => setEdit({ ...edit, question: e.target.value })} /></Field>
          <Field label="Answer" required><Textarea className="min-h-32" value={edit.answer} onChange={(e) => setEdit({ ...edit, answer: e.target.value })} /></Field>
          <Field label="Tags" hint="Comma-separated, for example encryption, backups"><Input value={edit.tags} onChange={(e) => setEdit({ ...edit, tags: e.target.value })} /></Field>
        </div>}
      </Dialog>
    </div>
  );
}
