import { useState } from "react";
import { Copy, Download, Eye, FileText, MoreHorizontal, Pencil, Plus, Trash2, Upload, Users, X } from "lucide-react";
import { api, downloadUrl, upload } from "@/lib/api";
import { useAction, useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Menu } from "@/components/ui/dropdown";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Section, Skeleton, Switch } from "@/components/ui/misc";
import { MultiSelect } from "@/components/ui/multiselect";
import { Select } from "@/components/ui/select";
import { DataTable } from "@/components/ui/table";
import { DateInput } from "@/components/forms";
import { Markdown } from "@/components/Markdown";

export type Audience = { departments: string[]; employment_types: string[] } | null;

/** Describes an audience in words: "Everyone", or "Finance, IT · contractors". */
export function audienceText(a: Audience): string {
  if (!a || (!a.departments.length && !a.employment_types.length)) return "Everyone";
  return [a.departments.join(", "), a.employment_types.map((t) => `${t}s`).join(", ")].filter(Boolean).join(" · ");
}

/** Pick departments and employment types; nothing picked means everyone. */
export function AudienceEditor({ value, onChange }: { value: Audience; onChange: (a: Audience) => void }) {
  const { data: departments } = useApi<string[]>("/audience/departments");
  const a = value ?? { departments: [], employment_types: [] };
  const set = (patch: Partial<NonNullable<Audience>>) => {
    const next = { ...a, ...patch };
    onChange(next.departments.length || next.employment_types.length ? next : null);
  };
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <Field label="Departments" hint="From the People register. None: all departments.">
        <MultiSelect value={a.departments} onChange={(v) => set({ departments: v })} options={(departments ?? []).map((d) => ({ value: d, label: d }))} placeholder="All departments" />
      </Field>
      <Field label="Employment type"><MultiSelect value={a.employment_types} onChange={(v) => set({ employment_types: v })} options={[{ value: "employee", label: "Employees" }, { value: "contractor", label: "Contractors" }]} placeholder="Everyone" /></Field>
    </div>
  );
}

const INV = ["/training", "/people", "/dashboard", "/portal"];

/**
 * Security awareness training (ISO 27001 A.6.3): the modules (Keystone's built-in ones and your own), who takes each
 * one and how soon, switching modules off, and training people did elsewhere.
 */
export function TrainingAssignments() {
  const { can } = useAuth();
  const manage = can("people.write");
  const { data } = useApi<any>("/training/assignments");
  const [assign, setAssign] = useState<any>(null);
  const [editing, setEditing] = useState<string | "new" | null>(null);
  const save = useAction(() => api(`/training/assignments/${assign.key}`, { method: "PUT", body: { audience: assign.audience, due_days: Number(assign.due_days) } }),
    { success: "Assignment saved.", invalidate: INV, onSuccess: () => setAssign(null) });
  const toggle = useAction((m: any) => api(`/training/modules/${m.key}/active`, { method: "PUT", body: { active: !m.active } }),
    { success: (r: any) => (r.active ? "Module switched on." : "Module switched off: it's no longer offered or due."), invalidate: INV });
  const copy = useAction((key: string) => api<any>(`/training/modules/${key}/copy`, { method: "POST" }),
    { success: "Your copy is ready to edit. The built-in module is switched off; passes carry over until you save a new version.", invalidate: INV, onSuccess: (r: any) => setEditing(r.key) });
  const remove = useAction((key: string) => api(`/training/modules/${key}`, { method: "DELETE" }), { success: "Module deleted.", invalidate: INV });
  if (!data) return <Skeleton className="h-64" />;
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-3xl text-sm text-muted-foreground">
          Keystone comes with six modules; add your own, or copy a built-in one to change it. Each module applies to everyone unless you limit it (click a row).
          A pass is valid for a year, and a new version of a module asks for it again. Switched-off modules aren't offered or due.
        </p>
        <div className="flex flex-wrap gap-2">
          <a href={downloadUrl("/training/matrix.xlsx")}><Button variant="outline"><Download /> Training matrix</Button></a>
          {manage && <Button onClick={() => setEditing("new")}><Plus /> New module</Button>}
        </div>
      </div>
      <DataTable rows={data.modules} rowKey={(m: any) => m.key} onRowClick={manage ? (m: any) => setAssign({ ...m }) : undefined} columns={[
        { key: "t", header: "Module", cell: (m: any) => (
          <span className={m.active ? undefined : "opacity-60"}>
            <span className="flex flex-wrap items-center gap-1.5"><span className="font-medium">{m.title}</span>
              <Badge tone={m.source === "custom" ? "primary" : "outline"}>{m.source === "custom" ? "Your own" : "Built-in"}</Badge></span>
            <span className="block text-xs text-muted-foreground">v{m.version} · {m.minutes} min · {m.questions} questions{m.copied_from ? " · copied from the built-in module" : ""}</span>
          </span>
        ) },
        { key: "a", header: "Who", cell: (m: any) => <span className="flex items-center gap-1.5"><Users className="size-4 text-muted-foreground" />{audienceText(m.audience)}</span> },
        { key: "d", header: "Due within", cell: (m: any) => `${m.due_days} days of starting` },
        { key: "o", header: "Overdue", cell: (m: any) => (data.overdue[m.title] && m.active ? <Badge tone="critical">{data.overdue[m.title]} people</Badge> : <span className="text-muted-foreground">None</span>) },
        { key: "on", header: "On", cell: (m: any) => (
          // The switch and menu act on the module, not the row (a row click opens "who and when").
          <span className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.stopPropagation()} role="presentation">
            <Switch checked={m.active} disabled={!manage || toggle.isPending} onChange={() => toggle.mutate(m)} label={<span className="sr-only">{m.active ? `Switch off ${m.title}` : `Switch on ${m.title}`}</span>} />
            {manage && (
              <Menu trigger={<Button size="icon" variant="ghost" aria-label={`More for ${m.title}`}><MoreHorizontal /></Button>} items={m.source === "custom" ? [
                { label: "Edit content and quiz", icon: Pencil, onSelect: () => setEditing(m.key) },
                { label: "Who and when", icon: Users, onSelect: () => setAssign({ ...m }) },
                "sep",
                { label: "Delete", icon: Trash2, danger: true, onSelect: () => { if (window.confirm(`Delete ${m.title}? This can't be undone. Once anyone has taken it, switch it off instead.`)) remove.mutate(m.key); } },
              ] : [
                { label: "View content", icon: Eye, onSelect: () => setEditing(m.key) },
                { label: "Make your own copy", icon: Copy, onSelect: () => copy.mutate(m.key) },
                { label: "Who and when", icon: Users, onSelect: () => setAssign({ ...m }) },
              ]} />
            )}
          </span>
        ) },
      ]} />
      {assign && (
        <Dialog open onOpenChange={(o) => !o && setAssign(null)} title={`Who and when: ${assign.title}`} footer={<Button loading={save.isPending} onClick={() => save.mutate(undefined)}>Save</Button>}>
          <div className="space-y-4">
            <AudienceEditor value={assign.audience} onChange={(audience) => setAssign({ ...assign, audience })} />
            <Field label="Days to complete it after starting" className="max-w-xs"><Input type="number" min={1} max={365} value={assign.due_days} onChange={(e) => setAssign({ ...assign, due_days: e.target.value })} /></Field>
          </div>
        </Dialog>
      )}
      {editing && <ModuleEditor moduleKey={editing === "new" ? null : editing} onClose={() => setEditing(null)} />}
      {manage && <ExternalTraining modules={data.modules} />}
    </div>
  );
}

type Question = { q: string; options: string[]; answer: number };
type ModuleForm = { title: string; summary: string; minutes: number | string; body: string; quiz: Question[]; pass_mark: number | string; retake: boolean };

const BLANK: ModuleForm = { title: "", summary: "", minutes: 5, body: "## What this covers\n\n", quiz: [{ q: "", options: ["", ""], answer: 0 }], pass_mark: 1, retake: false };

/** Write or change one of your own modules; built-in ones open read-only (copy them to change them). */
function ModuleEditor({ moduleKey, onClose }: { moduleKey: string | null; onClose: () => void }) {
  const { data } = useApi<any>(moduleKey ? `/training/modules/${moduleKey}` : null);
  const [f, setF] = useState<ModuleForm | null>(moduleKey ? null : BLANK);
  const [preview, setPreview] = useState(false);
  if (!f && data) setF({ title: data.title, summary: data.summary, minutes: data.minutes, body: data.body, quiz: data.quiz, pass_mark: data.pass_mark, retake: false });
  const readOnly = data?.source === "builtin";
  const body = () => ({ ...f!, minutes: Number(f!.minutes), pass_mark: Number(f!.pass_mark), quiz: f!.quiz.map((q) => ({ ...q, options: q.options.map((o) => o.trim()) })) });
  const save = useAction(() => (moduleKey ? api(`/training/modules/${moduleKey}`, { method: "PUT", body: body() }) : api("/training/modules", { body: body() })),
    { success: (r: any) => (moduleKey ? (r.version > (data?.version ?? 0) ? `Saved as version ${r.version}: everyone it applies to takes it again.` : "Module saved.") : "Module created. It's switched on for everyone; limit it with Who and when."),
      invalidate: INV, onSuccess: onClose });
  if (!f) return null;
  const setQ = (i: number, patch: Partial<Question>) => setF({ ...f, quiz: f.quiz.map((q, j) => (j === i ? { ...q, ...patch } : q)) });
  const ready = f.title.trim() && f.summary.trim() && f.body.trim() && f.quiz.every((q) => q.q.trim() && q.options.length >= 2 && q.options.every((o) => o.trim()));
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} extraWide title={moduleKey ? (readOnly ? `${f.title} (built-in)` : `Edit: ${f.title}`) : "New training module"}
      description={readOnly ? "Built-in modules can't be changed. Use Make your own copy in the module's menu to start an editable copy." : "Employees read the content, then answer the quiz. The right answers stay on the server."}
      footer={readOnly ? <Button variant="outline" onClick={onClose}>Close</Button> : (
        <div className="flex w-full flex-wrap items-center justify-between gap-3">
          {moduleKey ? <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={f.retake} onChange={(e) => setF({ ...f, retake: e.target.checked })} /> New version: everyone takes it again</label> : <span />}
          <Button disabled={!ready} loading={save.isPending} onClick={() => save.mutate(undefined)}>{moduleKey ? "Save" : "Create module"}</Button>
        </div>
      )}>
      <fieldset disabled={readOnly} className="space-y-5">
        <div className="grid gap-4 sm:grid-cols-[1fr_9rem]">
          <Field label="Title" required><Input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} placeholder="e.g. Building access and visitors" /></Field>
          <Field label="Minutes"><Input type="number" min={1} max={240} value={f.minutes} onChange={(e) => setF({ ...f, minutes: e.target.value })} /></Field>
        </div>
        <Field label="Summary" required hint="One sentence, shown on the module's card in the portal."><Input value={f.summary} maxLength={300} onChange={(e) => setF({ ...f, summary: e.target.value })} /></Field>
        <div className="grid gap-1.5 text-sm">
          <div className="flex items-center justify-between gap-2">
            <span id="module-content-label" className="font-medium">Content <span className="text-critical">*</span></span>
            {!readOnly && <Button type="button" size="sm" variant="ghost" aria-pressed={preview} onClick={() => setPreview(!preview)}>{preview ? <><Pencil /> Write</> : <><Eye /> Preview</>}</Button>}
          </div>
          {readOnly || preview ? <div className="max-h-96 overflow-auto rounded-md border p-4" aria-labelledby="module-content-label" role="region"><Markdown>{f.body}</Markdown></div>
            : <Textarea aria-labelledby="module-content-label" rows={12} className="font-mono text-xs" value={f.body} onChange={(e) => setF({ ...f, body: e.target.value })} />}
          <span className="text-xs text-muted-foreground">Markdown: ## for headings, - for lists, **bold**. Images aren't shown.</span>
        </div>
        <Section level={3} title={`Quiz (${f.quiz.length} question${f.quiz.length === 1 ? "" : "s"})`}>
          <ol className="space-y-3">
            {f.quiz.map((q, i) => (
              <li key={i} className="space-y-2 rounded-lg border p-3">
                <div className="flex items-start gap-2">
                  <span className="mt-2 text-sm font-medium tabular-nums">{i + 1}.</span>
                  <Input aria-label={`Question ${i + 1}`} value={q.q} placeholder="The question" onChange={(e) => setQ(i, { q: e.target.value })} />
                  {!readOnly && <Button size="icon" variant="ghost" aria-label={`Remove question ${i + 1}`} disabled={f.quiz.length === 1}
                    onClick={() => setF({ ...f, quiz: f.quiz.filter((_, j) => j !== i), pass_mark: Math.min(Number(f.pass_mark), f.quiz.length - 1) })}><Trash2 /></Button>}
                </div>
                <div role="radiogroup" aria-label={`Answers to question ${i + 1}`} className="space-y-1.5 pl-6">
                  {q.options.map((o, k) => (
                    <div key={k} className="flex items-center gap-2">
                      <input type="radio" name={`answer-${i}`} checked={q.answer === k} onChange={() => setQ(i, { answer: k })} aria-label={`Answer ${k + 1} is right`} className="size-4 accent-[hsl(var(--primary))]" />
                      <Input aria-label={`Question ${i + 1}, answer ${k + 1}`} value={o} placeholder={`Answer ${k + 1}`} onChange={(e) => setQ(i, { options: q.options.map((x, n) => (n === k ? e.target.value : x)) })} />
                      {!readOnly && <Button size="icon" variant="ghost" aria-label={`Remove answer ${k + 1}`} disabled={q.options.length <= 2}
                        onClick={() => setQ(i, { options: q.options.filter((_, n) => n !== k), answer: q.answer === k ? 0 : q.answer > k ? q.answer - 1 : q.answer })}><X /></Button>}
                    </div>
                  ))}
                  {!readOnly && q.options.length < 6 && <Button size="sm" variant="ghost" onClick={() => setQ(i, { options: [...q.options, ""] })}><Plus /> Add answer</Button>}
                  <p className="text-xs text-muted-foreground">Select the right answer with the round button.</p>
                </div>
              </li>
            ))}
          </ol>
          <div className="mt-3 flex flex-wrap items-end justify-between gap-3">
            {!readOnly && f.quiz.length < 20 ? <Button variant="outline" onClick={() => setF({ ...f, quiz: [...f.quiz, { q: "", options: ["", ""], answer: 0 }], pass_mark: Number(f.pass_mark) === f.quiz.length ? f.quiz.length + 1 : f.pass_mark })}><Plus /> Add question</Button> : <span />}
            <Field label="Pass mark" className="w-40"><span className="flex items-center gap-2"><Input type="number" min={1} max={f.quiz.length} value={f.pass_mark} onChange={(e) => setF({ ...f, pass_mark: e.target.value })} /><span className="whitespace-nowrap text-sm text-muted-foreground">of {f.quiz.length}</span></span></Field>
          </div>
        </Section>
      </fieldset>
    </Dialog>
  );
}

/** Training done outside Keystone (a classroom session, an external course), with its certificate. */
function ExternalTraining({ modules }: { modules: any[] }) {
  const { data } = useApi<any[]>("/training/external");
  const [adding, setAdding] = useState(false);
  const remove = useAction((id: number) => api(`/training/external/${id}`, { method: "DELETE" }), { success: "Record removed.", invalidate: INV });
  const titles = new Map(modules.map((m) => [m.key, m.title]));
  return (
    <Section level={2} title="Training done elsewhere" action={<Button variant="outline" onClick={() => setAdding(true)}><Upload /> Record training</Button>}>
      <p className="mb-3 max-w-3xl text-sm text-muted-foreground">
        Record training people did outside Keystone, such as a classroom session or an external course, with its certificate. When it covers one of the
        modules, it counts as passing that module until its valid-until date, also for people without a portal account. Certificates can be opened only by
        people who manage people.
      </p>
      {!data ? <Skeleton className="h-24" /> : (
        <DataTable rows={data} rowKey={(e: any) => e.id} search={(e: any) => `${e.person} ${e.title} ${e.provider ?? ""}`} exportName="training-done-elsewhere" empty="No training recorded from elsewhere yet." columns={[
          { key: "p", header: "Person", cell: (e: any) => <span className="font-medium">{e.person}</span> },
          { key: "t", header: "Training", cell: (e: any) => <span>{e.title}{e.module_key && <span className="block text-xs text-muted-foreground">Counts as: {titles.get(e.module_key) ?? e.module_key}</span>}</span> },
          { key: "v", header: "Provider", cell: (e: any) => e.provider ?? "" },
          { key: "c", header: "Completed", cell: (e: any) => fmtDate(e.completed_on) },
          { key: "u", header: "Valid until", cell: (e: any) => fmtDate(e.valid_until) },
          { key: "f", header: "Certificate", cell: (e: any) => (e.attachment_id ? <a href={downloadUrl(`/attachments/${e.attachment_id}`)} className="inline-flex items-center gap-1 text-primary hover:underline"><FileText className="size-4" /> Open</a> : <span className="text-muted-foreground">None</span>) },
          { key: "x", header: "", cell: (e: any) => <Button size="icon" variant="ghost" aria-label={`Remove the record of ${e.title} for ${e.person}`} onClick={() => { if (window.confirm("Remove this record? The audit log keeps what it said.")) remove.mutate(e.id); }}><Trash2 /></Button> },
        ]} />
      )}
      {adding && <RecordExternal modules={modules} onClose={() => setAdding(false)} />}
    </Section>
  );
}

function RecordExternal({ modules, onClose }: { modules: any[]; onClose: () => void }) {
  const { data } = useApi<any>("/people");
  const [f, setF] = useState<{ person_id: string | null; module_key: string | null; title: string; provider: string; completed_on: string | null; valid_until: string | null; note: string; file: File | null }>(
    { person_id: null, module_key: null, title: "", provider: "", completed_on: null, valid_until: null, note: "", file: null });
  const save = useAction(() => {
    const fd = new FormData();
    fd.append("person_id", f.person_id!);
    fd.append("completed_on", f.completed_on!);
    for (const k of ["module_key", "title", "provider", "valid_until", "note"] as const) if (f[k]) fd.append(k, f[k] as string);
    if (f.file) fd.append("file", f.file);
    return upload("/training/external", fd);
  }, { success: "Training recorded.", invalidate: INV, onSuccess: onClose });
  const people = (data?.people ?? []).filter((p: any) => p.status !== "offboarded");
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} wide title="Record training done elsewhere"
      footer={<Button disabled={!f.person_id || !f.completed_on || (!f.module_key && !f.title.trim())} loading={save.isPending} onClick={() => save.mutate(undefined)}>Record</Button>}>
      <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Person" required><Select ariaLabel="Person" value={f.person_id} onChange={(v) => setF({ ...f, person_id: v })} options={people.map((p: any) => ({ value: String(p.id), label: p.full_name }))} placeholder="Choose…" /></Field>
          <Field label="Counts as module" hint="Leave empty for other training (then name it).">
            <Select ariaLabel="Counts as module" value={f.module_key} allowEmpty emptyLabel="Other training" onChange={(v) => setF({ ...f, module_key: v })} options={modules.map((m) => ({ value: m.key, label: m.title }))} />
          </Field>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Training name" required={!f.module_key} hint={f.module_key ? "Optional: defaults to the module's title." : undefined}><Input value={f.title} maxLength={200} onChange={(e) => setF({ ...f, title: e.target.value })} placeholder="e.g. Security awareness workshop" /></Field>
          <Field label="Provider"><Input value={f.provider} maxLength={200} onChange={(e) => setF({ ...f, provider: e.target.value })} placeholder="e.g. In-house, or the training company" /></Field>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Completed on" required><DateInput ariaLabel="Completed on" value={f.completed_on} onChange={(v) => setF({ ...f, completed_on: v })} /></Field>
          <Field label="Valid until" hint="Empty: a year after completion."><DateInput ariaLabel="Valid until" value={f.valid_until} onChange={(v) => setF({ ...f, valid_until: v })} /></Field>
        </div>
        <Field label="Certificate" hint="PDF, PNG or JPG. Optional.">
          <input type="file" accept=".pdf,.png,.jpg,.jpeg" aria-label="Certificate" onChange={(e) => setF({ ...f, file: e.target.files?.[0] ?? null })} className="text-sm" />
        </Field>
        <Field label="Note"><Textarea value={f.note} maxLength={2000} onChange={(e) => setF({ ...f, note: e.target.value })} /></Field>
      </div>
    </Dialog>
  );
}
