import { useState } from "react";
import { ArrowDown, ArrowUp, FileCog, Plus, Trash2 } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi } from "@/lib/hooks";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/misc";
import { Select } from "@/components/ui/select";

const TYPES = [{ value: "ynp", label: "Yes / partly / no" }, { value: "yn", label: "Yes / no" }, { value: "text", label: "Free text" }];
const INV = ["/questionnaire"];

type Q = { id: string; section: string; text: string; type: string; weight: number; control?: string; required: boolean };

/** Questionnaire templates (A.5.19-5.21): write your own questions, weights and the controls they evidence. */
export function TemplatesButton() {
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<number | "new" | null>(null);
  const { data } = useApi<any[]>(open ? "/questionnaire-templates" : null);
  return (
    <>
      <Button variant="outline" onClick={() => setOpen(true)}><FileCog /> Templates</Button>
      {open && (
        <Dialog open onOpenChange={(o) => !o && setOpen(false)} wide title="Questionnaire templates" description="Templates in use keep their questions: change them by saving a new version."
          footer={<Button onClick={() => setEditing("new")}><Plus /> New template</Button>}>
          {!data ? <Skeleton className="h-32" /> : (
            <ul className="divide-y rounded-md border">
              {data.map((t) => (
                <li key={t.id}>
                  <button type="button" onClick={() => setEditing(t.id)} className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-sm hover:bg-muted/50">
                    <span><span className="font-medium">{t.name}</span> <Badge tone="outline">v{t.version}</Badge></span>
                    <span className="text-xs text-muted-foreground">{t.question_count} questions</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Dialog>
      )}
      {editing !== null && <TemplateEditor id={editing} onClose={() => setEditing(null)} />}
    </>
  );
}

function TemplateEditor({ id, onClose }: { id: number | "new"; onClose: () => void }) {
  const isNew = id === "new";
  const { data } = useApi<any>(isNew ? null : `/questionnaire-templates/${id}`);
  const [f, setF] = useState<{ name: string; version: string; description: string; questions: Q[] } | null>(isNew ? { name: "", version: "1.0", description: "", questions: [blank(1)] } : null);
  const [newVersion, setNewVersion] = useState("");
  if (!f && data) setF({ name: data.name, version: data.version, description: data.description ?? "", questions: data.questions.map((q: any) => ({ ...q, control: q.control ?? "", required: !!q.required })) });
  const body = () => ({ ...f!, questions: f!.questions.map((q) => ({ ...q, control: q.control || undefined, weight: Number(q.weight) })) });
  const save = useAction(() => (isNew ? api("/questionnaire-templates", { body: body() }) : api(`/questionnaire-templates/${id}`, { method: "PATCH", body: data?.in_use ? { name: f!.name, description: f!.description } : body() })),
    { success: "Template saved.", invalidate: INV, onSuccess: onClose });
  const version = useAction(() => api(`/questionnaire-templates/${id}/versions`, { body: { version: newVersion, questions: body().questions } }), { success: "New version saved; the old one is retired from new sends.", invalidate: INV, onSuccess: onClose });
  const retire = useAction(() => api(`/questionnaire-templates/${id}`, { method: "PATCH", body: { active: false } }), { success: "Template retired.", invalidate: INV, onSuccess: onClose });
  if (!f) return null;
  const setQ = (i: number, patch: Partial<Q>) => setF({ ...f, questions: f.questions.map((q, j) => (j === i ? { ...q, ...patch } : q)) });
  const move = (i: number, d: number) => { const qs = [...f.questions]; [qs[i], qs[i + d]] = [qs[i + d], qs[i]]; setF({ ...f, questions: qs }); };
  const locked = !!data?.in_use;
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} extraWide title={isNew ? "New questionnaire template" : `${f.name} v${f.version}`}
      description={locked ? "Questionnaires were sent from this version, so its questions are fixed. Edit them below and save as a new version." : "Weights set how much each answer counts in the score (0 for information only)."}
      footer={<div className="flex flex-wrap items-center gap-2">
        {!isNew && <Button variant="outline" loading={retire.isPending} onClick={() => retire.mutate(undefined)}>Retire</Button>}
        {!isNew && <><Input aria-label="New version label" className="w-28" placeholder="e.g. 1.1" value={newVersion} onChange={(e) => setNewVersion(e.target.value)} />
          <Button variant="outline" disabled={!newVersion.trim()} loading={version.isPending} onClick={() => version.mutate(undefined)}>Save as new version</Button></>}
        <Button disabled={!f.name.trim() || !f.questions.length} loading={save.isPending} onClick={() => save.mutate(undefined)}>{locked ? "Save name and description" : "Save"}</Button>
      </div>}>
      <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-[1fr_8rem]">
          <Field label="Name" required><Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
          <Field label="Version"><Input disabled={!isNew} value={f.version} onChange={(e) => setF({ ...f, version: e.target.value })} /></Field>
        </div>
        <Field label="Description"><Textarea value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
        <ol className="space-y-3">
          {f.questions.map((q, i) => (
            <li key={i} className="space-y-2 rounded-lg border p-3">
              <div className="flex flex-wrap items-end gap-2">
                <Field label="Id" className="w-24"><Input value={q.id} onChange={(e) => setQ(i, { id: e.target.value })} /></Field>
                <Field label="Section" className="w-40"><Input value={q.section} onChange={(e) => setQ(i, { section: e.target.value })} /></Field>
                <Field label="Answer" className="w-44"><Select ariaLabel="Answer type" value={q.type} onChange={(v) => setQ(i, { type: v ?? "ynp" })} options={TYPES} /></Field>
                <Field label="Weight" className="w-20"><Input type="number" min={0} max={10} step={0.5} value={q.weight} onChange={(e) => setQ(i, { weight: Number(e.target.value) })} /></Field>
                <Field label="Control" className="w-32"><Input value={q.control ?? ""} placeholder="KC-TEC-05" onChange={(e) => setQ(i, { control: e.target.value })} /></Field>
                <label className="flex items-center gap-1.5 pb-2 text-sm"><input type="checkbox" checked={q.required} onChange={(e) => setQ(i, { required: e.target.checked })} /> Required</label>
                <span className="ml-auto flex gap-1 pb-1">
                  <Button size="icon" variant="ghost" aria-label="Move up" disabled={i === 0} onClick={() => move(i, -1)}><ArrowUp /></Button>
                  <Button size="icon" variant="ghost" aria-label="Move down" disabled={i === f.questions.length - 1} onClick={() => move(i, 1)}><ArrowDown /></Button>
                  <Button size="icon" variant="ghost" aria-label="Remove question" onClick={() => setF({ ...f, questions: f.questions.filter((_, j) => j !== i) })}><Trash2 /></Button>
                </span>
              </div>
              <Textarea aria-label="Question" value={q.text} onChange={(e) => setQ(i, { text: e.target.value })} placeholder="The question as the vendor will read it" />
            </li>
          ))}
        </ol>
        <Button variant="outline" onClick={() => setF({ ...f, questions: [...f.questions, blank(f.questions.length + 1)] })}><Plus /> Add question</Button>
      </div>
    </Dialog>
  );
}

function blank(n: number): Q {
  return { id: `q${n}`, section: "General", text: "", type: "ynp", weight: 1, control: "", required: false };
}
