import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { CheckCircle2, Download, FilePlus2, Plus, ScrollText, Send, Sparkles, Stamp, Undo2 } from "lucide-react";
import { api, downloadUrl, upload } from "@/lib/api";
import { useAction, useApi, usePeople } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate, titleCase } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { Dialog, Sheet } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { PageHeader, Progress, Section, Skeleton, Stat } from "@/components/ui/misc";
import { MultiSelect } from "@/components/ui/multiselect";
import { StatusBadge } from "@/components/ui/status";
import { Tabs } from "@/components/ui/tabs";
import { DataTable } from "@/components/ui/table";
import { Markdown } from "@/components/Markdown";
import { PolicyAssistant } from "@/components/PolicyAssistant";
import { EnumSelect, OwnerSelect } from "@/components/forms";

const TYPES = ["policy", "standard", "procedure", "guideline", "plan"];

export function PendingAcknowledgements() {
  const { data } = useApi<any[]>("/policies/pending");
  const ack = useAction((vid: number) => api(`/policies/versions/${vid}/acknowledge`, { method: "POST" }), { success: "Thank you, acknowledgement recorded.", invalidate: ["/policies", "/dashboard"] });
  const [open, setOpen] = useState<any>(null);
  if (!data?.length) return null;
  return (
    <Card className="mb-6 border-primary/30 bg-accent/40">
      <CardBody>
        <div className="mb-3 font-medium">Waiting for your acknowledgement ({data.length})</div>
        <div className="space-y-2">
          {data.map((v) => (
            <div key={v.id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border bg-card px-3 py-2 text-sm">
              <span><span className="font-mono text-xs text-muted-foreground">{v.code}</span> {v.title} <span className="text-muted-foreground">v{v.version_label}</span></span>
              <div className="flex gap-2"><Button size="sm" variant="outline" onClick={() => setOpen(v)}>Read</Button><Button size="sm" onClick={() => ack.mutate(v.id)}><CheckCircle2 /> I have read it</Button></div>
            </div>
          ))}
        </div>
      </CardBody>
      <Dialog open={!!open} onOpenChange={(o) => !o && setOpen(null)} wide title={open ? `${open.code} ${open.title} v${open.version_label}` : ""}
        footer={<Button onClick={() => { ack.mutate(open.id); setOpen(null); }}><CheckCircle2 /> I have read and understood this document</Button>}>
        {open?.body && <Markdown>{open.body}</Markdown>}
        {open?.attachment_id && <a href={downloadUrl(`/attachments/${open.attachment_id}`)}><Button variant="outline"><Download /> Download document</Button></a>}
      </Dialog>
    </Card>
  );
}

export default function Policies() {
  const { can } = useAuth();
  const { name } = usePeople();
  const [params, setParams] = useSearchParams();
  const { data } = useApi<any>("/policies");
  const [create, setCreate] = useState(false);
  if (!data) return <Skeleton className="h-96" />;
  const att = data.attention;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={ScrollText} title="Policies" description="Versioned documents with approval, review cycles and staff acknowledgement." actions={can("policy.write") && <Button onClick={() => setCreate(true)}><Plus /> New document</Button>} />
      <PendingAcknowledgements />
      <div className="mb-5 grid gap-4 sm:grid-cols-4">
        <Stat label="Documents" value={data.documents.length} />
        <Stat label="Reviews overdue" value={att.review_overdue.length} tone={att.review_overdue.length ? "warning" : undefined} />
        <Stat label="Awaiting approval" value={att.awaiting_approval.length} />
        <Stat label="Acknowledgement incomplete" value={att.acknowledgement_incomplete.length} />
      </div>
      <DataTable rows={data.documents} rowKey={(d: any) => d.id} onRowClick={(d: any) => setParams({ open: String(d.id) })} search={(d: any) => `${d.code} ${d.title}`} columns={[
        { key: "c", header: "Code", cell: (d: any) => <span className="font-mono text-xs">{d.code}</span>, sort: (d: any) => d.code, className: "w-24" },
        { key: "t", header: "Document", cell: (d: any) => <div><div className="font-medium">{d.title}</div><div className="text-xs text-muted-foreground">{titleCase(d.doc_type)} · {name(d.owner_id)}</div></div>, sort: (d: any) => d.title },
        { key: "s", header: "Status", cell: (d: any) => <div className="flex flex-col items-start gap-1"><StatusBadge status={d.status} label={d.current_version ? `${titleCase(d.status)} v${d.current_version}` : undefined} />{d.open_version && <span className="text-xs text-muted-foreground">v{d.open_version.label} {d.open_version.status.replace("_", " ")}</span>}</div> },
        { key: "a", header: "Acknowledged", cell: (d: any) => (d.ack ? <div className="w-36"><Progress label={`${d.code} acknowledgement`} value={d.ack.pct} tone={d.ack.pct === 100 ? "good" : "primary"} /><div className="mt-1 text-xs text-muted-foreground">{d.ack.acknowledged}/{d.ack.total}</div></div> : <span className="text-muted-foreground">n/a</span>) },
        { key: "r", header: "Next review", cell: (d: any) => <span className={att.review_overdue.includes(d.id) ? "font-medium text-critical" : ""}>{fmtDate(d.next_review_date)}</span>, sort: (d: any) => d.next_review_date ?? "" },
      ]} />
      {create && <NewDocument onClose={() => setCreate(false)} onCreated={(id) => { setCreate(false); setParams({ open: String(id) }); }} />}
      {params.get("open") && <DocumentDrawer id={Number(params.get("open"))} onClose={() => setParams({})} />}
    </div>
  );
}

function NewDocument({ onClose, onCreated }: { onClose: () => void; onCreated: (id: number) => void }) {
  const controls = useApi<any[]>("/controls");
  const [f, setF] = useState<any>({ code: "", title: "", doc_type: "policy", owner_id: null, review_interval_months: 12, requires_acknowledgement: true, control_ids: [] });
  const save = useAction((b: any) => api("/policies", { body: b }), { success: "Document created.", invalidate: ["/policies"], onSuccess: (r: any) => onCreated(r.id) });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title="New document" wide footer={<Button loading={save.isPending} onClick={() => save.mutate({ ...f, control_ids: f.control_ids.map(Number) })}>Create</Button>}>
      <div className="grid gap-4 sm:grid-cols-[1fr_3fr]">
        <Field label="Code" required><Input placeholder="POL-003" value={f.code} onChange={(e) => setF({ ...f, code: e.target.value })} /></Field>
        <Field label="Title" required><Input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} /></Field>
        <Field label="Type"><EnumSelect value={f.doc_type} onChange={(v) => setF({ ...f, doc_type: v })} values={TYPES} /></Field>
        <Field label="Owner"><OwnerSelect value={f.owner_id} onChange={(v) => setF({ ...f, owner_id: v })} /></Field>
        <Field label="Review every (months)"><Input type="number" min={1} max={36} value={f.review_interval_months} onChange={(e) => setF({ ...f, review_interval_months: Number(e.target.value) })} /></Field>
        <label className="flex items-center gap-2 self-end text-sm"><input type="checkbox" checked={f.requires_acknowledgement} onChange={(e) => setF({ ...f, requires_acknowledgement: e.target.checked })} /> Staff must acknowledge</label>
        <Field label="Implements controls" className="sm:col-span-2"><MultiSelect value={f.control_ids} onChange={(v) => setF({ ...f, control_ids: v })} options={(controls.data ?? []).map((c) => ({ value: String(c.id), label: `${c.code} ${c.title}` }))} /></Field>
      </div>
    </Dialog>
  );
}

function DocumentDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const { can, me } = useAuth();
  const { name } = usePeople();
  const { data } = useApi<any>(`/policies/${id}`);
  const [body, setBody] = useState("");
  const [summary, setSummary] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [note, setNote] = useState("");
  const [major, setMajor] = useState(true);
  const ov = data?.versions.find((v: any) => ["draft", "in_review"].includes(v.status));
  const [loadedVersion, setLoadedVersion] = useState<number | null>(null);
  if (ov && ov.id !== loadedVersion) { setLoadedVersion(ov.id); setBody(ov.body ?? ""); setSummary(ov.change_summary ?? ""); } // reset the editor when another version opens
  const inv = ["/policies", "/dashboard"];
  const start = useAction(() => api(`/policies/${id}/versions`, { body: { change_summary: summary || null, major } }), { success: "Draft version started.", invalidate: inv });
  const saveDraft = useAction(async () => { const fd = new FormData(); fd.append("body", body); fd.append("change_summary", summary); if (file) fd.append("file", file); return upload(`/policies/versions/${ov.id}`, fd, "PATCH"); }, { success: "Draft saved.", invalidate: inv });
  const submit = useAction(async () => { await saveDraft.mutateAsync(undefined); return api(`/policies/versions/${ov.id}/submit`, { method: "POST" }); }, { success: "Submitted for approval.", invalidate: inv });
  const approve = useAction(() => api(`/policies/versions/${ov.id}/approve`, { body: { note: note || null } }), { success: "Version approved and published.", invalidate: inv });
  const ret = useAction(() => api(`/policies/versions/${ov.id}/return`, { body: { note } }), { success: "Returned to author.", invalidate: inv });
  const review = useAction(() => api(`/policies/${id}/review`, { method: "POST" }), { success: "Periodic review recorded.", invalidate: inv });
  const retire = useAction(() => api(`/policies/${id}/retire`, { method: "POST" }), { success: "Document retired.", invalidate: inv });
  const current = data?.versions.find((v: any) => v.status === "approved");
  const aiStatus = useApi<any>("/ai/status");
  const [assist, setAssist] = useState(false);
  const canAssist = aiStatus.data?.available && can("policy.write") && data && data.status !== "retired" && (!ov || ov.status === "draft");
  return (
    <>
    {assist && <PolicyAssistant docId={id} unsaved={!!ov && (body !== (ov.body ?? "") || summary !== (ov.change_summary ?? ""))} onClose={() => setAssist(false)} onAccepted={(b, s) => { setBody(b); setSummary(s); }} />}
    <Sheet open onOpenChange={(o) => !o && onClose()} title={data ? `${data.code} · ${data.title}` : "Loading…"} subtitle={data && <span className="flex items-center gap-2"><StatusBadge status={data.status} />{data.current_version && <Badge tone="outline">v{data.current_version}</Badge>}{data.next_review_date && <span>review {fmtDate(data.next_review_date)}</span>}</span>}
      actions={<>{canAssist && <Button size="sm" variant="outline" onClick={() => setAssist(true)}><Sparkles /> AI assist</Button>}{data && can("policy.approve") && data.status === "approved" && <><Button size="sm" variant="outline" onClick={() => review.mutate(undefined)}><CheckCircle2 /> Reviewed, no change</Button><Button size="sm" variant="ghost" onClick={() => retire.mutate(undefined)}>Retire</Button></>}</>}>
      {!data ? <Skeleton className="h-64" /> : (
        <Tabs tabs={[
          { value: "doc", label: current ? `Current (v${current.version_label})` : "Document", content: current ? (
            <div>{current.body ? <Markdown>{current.body}</Markdown> : <p className="text-sm text-muted-foreground">No text; see the attached file.</p>}{current.attachment_id && <a href={downloadUrl(`/attachments/${current.attachment_id}`)}><Button variant="outline" className="mt-3"><Download /> Download</Button></a>}</div>
          ) : <p className="text-sm text-muted-foreground">No approved version yet.</p> },
          { value: "edit", label: ov ? `v${ov.version_label} (${ov.status.replace("_", " ")})` : "New version", content: (
            <div className="space-y-4">
              {!ov && can("policy.write") && data.status !== "retired" && (
                <div className="flex flex-wrap items-end gap-3 rounded-lg border p-4">
                  <Field label="What changes" className="min-w-64 flex-1"><Input value={summary} onChange={(e) => setSummary(e.target.value)} /></Field>
                  <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={major} onChange={(e) => setMajor(e.target.checked)} /> Major version</label>
                  <Button loading={start.isPending} onClick={() => start.mutate(undefined)}><FilePlus2 /> Start new version</Button>
                </div>
              )}
              {ov && ov.status === "draft" && can("policy.write") && (
                <>
                  {ov.approval_note && <p className="rounded-md bg-warning/10 px-3 py-2 text-sm">Returned: {ov.approval_note}</p>}
                  <div className="grid gap-4 lg:grid-cols-2">
                    <Field label="Text (Markdown)"><Textarea className="min-h-96 font-mono text-xs" value={body} onChange={(e) => setBody(e.target.value)} /></Field>
                    <div><div className="mb-1.5 text-sm font-medium">Preview</div><div className="min-h-96 rounded-md border p-4"><Markdown>{body || "*Nothing yet*"}</Markdown></div></div>
                  </div>
                  <Field label="Change summary"><Input value={summary} onChange={(e) => setSummary(e.target.value)} /></Field>
                  <Field label="Or attach the document (PDF, Word)"><input type="file" accept=".pdf,.docx,.md,.txt" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="text-sm" /></Field>
                  <div className="flex gap-2"><Button variant="outline" loading={saveDraft.isPending} onClick={() => saveDraft.mutate(undefined)}>Save draft</Button><Button loading={submit.isPending} onClick={() => submit.mutate(undefined)}><Send /> Submit for approval</Button></div>
                </>
              )}
              {ov && ov.status === "in_review" && (
                <div className="space-y-3">
                  <p className="text-sm">Submitted {fmtDate(ov.submitted_at, true)} by {name(ov.author_id)}.</p>
                  <div className="rounded-md border p-4">{ov.body ? <Markdown>{ov.body}</Markdown> : "See attachment."}</div>
                  {can("policy.approve") && (ov.author_id === me?.id ? <p className="text-sm text-muted-foreground">You wrote this version, so someone else must approve it.</p> : (
                    <div className="flex flex-wrap items-end gap-2">
                      <Field label="Note" className="min-w-64 flex-1"><Input value={note} onChange={(e) => setNote(e.target.value)} /></Field>
                      <Button loading={approve.isPending} onClick={() => approve.mutate(undefined)}><Stamp /> Approve and publish</Button>
                      <Button variant="ghost" onClick={() => ret.mutate(undefined)}><Undo2 /> Return</Button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) },
          { value: "history", label: `History (${data.versions.length})`, content: (
            <DataTable rows={data.versions} rowKey={(v: any) => v.id} columns={[
              { key: "v", header: "Version", cell: (v: any) => `v${v.version_label}` },
              { key: "s", header: "Status", cell: (v: any) => <StatusBadge status={v.status} /> },
              { key: "a", header: "Author", cell: (v: any) => name(v.author_id) },
              { key: "ap", header: "Approved", cell: (v: any) => (v.approved_at ? `${fmtDate(v.approved_at)} · ${name(v.approved_by_id)}` : "—") },
              { key: "c", header: "Changes", cell: (v: any) => v.change_summary ?? "" },
            ]} />
          ) },
          { value: "ack", label: "Acknowledgement", content: (
            <Section title="Staff acknowledgement">
              {data.ack ? <div className="max-w-sm"><Progress label="Acknowledgement progress" value={data.ack.pct} tone={data.ack.pct === 100 ? "good" : "primary"} /><p className="mt-2 text-sm">{data.ack.acknowledged} of {data.ack.total} active users ({data.ack.pct}%)</p></div> : <p className="text-sm text-muted-foreground">Not required, or no approved version yet.</p>}
            </Section>
          ) },
        ]} />
      )}
    </Sheet>
    </>
  );
}
