import { useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { Download, Paperclip, Plus } from "lucide-react";
import { api, downloadUrl, upload } from "@/lib/api";
import { useAction, useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { PageHeader, Skeleton, Stat } from "@/components/ui/misc";
import { Select } from "@/components/ui/select";
import { StatusBadge } from "@/components/ui/status";
import { DataTable } from "@/components/ui/table";
import { previewKind, ViewAttachment } from "@/components/DocumentViewer";
import { EvidenceActions } from "@/components/ControlAssurance";

const EVIDENCE_PAGE = 1000; // matches the API default page size (SC-ERR-004)

export default function Evidence() {
  const { can } = useAuth();
  const [params] = useSearchParams();
  const { data, isLoading } = useApi<any[]>("/evidence");
  const controls = useApi<any[]>("/controls");
  const [open, setOpen] = useState(!!params.get("control"));
  const [f, setF] = useState<any>({ control_id: params.get("control"), title: "", kind: "file", url: "", description: "", collected_on: "", valid_until: "", file: null });
  const ctlName = useMemo(() => new Map((controls.data ?? []).map((c) => [c.id, `${c.code} ${c.title}`])), [controls.data]);
  const add = useAction(async () => {
    const fd = new FormData();
    fd.append("control_id", String(f.control_id));
    fd.append("title", f.title);
    fd.append("kind", f.kind);
    for (const k of ["url", "description", "collected_on", "valid_until"]) if (f[k]) fd.append(k, f[k]);
    if (f.file) fd.append("file", f.file);
    return upload("/evidence", fd);
  }, { success: "Evidence added.", invalidate: ["/evidence", "/controls", "/dashboard"], onSuccess: () => setOpen(false) });
  const review = useAction((v: { id: number; superseded: boolean }) => api(`/evidence/${v.id}/review`, { body: { superseded: v.superseded } }), { success: "Review recorded.", invalidate: ["/evidence"] });
  if (isLoading || !data) return <Skeleton className="h-96" />;
  const count = (s: string) => data.filter((e) => e.state === s).length;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Paperclip} title="Evidence" description="Proof that controls operate: files, links and notes, with expiry tracking."
        actions={can("evidence.write") && <Button onClick={() => setOpen(true)}><Plus /> Add evidence</Button>} />
      {data.length >= EVIDENCE_PAGE && <p className="mb-4 rounded-lg border bg-muted/40 px-4 py-3 text-sm text-muted-foreground">Showing the {EVIDENCE_PAGE.toLocaleString()} most recent items. Open a control to see all of its evidence.</p>}
      <div className="mb-5 grid gap-4 sm:grid-cols-4">
        <Stat label="Current" value={count("current")} tone="good" />
        <Stat label="Expiring in 30 days" value={count("expiring")} tone={count("expiring") ? "warning" : undefined} />
        <Stat label="Expired" value={count("expired")} tone={count("expired") ? "critical" : undefined} />
        <Stat label="Rejected or superseded" value={count("rejected") + count("superseded")} tone={count("rejected") ? "critical" : undefined} />
      </div>
      <DataTable
        rows={data}
        rowKey={(e: any) => e.id}
        search={(e: any) => `${e.title} ${ctlName.get(e.common_control_id) ?? ""}`}
        columns={[
          { key: "title", header: "Evidence", cell: (e: any) => <div><div className="font-medium">{e.title}</div><div className="text-xs text-muted-foreground">{[e.common_control_id, ...e.also_controls.map((c: any) => c.id)].map((id: number) => ctlName.get(id)).filter(Boolean).join(" · ")}</div>{e.review_decision === "rejected" && <div className="text-xs text-critical">Rejected: {e.review_note}</div>}</div>, sort: (e: any) => e.title },
          { key: "kind", header: "Kind", cell: (e: any) => e.kind },
          { key: "collected", header: "Collected", cell: (e: any) => fmtDate(e.collected_on), sort: (e: any) => e.collected_on },
          { key: "valid", header: "Valid until", cell: (e: any) => fmtDate(e.valid_until), sort: (e: any) => e.valid_until ?? "" },
          { key: "state", header: "State", cell: (e: any) => <span className="flex flex-wrap gap-1"><StatusBadge status={e.state} />{e.review_decision === "accepted" && <StatusBadge status="approved" label="Accepted" />}</span>, sort: (e: any) => e.state },
          { key: "act", header: "", className: "w-40", cell: (e: any) => (
            <div className="flex justify-end gap-1">
              {e.attachment_id && previewKind(e.filename) && <ViewAttachment id={e.attachment_id} filename={e.filename} title={e.title} size="icon" />}
              {e.attachment_id && <a href={downloadUrl(`/attachments/${e.attachment_id}`)} onClick={(x) => x.stopPropagation()}><Button size="icon" variant="ghost" aria-label="Download"><Download /></Button></a>}
              {e.url && <a href={e.url} target="_blank" rel="noreferrer noopener" className="self-center text-xs text-primary hover:underline">Open link</a>}
              {can("evidence.write") && e.state !== "superseded" && e.state !== "rejected" && <Button size="sm" variant="ghost" onClick={() => review.mutate({ id: e.id, superseded: true })}>Superseded</Button>}
              <EvidenceActions evidence={e} />
            </div>
          ) },
        ]}
      />
      <Dialog open={open} onOpenChange={setOpen} title="Add evidence" wide footer={<Button loading={add.isPending} onClick={() => add.mutate(undefined)}>Add evidence</Button>}>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Control" className="sm:col-span-2"><Select value={f.control_id} onChange={(v) => setF({ ...f, control_id: v })} options={(controls.data ?? []).map((c) => ({ value: String(c.id), label: `${c.code} · ${c.title}` }))} /></Field>
          <Field label="Title" className="sm:col-span-2"><Input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} /></Field>
          <Field label="Kind"><Select value={f.kind} onChange={(v) => setF({ ...f, kind: v })} options={[{ value: "file", label: "File" }, { value: "link", label: "Link" }, { value: "note", label: "Note" }]} /></Field>
          {f.kind === "file" && <Field label="File"><input type="file" onChange={(e) => setF({ ...f, file: e.target.files?.[0] ?? null })} className="text-sm" /></Field>}
          {f.kind === "link" && <Field label="Link"><Input placeholder="https://…" value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} /></Field>}
          <Field label="Description" className="sm:col-span-2"><Textarea value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
          <Field label="Collected on"><Input type="date" value={f.collected_on} onChange={(e) => setF({ ...f, collected_on: e.target.value })} /></Field>
          <Field label="Valid until"><Input type="date" value={f.valid_until} onChange={(e) => setF({ ...f, valid_until: e.target.value })} /></Field>
        </div>
      </Dialog>
    </div>
  );
}
