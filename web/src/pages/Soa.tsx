import { useEffect, useState } from "react";
import { FileCheck2, FileSpreadsheet, FileText, Stamp } from "lucide-react";
import { api, downloadUrl } from "@/lib/api";
import { useAction, useApi, usePeople } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { PageHeader, Skeleton, Stat } from "@/components/ui/misc";
import { Select } from "@/components/ui/select";
import { StatusBadge } from "@/components/ui/status";
import { DataTable } from "@/components/ui/table";

const BASIS: Record<string, string> = { decision: "Recorded decision", controls_na: "Controls not applicable", risks: "Risk treatment", baseline: "Baseline" };

export default function Soa() {
  const { can } = useAuth();
  const { name } = usePeople();
  const fws = useApi<any[]>("/frameworks");
  const [code, setCode] = useState<string | null>(null);
  useEffect(() => { if (!code && fws.data?.length) setCode(fws.data[0].code); }, [fws.data, code]);
  const { data } = useApi<any>(code ? `/soa/${code}` : null);
  const [edit, setEdit] = useState<any>(null);
  const [approve, setApprove] = useState(false);
  const [note, setNote] = useState("");
  const saveEntry = useAction((v: any) => api(`/soa/entries/${v.id}`, { method: "PUT", body: { applicable: v.applicable, justification: v.justification } }), { success: "Decision saved.", invalidate: ["/soa"], onSuccess: () => setEdit(null) });
  const clearEntry = useAction((id: number) => api(`/soa/entries/${id}`, { method: "DELETE" }), { success: "Decision removed.", invalidate: ["/soa"], onSuccess: () => setEdit(null) });
  const doApprove = useAction(() => api(`/soa/${code}/approve`, { body: { note: note || null } }), { success: "SoA approved.", invalidate: ["/soa"], onSuccess: () => setApprove(false) });
  if (!fws.data) return <Skeleton className="h-96" />;
  const rows = data?.rows ?? [];
  const latest = data?.approvals?.[0];
  return (
    <div className="animate-fade-in">
      <PageHeader icon={FileCheck2} title="Statement of Applicability" description="Applicability and justification for every requirement, derived from your controls and risks (ISO 27001 6.1.3 d)."
        actions={
          <>
            <div className="w-64"><Select value={code} onChange={setCode} options={fws.data.map((f) => ({ value: f.code, label: `${f.name} ${f.version}` }))} ariaLabel="Framework" /></div>
            {code && <a href={downloadUrl(`/soa/${code}/export.xlsx`)}><Button variant="outline"><FileSpreadsheet /> Excel</Button></a>}
            {code && <a href={downloadUrl(`/soa/${code}/export.docx`)}><Button variant="outline"><FileText /> Word</Button></a>}
            {can("soa.write") && <Button onClick={() => setApprove(true)}><Stamp /> Approve version</Button>}
          </>
        } />
      {data && (
        <>
          <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-4 sm:gap-4">
            <Stat label="Requirements" value={rows.length} />
            <Stat label="Applicable" value={rows.filter((r: any) => r.applicable).length} />
            <Stat label="Implemented" value={rows.filter((r: any) => r.applicable && r.implementation === "implemented").length} tone="good" />
            <Stat label="Version" value={latest ? `v${latest.version}` : "Draft"} hint={latest ? `${fmtDate(latest.approved_at)} by ${name(latest.approved_by_id)}${data.changed_since_approval.length ? ` · ${data.changed_since_approval.length} changed since` : ""}` : "Not approved yet"} tone={data.changed_since_approval.length ? "warning" : undefined} />
          </div>
          <DataTable
            rows={rows}
            rowKey={(r: any) => r.requirement_id}
            onRowClick={can("soa.write") ? (r: any) => setEdit({ id: r.requirement_id, ref: r.ref, applicable: r.applicable, justification: r.basis === "decision" ? r.justification : "", basis: r.basis }) : undefined}
            search={(r: any) => `${r.ref} ${r.title} ${r.controls.join(" ")}`}
            columns={[
              { key: "ref", header: "Ref", cell: (r: any) => <span className="font-mono text-xs">{r.ref}</span>, sort: (r: any) => r.ref, className: "w-24" },
              { key: "title", header: "Requirement", cell: (r: any) => <div>{r.title}{data.changed_since_approval.includes(r.ref) && <Badge tone="warning" className="ml-2">changed</Badge>}</div> },
              { key: "app", header: "Applicable", cell: (r: any) => (r.applicable ? <Badge tone="good">Yes</Badge> : <Badge tone="outline">No</Badge>), sort: (r: any) => String(r.applicable) },
              { key: "just", header: "Justification", cell: (r: any) => <div className="max-w-md"><div className="line-clamp-2">{r.justification}</div><div className="text-xs text-muted-foreground">{BASIS[r.basis]}</div></div> },
              { key: "impl", header: "Implementation", cell: (r: any) => <StatusBadge status={r.implementation} />, sort: (r: any) => r.implementation },
              { key: "ev", header: "Evidence", cell: (r: any) => (r.applicable ? <span className={r.evidence ? "tabular-nums" : "text-xs text-muted-foreground"}>{r.evidence || "None current"}</span> : "—"), sort: (r: any) => r.evidence },
              { key: "test", header: "Last test", cell: (r: any) => (r.last_test ? <span className="flex flex-col gap-0.5"><StatusBadge status={r.last_test} label={r.last_test === "partially_effective" ? "Partly effective" : undefined} /><span className="text-xs text-muted-foreground">{fmtDate(r.last_tested_on)}</span></span> : <span className="text-xs text-muted-foreground">Not tested</span>), sort: (r: any) => r.last_tested_on ?? "" },
            ]}
          />
        </>
      )}
      <Dialog open={!!edit} onOpenChange={(o) => !o && setEdit(null)} title={`Applicability of ${edit?.ref}`} description="Recording a decision overrides the derived default."
        footer={<>{edit?.basis === "decision" && <Button variant="ghost" onClick={() => clearEntry.mutate(edit.id)}>Use default</Button>}<Button loading={saveEntry.isPending} onClick={() => saveEntry.mutate(edit)}>Save decision</Button></>}>
        {edit && (
          <div className="space-y-4">
            <Field label="Applicable?"><Select value={edit.applicable ? "yes" : "no"} onChange={(v) => setEdit({ ...edit, applicable: v === "yes" })} options={[{ value: "yes", label: "Yes, applicable" }, { value: "no", label: "No, excluded" }]} /></Field>
            <Field label="Justification" required={!edit.applicable}><Textarea value={edit.justification} onChange={(e) => setEdit({ ...edit, justification: e.target.value })} /></Field>
          </div>
        )}
      </Dialog>
      <Dialog open={approve} onOpenChange={setApprove} title="Approve this SoA version" description="Freezes a snapshot. Later changes are highlighted until the next approval."
        footer={<Button loading={doApprove.isPending} onClick={() => doApprove.mutate(undefined)}>Approve</Button>}>
        <Field label="Approval note"><Input value={note} onChange={(e) => setNote(e.target.value)} /></Field>
      </Dialog>
    </div>
  );
}
