import { useState } from "react";
import { Check, ClipboardCheck, Link2, Plus, X } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi, usePeople } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate, titleCase } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Textarea } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { MultiSelect } from "@/components/ui/multiselect";
import { StatusBadge } from "@/components/ui/status";
import { DateInput } from "@/components/forms";

const INV = ["/controls", "/evidence", "/dashboard", "/soa", "/nonconformities"];
const TYPES = [{ value: "operating", label: "Operating effectiveness" }, { value: "design", label: "Design" }];
const METHODS = ["inspection", "observation", "inquiry", "reperformance"].map((m) => ({ value: m, label: titleCase(m) }));
const RESULTS = [{ value: "effective", label: "Effective" }, { value: "partially_effective", label: "Partly effective" }, { value: "ineffective", label: "Ineffective" }];

/** Tests of a control's design or operation (ISO 27001 9.1, 9.2). The control owner can't test their own control. */
export function ControlTests({ controlId, ownerId, tests, evidence }: { controlId: number; ownerId: number | null; tests: any[]; evidence: any[] }) {
  const { can, me } = useAuth();
  const { name } = usePeople();
  const [open, setOpen] = useState(false);
  const mayTest = can("audit.findings") && me?.id !== ownerId;
  return (
    <div className="space-y-2">
      {tests.length === 0 ? <p className="text-sm text-muted-foreground">Not tested yet.</p> : (
        <ul className="divide-y rounded-md border">
          {tests.map((t) => (
            <li key={t.id} className="space-y-1 px-3 py-2 text-sm">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span>{fmtDate(t.tested_on)} · {t.test_type === "design" ? "Design" : "Operating"} test by {titleCase(t.method)} · {name(t.tester_id)}</span>
                <StatusBadge status={t.result} label={RESULTS.find((r) => r.value === t.result)?.label} />
              </div>
              {t.sample && <div className="text-xs text-muted-foreground">Sample: {t.sample}</div>}
              {t.findings && <div className="text-xs">{t.findings}</div>}
              {t.nonconformity_id && <a className="text-xs text-primary hover:underline" href={`/nonconformities?open=${t.nonconformity_id}`}>Nonconformity raised</a>}
            </li>
          ))}
        </ul>
      )}
      {mayTest && <Button size="sm" variant="outline" onClick={() => setOpen(true)}><ClipboardCheck /> Record a test</Button>}
      {can("audit.findings") && me?.id === ownerId && <p className="text-xs text-muted-foreground">You own this control, so someone else tests it.</p>}
      {open && <TestDialog controlId={controlId} evidence={evidence} onClose={() => setOpen(false)} />}
    </div>
  );
}

function TestDialog({ controlId, evidence, onClose }: { controlId: number; evidence: any[]; onClose: () => void }) {
  const [f, setF] = useState<any>({ test_type: "operating", method: "inspection", tested_on: new Date().toISOString().slice(0, 10), result: "effective", sample: "", findings: "", evidence_ids: [], raise_nc: true });
  const save = useAction(() => api(`/controls/${controlId}/tests`, { body: { ...f, evidence_ids: f.evidence_ids.map(Number) } }), { success: "Test recorded.", invalidate: INV, onSuccess: onClose });
  const bad = f.result !== "effective";
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} wide title="Record a control test" description="What you checked, how, on which sample, and whether the control worked."
      footer={<Button disabled={bad && !f.findings.trim()} loading={save.isPending} onClick={() => save.mutate(undefined)}>Save test</Button>}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Test"><Select ariaLabel="Test type" value={f.test_type} onChange={(v) => setF({ ...f, test_type: v })} options={TYPES} /></Field>
        <Field label="Method"><Select ariaLabel="Method" value={f.method} onChange={(v) => setF({ ...f, method: v })} options={METHODS} /></Field>
        <Field label="Tested on"><DateInput ariaLabel="Tested on" value={f.tested_on} onChange={(v) => setF({ ...f, tested_on: v })} /></Field>
        <Field label="Result"><Select ariaLabel="Result" value={f.result} onChange={(v) => setF({ ...f, result: v })} options={RESULTS} /></Field>
        <Field label="Sample" className="sm:col-span-2" hint="e.g. 25 of 180 leavers in Q3, picked at random."><Textarea value={f.sample} onChange={(e) => setF({ ...f, sample: e.target.value })} /></Field>
        <Field label={bad ? "What didn't work" : "Notes"} required={bad} className="sm:col-span-2"><Textarea value={f.findings} onChange={(e) => setF({ ...f, findings: e.target.value })} /></Field>
        {evidence.length > 0 && <Field label="Evidence examined" className="sm:col-span-2"><MultiSelect value={f.evidence_ids} onChange={(v) => setF({ ...f, evidence_ids: v })} options={evidence.map((e) => ({ value: String(e.id), label: e.title }))} /></Field>}
        {bad && <label className="flex items-center gap-2 text-sm sm:col-span-2"><input type="checkbox" checked={f.raise_nc} onChange={(e) => setF({ ...f, raise_nc: e.target.checked })} /> Raise a nonconformity for the control owner</label>}
      </div>
    </Dialog>
  );
}

/** The requirements a control satisfies: Keystone's mappings, plus the organisation's own. */
export function ControlMappings({ controlId, mappings }: { controlId: number; mappings: any[] }) {
  const { can } = useAuth();
  const [adding, setAdding] = useState(false);
  const remove = useAction((mid: number) => api(`/control-mappings/${mid}`, { method: "DELETE" }), { success: "Mapping removed.", invalidate: INV });
  const byFw: Record<string, any[]> = {};
  for (const m of mappings) (byFw[m.framework] ??= []).push(m);
  return (
    <div className="space-y-3">
      {mappings.length === 0 && <p className="text-sm text-muted-foreground">Not mapped to any requirement.</p>}
      {Object.entries(byFw).map(([fw, ms]) => (
        <div key={fw}>
          <div className="mb-1 text-xs font-medium text-muted-foreground">{fw}</div>
          <div className="flex flex-wrap gap-1">
            {ms.map((m) => (
              <span key={m.id} title={m.title} className="inline-flex items-center gap-1">
                <Badge tone={m.source === "user" ? "neutral" : "primary"} className="font-mono">{m.ref}{m.source === "user" && " ·"}</Badge>
                {m.source === "user" && can("framework.write") && <button type="button" aria-label={`Remove mapping to ${m.ref}`} className="text-muted-foreground hover:text-critical" onClick={() => remove.mutate(m.id)}><X className="size-3" /></button>}
              </span>
            ))}
          </div>
        </div>
      ))}
      {mappings.some((m) => m.source === "user") && <p className="text-xs text-muted-foreground">Grey references with a dot are your own mappings.</p>}
      {can("framework.write") && <Button size="sm" variant="outline" onClick={() => setAdding(true)}><Plus /> Map to a requirement</Button>}
      {adding && <MappingDialog controlId={controlId} onClose={() => setAdding(false)} />}
    </div>
  );
}

function MappingDialog({ controlId, onClose }: { controlId: number; onClose: () => void }) {
  const { data: fws } = useApi<any[]>("/frameworks");
  const [fw, setFw] = useState<string | null>(null);
  const { data: reqs } = useApi<any>(fw ? `/frameworks/${fw}/requirements` : null);
  const [req, setReq] = useState<string | null>(null);
  const save = useAction(() => api(`/controls/${controlId}/mappings`, { body: { requirement_id: Number(req) } }), { success: "Mapped.", invalidate: INV, onSuccess: onClose });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title="Map to a requirement" description="Record that this control also meets a requirement Keystone doesn't map it to."
      footer={<Button disabled={!req} loading={save.isPending} onClick={() => save.mutate(undefined)}><Link2 /> Map</Button>}>
      <div className="space-y-4">
        <Field label="Framework"><Select ariaLabel="Framework" value={fw} onChange={(v) => { setFw(v); setReq(null); }} options={(fws ?? []).map((f) => ({ value: f.code, label: f.name }))} /></Field>
        {reqs && <Field label="Requirement"><Select ariaLabel="Requirement" value={req} onChange={setReq} options={reqs.requirements.map((r: any) => ({ value: String(r.id), label: `${r.ref} ${r.title}` }))} /></Field>}
      </div>
    </Dialog>
  );
}

/** Accept or reject evidence (not by whoever added it), and choose the other controls it supports. */
export function EvidenceActions({ evidence, controls }: { evidence: any; controls?: { id: number; code: string; title: string }[] }) {
  const { can, me } = useAuth();
  const [rejecting, setRejecting] = useState(false);
  const [linking, setLinking] = useState(false);
  const [note, setNote] = useState("");
  const [ids, setIds] = useState<string[]>((evidence.also_controls ?? []).map((c: any) => String(c.id)));
  const decide = useAction((body: { decision: string; note?: string }) => api(`/evidence/${evidence.id}/decision`, { body }), { success: "Review recorded.", invalidate: INV, onSuccess: () => setRejecting(false) });
  const link = useAction(() => api(`/evidence/${evidence.id}/controls`, { body: { control_ids: [evidence.common_control_id, ...ids.map(Number)] } }), { success: "Saved.", invalidate: INV, onSuccess: () => setLinking(false) });
  if (!can("evidence.write")) return null;
  const own = evidence.created_by_id != null && evidence.created_by_id === me?.id;
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {!own && !evidence.review_decision && evidence.state !== "superseded" && <>
        <Button size="sm" variant="ghost" onClick={() => decide.mutate({ decision: "accepted" })}><Check /> Accept</Button>
        <Button size="sm" variant="ghost" onClick={() => setRejecting(true)}><X /> Reject</Button>
      </>}
      {controls && <Button size="sm" variant="ghost" onClick={() => setLinking(true)}><Link2 /> Controls</Button>}
      {rejecting && (
        <Dialog open onOpenChange={(o) => !o && setRejecting(false)} title={`Reject: ${evidence.title}`} description="Rejected evidence no longer counts for its controls. Say what's wrong so it can be replaced."
          footer={<Button disabled={!note.trim()} loading={decide.isPending} onClick={() => decide.mutate({ decision: "rejected", note })}>Reject</Button>}>
          <Field label="Reason" required><Textarea value={note} onChange={(e) => setNote(e.target.value)} /></Field>
        </Dialog>
      )}
      {linking && controls && (
        <Dialog open onOpenChange={(o) => !o && setLinking(false)} title={`Controls supported by: ${evidence.title}`} description="One piece of evidence can support several controls; it then counts for each of them."
          footer={<Button loading={link.isPending} onClick={() => link.mutate(undefined)}>Save</Button>}>
          <Field label="Also supports"><MultiSelect value={ids} onChange={setIds} options={controls.filter((c) => c.id !== evidence.common_control_id).map((c) => ({ value: String(c.id), label: `${c.code} ${c.title}` }))} /></Field>
        </Dialog>
      )}
    </span>
  );
}
