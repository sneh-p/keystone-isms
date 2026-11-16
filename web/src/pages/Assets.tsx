import { useState } from "react";
import { Boxes, Plus } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi, usePeople } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { titleCase } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { PageHeader, Skeleton } from "@/components/ui/misc";
import { Select } from "@/components/ui/select";
import { DataTable } from "@/components/ui/table";
import { clean, EnumSelect, OwnerSelect } from "@/components/forms";

const TYPES = ["information", "application", "hardware", "software", "cloud_service", "service", "people", "site"];
const CLASSES = ["public", "internal", "confidential", "restricted"];
const CIA = [1, 2, 3, 4, 5].map((v) => ({ value: String(v), label: `${v} · ${["Very low", "Low", "Medium", "High", "Very high"][v - 1]}` }));
const CLASS_TONE: Record<string, any> = { public: "outline", internal: "neutral", confidential: "warning", restricted: "critical" };

export default function Assets() {
  const { can } = useAuth();
  const { name } = usePeople();
  const [retired, setRetired] = useState(false);
  const { data } = useApi<any[]>(`/assets?include_retired=${retired}`, ["/assets", retired]);
  const [edit, setEdit] = useState<any>(null);
  const save = useAction((f: any) => (f.id ? api(`/assets/${f.id}`, { method: "PATCH", body: strip(f) }) : api("/assets", { body: strip(f) })), { success: "Asset saved.", invalidate: ["/assets"], onSuccess: () => setEdit(null) });
  if (!data) return <Skeleton className="h-96" />;
  const blank = { name: "", asset_type: "information", classification: "internal", confidentiality: 3, integrity: 3, availability: 3, contains_personal_data: false, owner_id: null, location: "", custodian: "", description: "", status: "active", tags: "" };
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Boxes} title="Assets" description="Information, systems, services and sites in scope, with owners and CIA ratings." actions={can("asset.write") && <Button onClick={() => setEdit(blank)}><Plus /> New asset</Button>} />
      <DataTable
        rows={data}
        rowKey={(a: any) => a.id}
        onRowClick={can("asset.write") ? (a: any) => setEdit({ ...a }) : undefined}
        search={(a: any) => `${a.name} ${a.asset_type} ${a.location ?? ""} ${a.tags ?? ""}`}
        toolbar={<label className="flex items-center gap-2 text-sm text-muted-foreground"><input type="checkbox" checked={retired} onChange={(e) => setRetired(e.target.checked)} /> Include retired</label>}
        columns={[
          { key: "name", header: "Asset", cell: (a: any) => <div><div className="font-medium">{a.name}</div><div className="text-xs text-muted-foreground">{titleCase(a.asset_type)}{a.location ? ` · ${a.location}` : ""}</div></div>, sort: (a: any) => a.name },
          { key: "owner", header: "Owner", cell: (a: any) => name(a.owner_id) },
          { key: "class", header: "Classification", cell: (a: any) => <Badge tone={CLASS_TONE[a.classification]}>{titleCase(a.classification)}</Badge>, sort: (a: any) => CLASSES.indexOf(a.classification) },
          { key: "cia", header: "C / I / A", cell: (a: any) => <span className="tabular-nums">{a.confidentiality} / {a.integrity} / {a.availability}</span> },
          { key: "crit", header: "Criticality", cell: (a: any) => <span className="font-semibold tabular-nums">{a.criticality}</span>, sort: (a: any) => a.criticality },
          { key: "pii", header: "Personal data", cell: (a: any) => (a.contains_personal_data ? <Badge tone="warning">Yes</Badge> : "No") },
          { key: "status", header: "Status", cell: (a: any) => titleCase(a.status) },
        ]}
      />
      <Dialog open={!!edit} onOpenChange={(o) => !o && setEdit(null)} wide title={edit?.id ? `Edit ${edit.name}` : "New asset"} footer={<Button loading={save.isPending} onClick={() => save.mutate(edit)}>Save asset</Button>}>
        {edit && (
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Name" required className="sm:col-span-2"><Input value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.target.value })} /></Field>
            <Field label="Type"><EnumSelect value={edit.asset_type} onChange={(v) => setEdit({ ...edit, asset_type: v })} values={TYPES} /></Field>
            <Field label="Classification"><EnumSelect value={edit.classification} onChange={(v) => setEdit({ ...edit, classification: v })} values={CLASSES} /></Field>
            <Field label="Owner"><OwnerSelect value={edit.owner_id} onChange={(v) => setEdit({ ...edit, owner_id: v })} /></Field>
            <Field label="Status"><EnumSelect value={edit.status} onChange={(v) => setEdit({ ...edit, status: v })} values={["active", "planned", "retired"]} /></Field>
            {(["confidentiality", "integrity", "availability"] as const).map((k) => (
              <Field key={k} label={titleCase(k)}><Select value={String(edit[k])} onChange={(v) => setEdit({ ...edit, [k]: Number(v) })} options={CIA} /></Field>
            ))}
            <Field label="Location"><Input value={edit.location ?? ""} onChange={(e) => setEdit({ ...edit, location: e.target.value })} /></Field>
            <Field label="Custodian"><Input value={edit.custodian ?? ""} onChange={(e) => setEdit({ ...edit, custodian: e.target.value })} /></Field>
            <label className="flex items-center gap-2 text-sm sm:col-span-2"><input type="checkbox" checked={edit.contains_personal_data} onChange={(e) => setEdit({ ...edit, contains_personal_data: e.target.checked })} /> Contains personal data</label>
            <Field label="Description" className="sm:col-span-2"><Textarea value={edit.description ?? ""} onChange={(e) => setEdit({ ...edit, description: e.target.value })} /></Field>
          </div>
        )}
      </Dialog>
    </div>
  );
}

function strip(f: any) {
  const { id: _id, criticality: _c, ref: _r, ...rest } = f;
  return clean(rest);
}
