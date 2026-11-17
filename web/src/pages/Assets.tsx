import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { Boxes, CalendarCheck, Link2, Pencil, Plus, Trash2, Unlink } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi, usePeople } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate, titleCase } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, Sheet } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/input";
import { KeyValue, PageHeader, Section, Skeleton } from "@/components/ui/misc";
import { Select } from "@/components/ui/select";
import { DataTable } from "@/components/ui/table";
import { clean, DateInput, EnumSelect, OwnerSelect } from "@/components/forms";
import { Comments } from "@/components/Comments";
import { ImportButton } from "@/components/ImportDialog";

const TYPES = ["information", "application", "hardware", "software", "cloud_service", "service", "people", "site"];
const CLASSES = ["public", "internal", "confidential", "restricted"];
const CIA = [1, 2, 3, 4, 5].map((v) => ({ value: String(v), label: `${v} · ${["Very low", "Low", "Medium", "High", "Very high"][v - 1]}` }));
const CLASS_TONE: Record<string, any> = { public: "outline", internal: "neutral", confidential: "warning", restricted: "critical" };
const INV = ["/assets", "/dashboard", "/calendar"];

const tagsOf = (a: any): string[] => (a.tags ?? "").split(",").map((t: string) => t.trim()).filter(Boolean);
const overdue = (d?: string | null) => !!d && d < new Date().toISOString().slice(0, 10);

/** Asset inventory (ISO 27001 A.5.9): owners, classification, CIA ratings, reviews, and what each asset is linked to. */
export default function Assets() {
  const { can } = useAuth();
  const { name } = usePeople();
  const [params, setParams] = useSearchParams();
  const [retired, setRetired] = useState(false);
  const [tag, setTag] = useState<string | null>(null);
  const { data } = useApi<any[]>(`/assets?include_retired=${retired}`, ["/assets", retired]);
  const [edit, setEdit] = useState<any>(null);
  const save = useAction((f: any) => (f.id ? api(`/assets/${f.id}`, { method: "PATCH", body: strip(f) }) : api<any>("/assets", { body: strip(f) })), {
    success: "Asset saved.", invalidate: INV, onSuccess: (r: any) => { setEdit(null); if (r?.id) setParams({ open: String(r.id) }); },
  });
  if (!data) return <Skeleton className="h-96" />;
  const blank = { name: "", asset_type: "information", classification: "internal", confidentiality: 3, integrity: 3, availability: 3, contains_personal_data: false, owner_id: null, location: "", custodian: "", description: "", status: "active", tags: "" };
  const allTags = [...new Set(data.flatMap(tagsOf))].sort();
  const rows = tag ? data.filter((a) => tagsOf(a).includes(tag)) : data;
  const open = params.get("open");
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Boxes} title="Assets" description="Information, systems, services and sites in scope, with owners, CIA ratings and reviews. Open an asset to see the risks, incidents, vendors, processes and devices linked to it."
        actions={can("asset.write") && <><ImportButton register="assets" noun="assets" invalidate={INV} /><Button onClick={() => setEdit(blank)}><Plus /> New asset</Button></>} />
      <DataTable
        rows={rows}
        rowKey={(a: any) => a.id}
        onRowClick={(a: any) => setParams({ open: String(a.id) })}
        rowLabel={(a: any) => a.name}
        search={(a: any) => `${a.name} ${a.asset_type} ${a.location ?? ""} ${a.tags ?? ""}`}
        toolbar={<div className="flex flex-wrap items-center gap-3">
          {allTags.length > 0 && <Select ariaLabel="Tag" value={tag} onChange={setTag} allowEmpty emptyLabel="All tags" options={allTags.map((t) => ({ value: t, label: t }))} className="w-40" />}
          <label className="flex items-center gap-2 text-sm text-muted-foreground"><input type="checkbox" checked={retired} onChange={(e) => setRetired(e.target.checked)} /> Include retired</label>
        </div>}
        columns={[
          { key: "name", header: "Asset", cell: (a: any) => <div><div className="font-medium">{a.name}</div><div className="text-xs text-muted-foreground">{titleCase(a.asset_type)}{a.location ? ` · ${a.location}` : ""}</div></div>, sort: (a: any) => a.name },
          { key: "owner", header: "Owner", cell: (a: any) => name(a.owner_id) },
          { key: "class", header: "Classification", cell: (a: any) => <Badge tone={CLASS_TONE[a.classification]}>{titleCase(a.classification)}</Badge>, sort: (a: any) => CLASSES.indexOf(a.classification) },
          { key: "cia", header: "C / I / A", cell: (a: any) => <span className="tabular-nums">{a.confidentiality} / {a.integrity} / {a.availability}</span> },
          { key: "crit", header: "Criticality", cell: (a: any) => <span className="font-semibold tabular-nums">{a.criticality}</span>, sort: (a: any) => a.criticality },
          { key: "pii", header: "Personal data", cell: (a: any) => (a.contains_personal_data ? <Badge tone="warning">Yes</Badge> : "No") },
          { key: "review", header: "Next review", cell: (a: any) => (a.review_date ? <span className={overdue(a.review_date) ? "font-medium text-critical" : ""}>{fmtDate(a.review_date)}</span> : <span className="text-muted-foreground">Not set</span>), sort: (a: any) => a.review_date ?? "9999" },
          { key: "status", header: "Status", cell: (a: any) => titleCase(a.status) },
        ]}
      />
      {open && <AssetDrawer id={Number(open)} onClose={() => setParams({})} onEdit={(a) => setEdit({ ...a })} />}
      <Dialog open={!!edit} onOpenChange={(o) => !o && setEdit(null)} wide title={edit?.id ? `Edit ${edit.name}` : "New asset"} footer={<Button loading={save.isPending} onClick={() => save.mutate(edit)}>Save asset</Button>}>
        {edit && (
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Name" required className="sm:col-span-2"><Input value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.target.value })} /></Field>
            <Field label="Type"><EnumSelect value={edit.asset_type} onChange={(v) => setEdit({ ...edit, asset_type: v })} values={TYPES} /></Field>
            <Field label="Classification"><EnumSelect value={edit.classification} onChange={(v) => setEdit({ ...edit, classification: v })} values={CLASSES} /></Field>
            <Field label="Owner"><OwnerSelect value={edit.owner_id} onChange={(v) => setEdit({ ...edit, owner_id: v })} /></Field>
            <Field label="Status"><EnumSelect value={edit.status} onChange={(v) => setEdit({ ...edit, status: v, disposed_on: v === "retired" ? edit.disposed_on : null })} values={["active", "planned", "retired"]} /></Field>
            {(["confidentiality", "integrity", "availability"] as const).map((k) => (
              <Field key={k} label={titleCase(k)}><Select value={String(edit[k])} onChange={(v) => setEdit({ ...edit, [k]: Number(v) })} options={CIA} /></Field>
            ))}
            <Field label="Location"><Input value={edit.location ?? ""} onChange={(e) => setEdit({ ...edit, location: e.target.value })} /></Field>
            <Field label="Custodian"><Input value={edit.custodian ?? ""} onChange={(e) => setEdit({ ...edit, custodian: e.target.value })} /></Field>
            <Field label="Tags" hint="Separate with commas."><Input value={edit.tags ?? ""} onChange={(e) => setEdit({ ...edit, tags: e.target.value })} /></Field>
            <Field label="Next review"><DateInput ariaLabel="Next review" value={edit.review_date ?? null} onChange={(v) => setEdit({ ...edit, review_date: v })} /></Field>
            <Field label="Acquired"><DateInput ariaLabel="Acquired" value={edit.acquired_on ?? null} onChange={(v) => setEdit({ ...edit, acquired_on: v })} /></Field>
            {edit.status === "retired" && <Field label="Disposed of" hint="When the asset was securely disposed of or returned."><DateInput ariaLabel="Disposed of" value={edit.disposed_on ?? null} onChange={(v) => setEdit({ ...edit, disposed_on: v })} /></Field>}
            <label className="flex items-center gap-2 text-sm sm:col-span-2"><input type="checkbox" checked={edit.contains_personal_data} onChange={(e) => setEdit({ ...edit, contains_personal_data: e.target.checked })} /> Contains personal data</label>
            <Field label="Description" className="sm:col-span-2"><Textarea value={edit.description ?? ""} onChange={(e) => setEdit({ ...edit, description: e.target.value })} /></Field>
          </div>
        )}
      </Dialog>
    </div>
  );
}

function AssetDrawer({ id, onClose, onEdit }: { id: number; onClose: () => void; onEdit: (a: any) => void }) {
  const { data: a } = useApi<any>(`/assets/${id}`);
  const { can } = useAuth();
  const { name } = usePeople();
  const review = useAction(() => api(`/assets/${id}/review`, { method: "POST" }), { success: "Reviewed. The next review is in a year.", invalidate: INV });
  const device = useAction((v: { device_id: number; linked: boolean }) => api(`/assets/${id}/devices`, { body: v }), { success: "Saved.", invalidate: INV });
  const remove = useAction(() => api(`/assets/${id}`, { method: "DELETE" }), { success: "Asset deleted.", invalidate: INV, onSuccess: onClose });
  const ed = can("asset.write");
  const l = a?.links;
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={a?.name ?? "…"} subtitle={a && <span className="flex flex-wrap items-center gap-2"><Badge tone={CLASS_TONE[a.classification]}>{titleCase(a.classification)}</Badge>{titleCase(a.asset_type)} · {titleCase(a.status)}</span>}
      actions={a && ed && <>
        <Button size="sm" variant="outline" onClick={() => onEdit(a)}><Pencil /> Edit</Button>
        {a.status === "active" && <Button size="sm" variant="outline" loading={review.isPending} onClick={() => review.mutate(undefined)}><CalendarCheck /> Mark reviewed</Button>}
        <Button size="sm" variant="outline" loading={remove.isPending} onClick={() => window.confirm(`Delete ${a.name}? Use this only for an asset added by mistake; retire it otherwise.`) && remove.mutate(undefined)}><Trash2 /> Delete</Button>
      </>}>
      {!a ? <Skeleton className="h-64" /> : (
        <div className="space-y-6">
          <KeyValue items={[
            ["Owner", name(a.owner_id)], ["Custodian", a.custodian || "—"], ["Location", a.location || "—"],
            ["C / I / A", `${a.confidentiality} / ${a.integrity} / ${a.availability} (criticality ${a.criticality})`],
            ["Personal data", a.contains_personal_data ? "Yes" : "No"],
            ["Next review", a.review_date ? <span key="r" className={overdue(a.review_date) ? "font-medium text-critical" : ""}>{fmtDate(a.review_date)}{overdue(a.review_date) ? " (overdue)" : ""}</span> : "Not set"],
            ["Last reviewed", a.last_reviewed_at ? fmtDate(a.last_reviewed_at, true) : "Never"],
            ["Acquired", fmtDate(a.acquired_on) || "—"], ...(a.disposed_on ? [["Disposed of", fmtDate(a.disposed_on)] as [string, string]] : []),
            ["Tags", tagsOf(a).length ? <span key="t" className="flex flex-wrap gap-1">{tagsOf(a).map((t) => <Badge key={t} tone="outline">{t}</Badge>)}</span> : "—"],
          ]} />
          {a.description && <p className="whitespace-pre-wrap text-sm">{a.description}</p>}
          <Section title="Risks">
            <Linked items={l.risks} empty="No risks name this asset." render={(r: any) => <Link to={`/risks?open=${r.id}`} className="text-primary hover:underline">{r.ref} {r.title}</Link>} extra={(r: any) => r.level && <Badge tone="outline">{titleCase(r.level)}</Badge>} />
          </Section>
          <Section title="Incidents">
            <Linked items={l.incidents} empty="No incidents involved this asset." render={(i: any) => <Link to={`/incidents?open=${i.id}`} className="text-primary hover:underline">{i.ref} {i.title}</Link>} extra={(i: any) => <Badge tone="outline">{titleCase(i.status)}</Badge>} />
          </Section>
          <Section title="Vendors">
            <Linked items={l.vendors} empty="No vendor hosts or supports it." render={(v: any) => <Link to={`/vendors?open=${v.id}`} className="text-primary hover:underline">{v.name}</Link>} extra={(v: any) => titleCase(v.status)} />
          </Section>
          <Section title="Business processes">
            <Linked items={l.processes} empty="No business process depends on it." render={(p: any) => <Link to="/continuity" className="text-primary hover:underline">{p.name}</Link>} extra={(p: any) => p.rto_hours != null && `RTO ${p.rto_hours} h`} />
          </Section>
          <Section title="Configuration checks">
            <Linked items={l.config_targets} empty="No host or firewall is linked. Link one from its page under Configuration." render={(t: any) => <Link to={`/configuration?target=${t.id}`} className="text-primary hover:underline">{t.name}</Link>}
              extra={(t: any) => <span className="text-xs">{t.counts.fail} failing · {t.counts.pass} passing</span>} />
          </Section>
          <Section title="Devices (attack surface)">
            <Linked items={l.devices} empty="No device from your connected tools is linked." render={(d: any) => <Link to="/attack-surface?tab=devices" className="text-primary hover:underline">{d.name}</Link>}
              extra={(d: any) => <span className="flex items-center gap-2 text-xs">{d.os}{ed && <Button size="sm" variant="ghost" aria-label={`Unlink ${d.name}`} onClick={() => device.mutate({ device_id: d.id, linked: false })}><Unlink /></Button>}</span>} />
            {ed && l.device_suggestions.length > 0 && (
              <div className="mt-2 flex flex-wrap items-center gap-1 text-xs text-muted-foreground">Matching devices:
                {l.device_suggestions.map((d: any) => <Button key={d.id} size="sm" variant="outline" onClick={() => device.mutate({ device_id: d.id, linked: true })}><Link2 /> {d.name}</Button>)}
              </div>
            )}
          </Section>
          <Section title="Discussion"><Comments kind="asset" id={a.id} /></Section>
        </div>
      )}
    </Sheet>
  );
}

function Linked({ items, empty, render, extra }: { items: any[]; empty: string; render: (x: any) => any; extra?: (x: any) => any }) {
  if (!items.length) return <p className="text-sm text-muted-foreground">{empty}</p>;
  return <ul className="divide-y rounded-md border">{items.map((x) => <li key={x.id} className="flex items-center justify-between gap-3 px-3 py-2 text-sm"><span className="min-w-0">{render(x)}</span>{extra && <span className="shrink-0">{extra(x)}</span>}</li>)}</ul>;
}

function strip(f: any) {
  const { id: _id, criticality: _c, ref: _r, links: _l, last_reviewed_at: _lr, ...rest } = f;
  return clean(rest);
}
