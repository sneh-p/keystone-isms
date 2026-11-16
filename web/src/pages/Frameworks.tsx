import { useState } from "react";
import { Link, useParams } from "react-router";
import { BookOpen, ChevronLeft, Download, Upload } from "lucide-react";
import { api, upload } from "@/lib/api";
import { useAction, useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Empty, PageHeader, Progress, Skeleton, Switch } from "@/components/ui/misc";
import { StatusBadge } from "@/components/ui/status";
import { DataTable } from "@/components/ui/table";
import { Dialog } from "@/components/ui/dialog";
import { toast } from "sonner";

const LICENCE: Record<string, string> = { public_domain: "Full text", proprietary: "IDs + summaries", cc_by_nc_nd: "IDs + titles" };

export function Frameworks() {
  const { can } = useAuth();
  const { data, isLoading } = useApi<any[]>("/frameworks?all=true", ["/frameworks", "all"]);
  const seed = useAction(() => api("/frameworks/seed", { method: "POST" }), { success: "Frameworks and controls loaded.", invalidate: ["/"] });
  const toggle = useAction((v: { code: string; enabled: boolean }) => api(`/frameworks/${v.code}`, { method: "PATCH", body: { enabled: v.enabled } }), { invalidate: ["/frameworks", "/dashboard"] });
  if (isLoading) return <Skeleton className="h-64" />;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={BookOpen} title="Frameworks" description="One set of common controls, mapped to every framework. Implement once, comply many times."
        actions={can("framework.write") && <Button variant="outline" loading={seed.isPending} onClick={() => seed.mutate(undefined)}>{data?.length ? "Re-apply bundled content" : "Load frameworks"}</Button>} />
      {!data?.length ? (
        <Empty icon={BookOpen} title="No frameworks loaded yet" action={can("framework.write") && <Button onClick={() => seed.mutate(undefined)} loading={seed.isPending}>Load ISO 27001, NIST CSF, SOC 2 and CIS</Button>}>
          Loads four frameworks, 107 common controls and the crosswalk between them.
        </Empty>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          {data.map((f) => (
            <Card key={f.code} className={f.enabled ? "" : "opacity-60"}>
              <CardBody>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <Link to={`/frameworks/${f.code}`} className="text-lg font-semibold hover:text-primary">{f.name}</Link>
                    <div className="mt-0.5 text-sm text-muted-foreground">{f.publisher} · version {f.version}</div>
                  </div>
                  <Badge tone="outline">{LICENCE[f.license] ?? f.license}</Badge>
                </div>
                <div className="mt-5 flex items-end justify-between">
                  <div>
                    <div className="text-3xl font-semibold tabular-nums">{f.coverage.implemented_pct}%</div>
                    <div className="text-xs text-muted-foreground">implemented · {f.coverage.applicable} requirements</div>
                  </div>
                  <div className="text-right text-xs text-muted-foreground">{f.coverage.progress_pct}% incl. partial</div>
                </div>
                <Progress label={`${f.name} readiness`} className="mt-3" value={f.coverage.progress_pct} tone={f.coverage.implemented_pct >= 80 ? "good" : "primary"} />
                <div className="mt-4 flex items-center justify-between">
                  <Link to={`/frameworks/${f.code}`} className="text-sm font-medium text-primary hover:underline">View requirements</Link>
                  {can("framework.write") && <Switch checked={f.enabled} onChange={(v) => toggle.mutate({ code: f.code, enabled: v })} label={<span className="text-xs text-muted-foreground">In use</span>} />}
                </div>
              </CardBody>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

export function FrameworkDetail() {
  const { code } = useParams();
  const { can } = useAuth();
  const { data } = useApi<any>(`/frameworks/${code}/requirements`);
  const [imp, setImp] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const doImport = useAction(async () => {
    const fd = new FormData();
    fd.append("file", file as File);
    return upload(`/frameworks/${code}/licensed-text`, fd);
  }, { success: (r: any) => `Imported ${r.updated} requirement texts.`, invalidate: ["/frameworks"], onSuccess: (r: any) => { setImp(false); if (r.unknown_refs?.length) toast.warning(`Unknown refs: ${r.unknown_refs.slice(0, 10).join(", ")}`); } });
  if (!data) return <Skeleton className="h-96" />;
  const groups = new Map<string, any>(data.groups.map((g: any) => [g.ref, g]));
  return (
    <div className="animate-fade-in">
      <Link to="/frameworks" className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"><ChevronLeft className="size-4" /> Frameworks</Link>
      <PageHeader title={`${data.framework.name} ${data.framework.version}`} description={data.framework.notice}
        actions={can("framework.write") && data.framework.license !== "public_domain" && <Button variant="outline" onClick={() => setImp(true)}><Upload /> Import licensed text</Button>} />
      <div className="mb-5 grid gap-4 sm:grid-cols-3">
        <Card><CardBody><div className="text-sm text-muted-foreground">Requirements</div><div className="mt-1 text-2xl font-semibold">{data.summary.total}</div></CardBody></Card>
        <Card><CardBody><div className="text-sm text-muted-foreground">Implemented</div><div className="mt-1 text-2xl font-semibold">{data.summary.implemented_pct}%</div></CardBody></Card>
        <Card><CardBody><div className="text-sm text-muted-foreground">Progress (partial = ½)</div><div className="mt-1 text-2xl font-semibold">{data.summary.progress_pct}%</div></CardBody></Card>
      </div>
      <DataTable
        rows={data.requirements}
        rowKey={(r: any) => r.id}
        search={(r: any) => `${r.ref} ${r.title} ${r.controls.map((c: any) => c.code).join(" ")}`}
        columns={[
          { key: "ref", header: "Ref", cell: (r: any) => <span className="font-mono text-xs">{r.ref}</span>, sort: (r: any) => r.ref, className: "w-28" },
          { key: "title", header: "Requirement", cell: (r: any) => <div><div>{r.title}</div>{r.parent_ref && <div className="mt-0.5 text-xs text-muted-foreground">{groups.get(r.parent_ref)?.title ?? r.parent_ref}</div>}</div> },
          { key: "controls", header: "Controls", cell: (r: any) => <div className="flex flex-wrap gap-1">{r.controls.map((c: any) => <Link key={c.id} to={`/controls?open=${c.id}`}><Badge tone="primary">{c.code}</Badge></Link>)}</div> },
          { key: "status", header: "Status", cell: (r: any) => <StatusBadge status={r.status} />, sort: (r: any) => r.status },
        ]}
      />
      <Dialog open={imp} onOpenChange={setImp} title="Import licensed text" description="Upload CSV (ref,text) or YAML/JSON [{ref, text}] from your licensed copy. Stored only in your database."
        footer={<><Button variant="ghost" onClick={() => setImp(false)}>Cancel</Button><Button disabled={!file} loading={doImport.isPending} onClick={() => doImport.mutate(undefined)}><Download /> Import</Button></>}>
        <input type="file" accept=".csv,.yaml,.yml,.json" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="text-sm" />
      </Dialog>
    </div>
  );
}
