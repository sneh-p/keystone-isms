import { useState } from "react";
import { Cloud, Github, Globe, Play, Plug, Settings2, ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { Dialog, Sheet } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { PageHeader, Section, Skeleton, Stat, Switch } from "@/components/ui/misc";
import { StatusBadge } from "@/components/ui/status";
import { DataTable } from "@/components/ui/table";

const ICON: Record<string, any> = { website: Globe, github: Github, aws: Cloud, entra: ShieldCheck };

export default function Integrations() {
  const { can } = useAuth();
  const { data } = useApi<any>("/integrations");
  const [connect, setConnect] = useState<any>(null);
  const [open, setOpen] = useState<number | null>(null);
  const save = useAction((b: any) => (b.id ? api(`/integrations/${b.id}`, { method: "PATCH", body: { name: b.name, values: b.values, schedule_hours: b.schedule_hours } }) : api("/integrations", { body: { provider: b.provider, name: b.name, values: b.values, schedule_hours: b.schedule_hours } })), { success: "Integration saved. Run it to see results.", invalidate: ["/integrations"], onSuccess: (r: any) => { setConnect(null); setOpen(r.id); } });
  if (!data) return <Skeleton className="h-96" />;
  const all = data.integrations.flatMap((i: any) => i.results);
  const failing = all.filter((r: any) => r.result === "fail").length;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={Plug} title="Integrations" description="Read-only connections that test your controls automatically. Passing checks become evidence; failing, erroring or unknown checks never count as passing." />
      <div className="mb-5 grid gap-4 sm:grid-cols-4">
        <Stat label="Connected" value={data.integrations.length} />
        <Stat label="Checks passing" value={all.filter((r: any) => r.result === "pass").length} tone="good" />
        <Stat label="Checks failing" value={failing} tone={failing ? "critical" : undefined} />
        <Stat label="Errors or unknown" value={all.filter((r: any) => ["error", "unknown"].includes(r.result)).length} tone={all.some((r: any) => r.result === "error") ? "warning" : undefined} />
      </div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {data.providers.map((p: any) => {
          const Icon = ICON[p.key] ?? Plug;
          const mine = data.integrations.filter((i: any) => i.provider === p.key);
          return (
            <Card key={p.key} className="flex flex-col">
              <CardBody className="flex flex-1 flex-col">
                <div className="flex items-center gap-3"><div className="rounded-lg bg-accent p-2 text-accent-foreground"><Icon className="size-5" /></div><div className="font-semibold leading-tight">{p.name}</div></div>
                <p className="mt-3 flex-1 text-sm text-muted-foreground">{p.description}</p>
                <div className="mt-3 text-xs text-muted-foreground">{p.checks.length} checks · maps to {[...new Set(p.checks.flatMap((c: any) => c.controls))].length} controls</div>
                <div className="mt-4 flex flex-wrap gap-2">
                  {mine.map((i: any) => <Button key={i.id} size="sm" variant="secondary" onClick={() => setOpen(i.id)}>{i.name} <StatusBadge status={i.last_status === "error" ? "error" : i.results.some((r: any) => r.result === "fail") ? "fail" : i.results.length ? "pass" : "unknown"} label=" " /></Button>)}
                  {can("integration.manage") && <Button size="sm" variant="outline" onClick={() => setConnect({ provider: p.key, name: p.name, values: {}, schedule_hours: 24, fields: p.fields })}>Connect</Button>}
                </div>
              </CardBody>
            </Card>
          );
        })}
      </div>
      <Dialog open={!!connect} onOpenChange={(o) => !o && setConnect(null)} title={connect?.id ? `Edit ${connect.name}` : `Connect ${connect?.name}`} description="Use credentials with read-only permissions. Secrets are encrypted and can never be read back; leave a secret empty to keep the stored one."
        footer={<Button loading={save.isPending} onClick={() => save.mutate(connect)}>Save</Button>}>
        {connect && <div className="space-y-4">
          <Field label="Name"><Input value={connect.name} onChange={(e) => setConnect({ ...connect, name: e.target.value })} /></Field>
          {connect.fields.map((f: any) => (
            <Field key={f.name} label={f.label} hint={f.help}><Input type={f.secret ? "password" : "text"} autoComplete="off" placeholder={f.secret && connect.id ? "•••••••• (stored)" : ""} value={connect.values[f.name] ?? ""} onChange={(e) => setConnect({ ...connect, values: { ...connect.values, [f.name]: e.target.value } })} /></Field>
          ))}
          <Field label="Run every (hours)"><Input type="number" min={1} max={720} value={connect.schedule_hours} onChange={(e) => setConnect({ ...connect, schedule_hours: Number(e.target.value) })} /></Field>
        </div>}
      </Dialog>
      {open && <IntegrationDrawer id={open} providers={data.providers} integrations={data.integrations} onClose={() => setOpen(null)} onEdit={(c: any) => setConnect(c)} />}
    </div>
  );
}

function IntegrationDrawer({ id, providers, integrations, onClose, onEdit }: any) {
  const { can } = useAuth();
  const i = integrations.find((x: any) => x.id === id);
  const p = providers.find((x: any) => x.key === i?.provider);
  const hist = useApi<any[]>(`/integrations/${id}/history`);
  const run = useAction(() => api(`/integrations/${id}/run`, { method: "POST" }), { success: "Checks complete.", invalidate: ["/integrations", "/controls", "/evidence", "/dashboard"] });
  const toggle = useAction((v: boolean) => api(`/integrations/${id}`, { method: "PATCH", body: { enabled: v } }), { invalidate: ["/integrations"] });
  if (!i) return null;
  const ed = can("integration.manage");
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} title={i.name} subtitle={`${p?.name} · ${i.last_run_at ? `last run ${fmtDate(i.last_run_at, true)}` : "never run"} · every ${i.schedule_hours}h`}
      actions={ed && <><Button size="sm" variant="outline" onClick={() => onEdit({ id: i.id, provider: i.provider, name: i.name, values: { ...i.config }, schedule_hours: i.schedule_hours, fields: p.fields })}><Settings2 /> Edit</Button><Button size="sm" loading={run.isPending} onClick={() => run.mutate(undefined)}><Play /> Run now</Button></>}>
      <div className="space-y-6">
        {ed && <Switch checked={i.enabled} onChange={(v) => toggle.mutate(v)} label={i.enabled ? "Runs on schedule" : "Paused"} />}
        {i.last_error && <div className="rounded-lg border border-critical/30 bg-critical/5 px-4 py-3 text-sm">{i.last_error}</div>}
        <Section title="Latest results">
          {i.results.length === 0 ? <p className="text-sm text-muted-foreground">Not run yet.</p> : (
            <div className="space-y-2">{i.results.map((r: any) => (
              <div key={r.check_key} className="rounded-lg border p-3">
                <div className="flex items-start justify-between gap-2"><span className="font-medium">{r.title}</span><StatusBadge status={r.result} /></div>
                <p className="mt-1 text-sm text-muted-foreground">{r.summary}</p>
                <div className="mt-2 flex flex-wrap gap-1">{r.controls.map((c: string) => <Badge key={c} tone="primary" className="font-mono text-[10px]">{c}</Badge>)}</div>
              </div>
            ))}</div>
          )}
        </Section>
        <Section title="History">
          <DataTable rows={hist.data ?? []} rowKey={(r: any) => `${r.run_at}${r.check_key}`} empty="No runs yet." columns={[
            { key: "w", header: "When", cell: (r: any) => fmtDate(r.run_at, true) },
            { key: "c", header: "Check", cell: (r: any) => r.title },
            { key: "r", header: "Result", cell: (r: any) => <StatusBadge status={r.result} /> },
          ]} />
        </Section>
      </div>
    </Sheet>
  );
}
