import { Link, useNavigate } from "react-router-dom";
import { AlertTriangle, ArrowRight, CheckCircle2, Gauge, Handshake, LayoutDashboard, ShieldCheck, Siren, Wrench } from "lucide-react";
import { useApi } from "@/lib/hooks";
import { fmtDate, daysUntil, cn } from "@/lib/utils";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { PageHeader, Progress, Skeleton, Stat, Empty } from "@/components/ui/misc";
import { HeatMap } from "@/components/viz/HeatMap";
import { StatusBar, CONTROL_SEGMENTS } from "@/components/viz/StatusBar";
import { Button } from "@/components/ui/button";

const PAGE_FOR: Record<string, string> = {
  "pages/incidents.py": "/incidents", "pages/risks.py": "/risks", "pages/nonconformities.py": "/nonconformities", "pages/controls.py": "/controls",
  "pages/evidence.py": "/evidence", "pages/vendors.py": "/vendors", "pages/policies.py": "/policies",
};

export default function Dashboard() {
  const { data, isLoading } = useApi<any>("/dashboard");
  const matrix = useApi<any>("/risk-matrix");
  const nav = useNavigate();
  if (isLoading || !data) return <div className="space-y-4"><Skeleton className="h-10 w-72" /><div className="grid gap-4 md:grid-cols-4">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-24" />)}</div><Skeleton className="h-72" /></div>;
  const lv = data.risk_levels;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={LayoutDashboard} title={data.org?.name ?? "Overview"} description={data.org ? (data.org.scope_approved ? "ISMS scope approved." : "ISMS scope not approved yet.") : "Start by setting up your organisation."}
        actions={!data.org && <Button onClick={() => nav("/onboarding")}>Start setup <ArrowRight /></Button>} />
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <Stat label="Open risks" value={data.open_risks} icon={Gauge} hint={`${lv.Critical + lv.High} critical or high`} tone={lv.Critical ? "critical" : undefined} />
        <Stat label="Open incidents" value={data.open_incidents} icon={Siren} tone={data.open_incidents ? "warning" : undefined} />
        <Stat label="Open nonconformities" value={data.open_ncs} icon={Wrench} />
        <Stat label="Vendors" value={data.vendors} icon={Handshake} />
        <Stat label="Controls audited (3 yrs)" value={`${data.audit_coverage_pct}%`} icon={ShieldCheck} />
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader title="Framework readiness" description="Share of requirements whose mapped controls are implemented." action={<Link to="/frameworks" className="text-sm text-primary hover:underline">All frameworks</Link>} />
          <CardBody className="space-y-5">
            {data.coverage.length === 0 && <Empty title="No frameworks loaded" action={<Button onClick={() => nav("/frameworks")}>Load frameworks</Button>} />}
            {data.coverage.map((c: any) => (
              <div key={c.name}>
                <div className="mb-1.5 flex items-baseline justify-between text-sm">
                  <span className="font-medium">{c.name}</span>
                  <span className="tabular-nums text-muted-foreground"><span className="font-semibold text-foreground">{c.implemented_pct}%</span> implemented · {c.applicable} requirements</span>
                </div>
                <Progress value={c.progress_pct} tone={c.implemented_pct >= 80 ? "good" : "primary"} />
              </div>
            ))}
            <div className="border-t pt-4">
              <div className="mb-2 text-sm font-medium">Control implementation</div>
              <StatusBar segments={CONTROL_SEGMENTS(data.control_status)} />
            </div>
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Risk posture" description="Residual where assessed, otherwise inherent." action={<Link to="/risks" className="text-sm text-primary hover:underline">Register</Link>} />
          <CardBody className="flex justify-center">
            {matrix.data && <HeatMap grid={data.current_grid} levels={matrix.data.grid} title="" likelihood={matrix.data.likelihood} impact={matrix.data.impact} onCell={() => nav("/risks")} />}
          </CardBody>
        </Card>
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader title="Needs attention" description="Overdue and missing items across the ISMS." />
          <CardBody className="p-0">
            {data.attention.length === 0 ? (
              <div className="flex items-center gap-2 p-5 text-sm text-muted-foreground"><CheckCircle2 className="size-4 text-good" /> Nothing overdue.</div>
            ) : (
              <ul className="divide-y">
                {data.attention.map((a: any, i: number) => (
                  <li key={i}>
                    <Link to={PAGE_FOR[a.page] ?? "/"} className="flex items-center gap-3 px-5 py-3 text-sm hover:bg-muted/50">
                      <span className="grid size-7 shrink-0 place-items-center rounded-full bg-warning/15 text-xs font-semibold text-[#8a5a00] dark:text-warning">{a.count}</span>
                      <span className="flex-1">{a.text}</span>
                      <ArrowRight className="size-4 text-muted-foreground" />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>
        <Card>
          <CardHeader title={`My tasks (${data.my_tasks.length})`} description="Assigned to you or waiting on your approval." />
          <CardBody className="p-0">
            {data.my_tasks.length === 0 ? (
              <div className="p-5 text-sm text-muted-foreground">You're all caught up.</div>
            ) : (
              <ul className="divide-y">
                {data.my_tasks.map((t: any, i: number) => {
                  const d = daysUntil(t.due);
                  return (
                    <li key={i}>
                      <Link to={PAGE_FOR[t.page] ?? "/"} className="flex items-center gap-3 px-5 py-3 text-sm hover:bg-muted/50">
                        {d !== null && d < 0 ? <AlertTriangle className="size-4 shrink-0 text-critical" /> : <CheckCircle2 className="size-4 shrink-0 text-muted-foreground" />}
                        <span className="flex-1">{t.what}</span>
                        <span className={cn("whitespace-nowrap text-xs", d !== null && d < 0 ? "font-medium text-critical" : "text-muted-foreground")}>{t.due ? fmtDate(t.due) : ""}</span>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
