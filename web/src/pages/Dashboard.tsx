import { Link, useNavigate } from "react-router-dom";
import { AlertTriangle, ArrowRight, CheckCircle2, Gauge, Handshake, LayoutDashboard, ShieldCheck, Siren, Wrench } from "lucide-react";
import { useApi } from "@/lib/hooks";
import { fmtDate, daysUntil, cn } from "@/lib/utils";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { PageHeader, Progress, Skeleton, Stat, Empty, type StatTrend } from "@/components/ui/misc";
import { HeatMap } from "@/components/viz/HeatMap";
import { StatusBar, CONTROL_SEGMENTS } from "@/components/viz/StatusBar";
import { Button } from "@/components/ui/button";

export default function Dashboard() {
  const { data, isLoading } = useApi<any>("/dashboard");
  const onb = useApi<any>("/onboarding");
  const matrix = useApi<any>("/risk-matrix");
  const nav = useNavigate();
  if (isLoading || !data) return <div className="space-y-4"><Skeleton className="h-10 w-72" /><div className="grid gap-4 md:grid-cols-4">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-24" />)}</div><Skeleton className="h-72" /></div>;
  const lv = data.risk_levels;
  const trend = (key: string, upIsGood: boolean | null): StatTrend | undefined =>
    data.trend?.series?.[key] ? { values: data.trend.series[key], days: data.trend.days, upIsGood } : undefined;
  return (
    <div className="animate-fade-in">
      <PageHeader icon={LayoutDashboard} title={data.org?.name ?? "Overview"} description={data.org ? (data.org.scope_approved ? "ISMS scope approved." : "ISMS scope not approved yet.") : "Start by setting up your organisation."}
        actions={!data.org && <Button onClick={() => nav("/onboarding")}>Start setup <ArrowRight /></Button>} />
      {onb.data && !onb.data.completed && (
        <Card className="mb-6 overflow-hidden border-primary/30">
          <div className="flex flex-wrap items-center justify-between gap-4 bg-gradient-to-r from-indigo-600 to-violet-600 px-6 py-5 text-white">
            <div><div className="text-lg font-semibold">Set up your ISMS in a few minutes</div><div className="text-sm text-white/80">Answer a few questions and Keystone drafts your policies, schedules evidence tasks and tailors your controls.</div></div>
            <Button variant="secondary" onClick={() => nav("/onboarding")}>Start setup <ArrowRight /></Button>
          </div>
        </Card>
      )}
      {data.next_steps.length > 0 && (
        <Card className="mb-6">
          <CardHeader title="Next steps" description="The gaps that move readiness most, in the order to tackle them." />
          <CardBody className="p-0">
            <ol className="grid divide-y sm:grid-cols-2 sm:divide-y-0 lg:grid-cols-4 lg:divide-x">
              {data.next_steps.map((s: any, i: number) => (
                <li key={s.key} className="sm:border-t sm:[&:nth-child(-n+2)]:border-t-0 lg:border-t-0">
                  <Link to={s.page} className="flex h-full gap-3 p-4 hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring">
                    <span className="grid size-6 shrink-0 place-items-center rounded-full bg-primary/10 text-xs font-semibold text-primary" aria-hidden>{i + 1}</span>
                    <span className="min-w-0">
                      <span className="block text-sm font-medium">{s.title}</span>
                      <span className="mt-0.5 block text-xs text-muted-foreground">{s.detail}</span>
                    </span>
                  </Link>
                </li>
              ))}
            </ol>
          </CardBody>
        </Card>
      )}
      <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-5">
        <Stat label="Open risks" value={data.open_risks} icon={Gauge} to="/risks" hint={`${lv.Critical + lv.High} critical or high`} tone={lv.Critical ? "critical" : undefined} trend={trend("open_risks", false)} />
        <Stat label="Open incidents" value={data.open_incidents} icon={Siren} to="/incidents" tone={data.open_incidents ? "warning" : undefined} trend={trend("open_incidents", false)} />
        <Stat label="Open nonconformities" value={data.open_ncs} icon={Wrench} to="/nonconformities" trend={trend("open_ncs", false)} />
        <Stat label="Vendors" value={data.vendors} icon={Handshake} to="/vendors" trend={trend("vendors", null)} />
        <Stat label="Controls audited in 3 years" value={<>{data.audit_coverage.audited} <span className="text-base font-normal text-muted-foreground">of {data.audit_coverage.applicable}</span></>} icon={ShieldCheck} to="/audits"
          hint={`${data.audit_coverage_pct}% of applicable controls`} trend={trend("controls_audited", true)} />
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
                <Progress label={`${c.name} readiness`} value={c.progress_pct} tone={c.implemented_pct >= 80 ? "good" : "primary"} />
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
                    <Link to={a.page ?? "/"} className="flex items-center gap-3 px-5 py-3 text-sm hover:bg-muted/50">
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
                      <Link to={t.page ?? "/"} className="flex items-center gap-3 px-5 py-3 text-sm hover:bg-muted/50">
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
