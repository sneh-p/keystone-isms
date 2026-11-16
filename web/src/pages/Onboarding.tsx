import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { ArrowLeft, ArrowRight, Check, Cloud, Code2, Building, Sparkles } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi } from "@/lib/hooks";
import { fmtDate } from "@/lib/utils";
import { useAuth } from "@/lib/auth";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { OwnerSelect } from "@/components/forms";

const STEPS = ["Company", "Systems", "Data & work", "Frameworks", "Team", "Review"];
const DATA = [
  { value: "customer_personal", label: "Customer personal data" },
  { value: "employee", label: "Employee data" },
  { value: "payment_cards", label: "Payment card data" },
  { value: "health", label: "Health data" },
  { value: "intellectual_property", label: "Intellectual property / trade secrets" },
];
const FW = [
  { code: "ISO27001_2022", name: "ISO/IEC 27001:2022", hint: "Certifiable ISMS standard" },
  { code: "SOC2_TSC_2017", name: "SOC 2", hint: "Trust Services Criteria for service organisations" },
  { code: "NIST_CSF_2_0", name: "NIST CSF 2.0", hint: "Outcome-based cybersecurity framework" },
  { code: "CIS_V8_1", name: "CIS Controls v8.1", hint: "Prioritised technical safeguards" },
  { code: "NIS2", name: "NIS2", hint: "EU cybersecurity duties for essential and important entities" },
  { code: "DORA", name: "DORA", hint: "EU digital operational resilience for financial entities" },
  { code: "GDPR", name: "GDPR", hint: "EU data protection" },
  { code: "ISO27701_2019", name: "ISO/IEC 27701", hint: "Privacy management, extending ISO 27001" },
  { code: "ISO42001_2023", name: "ISO/IEC 42001", hint: "AI management system" },
  { code: "PCI_DSS_4_0_1", name: "PCI DSS 4.0.1", hint: "Payment card data security" },
  { code: "CYBER_ESSENTIALS", name: "Cyber Essentials", hint: "UK baseline technical controls" },
  { code: "ESSENTIAL_EIGHT", name: "Essential Eight", hint: "Australian mitigation strategies, maturity levels 1-3" },
];

function Toggle({ on, onClick, title, hint, icon: Icon }: { on: boolean; onClick: () => void; title: string; hint?: string; icon?: any }) {
  return (
    <button type="button" onClick={onClick} className={cn("flex w-full items-start gap-3 rounded-lg border p-3 text-left transition-colors", on ? "border-primary bg-accent" : "hover:bg-muted")}>
      <span className={cn("mt-0.5 grid size-5 shrink-0 place-items-center rounded border", on ? "border-primary bg-primary text-primary-foreground" : "bg-card")}>{on && <Check className="size-3.5" />}</span>
      <span className="flex-1"><span className="flex items-center gap-2 text-sm font-medium">{Icon && <Icon className="size-4" />}{title}</span>{hint && <span className="mt-0.5 block text-xs text-muted-foreground">{hint}</span>}</span>
    </button>
  );
}

export default function Onboarding() {
  const nav = useNavigate();
  const { me } = useAuth();
  const { data } = useApi<any>("/onboarding");
  const [step, setStep] = useState(0);
  const [p, setP] = useState<any>({ company_name: "", legal_name: "", industry: "", description: "", size: "11-50", website: "", locations: "", hosting: ["m365"], data_types: ["customer_personal", "employee"], develops_software: false, offices: true, frameworks: ["ISO27001_2022"], isms_owner_id: null, review_months: 12 });
  useEffect(() => { if (data?.profile) setP((x: any) => ({ ...x, ...data.profile })); }, [data]);
  const toggle = (k: string, v: string) => setP((x: any) => ({ ...x, [k]: x[k].includes(v) ? x[k].filter((i: string) => i !== v) : [...x[k], v] }));
  const finish = useAction(() => api("/onboarding/complete", { body: { ...p, isms_owner_id: p.isms_owner_id ?? me?.id } }), { invalidate: [""], onSuccess: (r: any) => setResult(r) });
  const [result, setResult] = useState<any>(null);
  const can = [!!p.company_name.trim(), true, true, p.frameworks.length > 0, true, true][step];
  const policies = (data?.policy_templates ?? []).filter((t: any) => !t.when || (t.when === "develops_software" ? p.develops_software : t.when === "personal_data" ? p.data_types.some((d: string) => d !== "intellectual_property") : true));

  if (result) return (
    <div className="mx-auto max-w-xl py-10 text-center animate-fade-in">
      <div className="mx-auto mb-5 grid size-14 place-items-center rounded-full bg-good/15 text-good"><Check className="size-7" /></div>
      <h1 className="text-2xl font-semibold">Your ISMS is ready to work on</h1>
      <p className="mt-2 text-muted-foreground">Keystone tailored a starting point for {p.company_name}.</p>
      <Card className="mt-6 text-left"><CardBody className="space-y-2 text-sm">
        <div className="flex justify-between"><span>Draft policies created</span><b>{result.policies_created}</b></div>
        <div className="flex justify-between"><span>Evidence tasks scheduled</span><b>{result.tasks_created}</b></div>
        <div className="flex justify-between"><span>Controls marked not applicable (with reasons)</span><b>{result.controls_marked_na}</b></div>
      </CardBody></Card>
      <div className="mt-6 flex justify-center gap-2"><Button variant="outline" onClick={() => nav("/policies")}>Review policies</Button><Button onClick={() => nav("/tasks")}>Go to tasks <ArrowRight /></Button></div>
    </div>
  );

  return (
    <div className="mx-auto max-w-3xl animate-fade-in">
      <h1 className="mb-2 flex items-center gap-2 text-sm font-normal text-muted-foreground"><Sparkles className="size-4 text-primary" /> Set up Keystone · about 3 minutes</h1>
      {data?.completed && (
        <p className="mb-6 rounded-lg border bg-muted/40 px-4 py-3 text-sm">
          Setup was completed{data.completed_at ? ` on ${fmtDate(data.completed_at)}` : ""}. Running it again keeps everything you have: it only adds
          policies and tasks that don't exist yet. It does turn on the frameworks you choose (and off the others) and update the organisation details.
        </p>
      )}
      {!data?.completed && <div className="mb-6" />}
      <ol className="mb-8 flex items-center gap-2">
        {STEPS.map((s, i) => (
          <li key={s} className="flex flex-1 items-center gap-2">
            <span className={cn("grid size-7 shrink-0 place-items-center rounded-full border text-xs font-semibold", i < step ? "border-primary bg-primary text-primary-foreground" : i === step ? "border-primary text-primary" : "text-muted-foreground")}>{i < step ? <Check className="size-3.5" /> : i + 1}</span>
            <span className={cn("hidden text-sm sm:block", i === step ? "font-medium" : "text-muted-foreground")}>{s}</span>
            {i < STEPS.length - 1 && <span className="h-px flex-1 bg-border" />}
          </li>
        ))}
      </ol>
      <Card>
        <CardBody className="space-y-5 p-6">
          {step === 0 && <>
            <h2 className="text-xl font-semibold">Tell us about your company</h2>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Company name" required><Input autoFocus value={p.company_name} onChange={(e) => setP({ ...p, company_name: e.target.value })} /></Field>
              <Field label="Legal name"><Input value={p.legal_name ?? ""} onChange={(e) => setP({ ...p, legal_name: e.target.value })} /></Field>
              <Field label="Industry"><Input value={p.industry ?? ""} onChange={(e) => setP({ ...p, industry: e.target.value })} placeholder="e.g. SaaS, healthcare, retail" /></Field>
              <Field label="Company size"><Select value={p.size} onChange={(v) => setP({ ...p, size: v })} options={(data?.sizes ?? []).map((s: string) => ({ value: s, label: `${s} people` }))} /></Field>
              <Field label="What does the company do?" className="sm:col-span-2"><Textarea value={p.description ?? ""} onChange={(e) => setP({ ...p, description: e.target.value })} /></Field>
            </div>
          </>}
          {step === 1 && <>
            <h2 className="text-xl font-semibold">Where do your systems run?</h2>
            <p className="text-sm text-muted-foreground">Used to write your scope and schedule the right evidence tasks.</p>
            <div className="grid gap-2 sm:grid-cols-2">{Object.entries(data?.hosting_options ?? {}).map(([k, v]: any) => <Toggle key={k} on={p.hosting.includes(k)} onClick={() => toggle("hosting", k)} title={v.charAt(0).toUpperCase() + v.slice(1)} icon={Cloud} />)}</div>
            <Field label="Locations in scope"><Input value={p.locations ?? ""} onChange={(e) => setP({ ...p, locations: e.target.value })} placeholder="e.g. London head office and remote staff in the UK" /></Field>
          </>}
          {step === 2 && <>
            <h2 className="text-xl font-semibold">Data and ways of working</h2>
            <div className="grid gap-2 sm:grid-cols-2">{DATA.map((d) => <Toggle key={d.value} on={p.data_types.includes(d.value)} onClick={() => toggle("data_types", d.value)} title={d.label} />)}</div>
            <div className="grid gap-2 sm:grid-cols-2">
              <Toggle on={p.develops_software} onClick={() => setP({ ...p, develops_software: !p.develops_software })} title="We develop software" hint="Adds secure development policy, tasks and controls." icon={Code2} />
              <Toggle on={p.offices} onClick={() => setP({ ...p, offices: !p.offices })} title="We operate our own offices or facilities" hint="If not, physical premises controls are marked not applicable." icon={Building} />
            </div>
          </>}
          {step === 3 && <>
            <h2 className="text-xl font-semibold">Which frameworks matter to you?</h2>
            <p className="text-sm text-muted-foreground">Keystone maps one set of controls to all of them; you can change this later.</p>
            <div className="grid gap-2 sm:grid-cols-2">{FW.map((f) => <Toggle key={f.code} on={p.frameworks.includes(f.code)} onClick={() => toggle("frameworks", f.code)} title={f.name} hint={f.hint} />)}</div>
          </>}
          {step === 4 && <>
            <h2 className="text-xl font-semibold">Who runs the ISMS?</h2>
            <Field label="ISMS owner" hint="Owns the generated policies and is assigned the starting tasks. Defaults to you."><OwnerSelect value={p.isms_owner_id} onChange={(v) => setP({ ...p, isms_owner_id: v })} emptyLabel={`Me (${me?.display_name})`} /></Field>
            <Field label="Review policies every (months)"><Input type="number" min={1} max={36} value={p.review_months} onChange={(e) => setP({ ...p, review_months: Number(e.target.value) })} /></Field>
            <p className="text-sm text-muted-foreground">Invite colleagues later under Settings → Users, or People once employees are set up.</p>
          </>}
          {step === 5 && <>
            <h2 className="text-xl font-semibold">Ready to generate</h2>
            <ul className="space-y-2 text-sm">
              <li className="flex gap-2"><Check className="size-4 text-good" /> Enable {p.frameworks.length} framework(s) and write your ISMS scope.</li>
              <li className="flex gap-2"><Check className="size-4 text-good" /> Create {policies.length} draft policies from Keystone templates, for you to review and approve.</li>
              <li className="flex gap-2"><Check className="size-4 text-good" /> Schedule recurring evidence tasks linked to controls.</li>
              {!p.develops_software && <li className="flex gap-2"><Check className="size-4 text-good" /> Mark secure development controls not applicable, with a written reason.</li>}
              {!p.offices && <li className="flex gap-2"><Check className="size-4 text-good" /> Mark premises controls not applicable, with a written reason.</li>}
            </ul>
            <p className="text-xs text-muted-foreground">Safe to run again: existing policies, tasks and decisions are kept.</p>
          </>}
          <div className="flex justify-between border-t pt-4">
            <Button variant="ghost" disabled={step === 0} onClick={() => setStep(step - 1)}><ArrowLeft /> Back</Button>
            {step < STEPS.length - 1 ? <Button disabled={!can} onClick={() => setStep(step + 1)}>Continue <ArrowRight /></Button> : <Button loading={finish.isPending} onClick={() => finish.mutate(undefined)}><Sparkles /> Generate my ISMS</Button>}
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
