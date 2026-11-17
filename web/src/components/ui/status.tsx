import { AlertTriangle, CheckCircle2, CircleDashed, CircleDot, HelpCircle, MinusCircle, XCircle } from "lucide-react";
import { Badge, type Tone } from "./badge";
import { titleCase } from "@/lib/utils";

const LEVEL: Record<string, Tone> = { Critical: "critical", High: "serious", Medium: "warning", Low: "good" };

/** Risk/exposure level badge: colour plus text, never colour alone. */
export function LevelBadge({ level }: { level?: string | null }) {
  if (!level) return <Badge tone="outline">Not assessed</Badge>;
  return (
    <Badge tone={LEVEL[level] ?? "neutral"}>
      <span className="size-1.5 rounded-full bg-current" aria-hidden />
      {level}
    </Badge>
  );
}

const STATUS: Record<string, { tone: Tone; icon?: any }> = {
  implemented: { tone: "good", icon: CheckCircle2 },
  partial: { tone: "warning", icon: CircleDot },
  planned: { tone: "primary", icon: CircleDashed },
  not_started: { tone: "neutral", icon: CircleDashed },
  not_implemented: { tone: "neutral", icon: CircleDashed },
  not_applicable: { tone: "outline", icon: MinusCircle },
  unmapped: { tone: "outline", icon: HelpCircle },
  pass: { tone: "good", icon: CheckCircle2 },
  fail: { tone: "critical", icon: XCircle },
  error: { tone: "serious", icon: AlertTriangle },
  unknown: { tone: "outline", icon: HelpCircle },
  done: { tone: "good", icon: CheckCircle2 },
  approved: { tone: "good", icon: CheckCircle2 },
  closed: { tone: "neutral", icon: CheckCircle2 },
  draft: { tone: "neutral" },
  in_review: { tone: "primary" },
  in_progress: { tone: "primary" },
  overdue: { tone: "critical", icon: AlertTriangle },
  expired: { tone: "critical", icon: AlertTriangle },
  expiring: { tone: "warning", icon: AlertTriangle },
  current: { tone: "good", icon: CheckCircle2 },
  rejected: { tone: "critical", icon: XCircle },
  superseded: { tone: "outline", icon: MinusCircle },
  effective: { tone: "good", icon: CheckCircle2 },
  partially_effective: { tone: "warning", icon: AlertTriangle },
  ineffective: { tone: "critical", icon: XCircle },
  drafted: { tone: "primary", icon: CircleDot },
  completed: { tone: "good", icon: CheckCircle2 },
  open: { tone: "neutral", icon: CircleDashed },
};

export function StatusBadge({ status, label }: { status?: string | null; label?: string }) {
  if (!status) return <Badge tone="outline">—</Badge>;
  const s = STATUS[status] ?? { tone: "neutral" as Tone };
  const Icon = s.icon;
  return (
    <Badge tone={s.tone}>
      {Icon && <Icon className="size-3" aria-hidden />}
      {label ?? titleCase(status)}
    </Badge>
  );
}
