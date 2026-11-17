import { useState } from "react";
import { Sparkles } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { titleCase } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { Markdown } from "@/components/Markdown";

function useAiAvailable() {
  const { data } = useApi<any>("/ai/status");
  return !!data?.available;
}

/** Drafts a control's implementation notes with Claude. The text goes into the form; nothing is saved until you save. */
export function ControlNarrativeButton({ controlId, onUse }: { controlId: number; onUse: (text: string) => void }) {
  const available = useAiAvailable();
  const [open, setOpen] = useState(false);
  const [instruction, setInstruction] = useState("");
  const [result, setResult] = useState<any>(null);
  const propose = useAction(() => api<any>(`/ai/controls/${controlId}/narrative`, { body: { instruction: instruction || null } }), { onSuccess: (r: any) => setResult(r) });
  if (!available) return null;
  return (
    <>
      <Button type="button" size="sm" variant="outline" onClick={() => { setOpen(true); setResult(null); }}><Sparkles /> Draft with AI</Button>
      <Dialog open={open} onOpenChange={setOpen} wide title="Draft the implementation description" description="Claude sees this control, the requirements it maps to, linked approved policy titles and your organisation profile: never evidence, risks or people."
        footer={result ? <><Button variant="ghost" onClick={() => setResult(null)}>Try again</Button><Button onClick={() => { onUse(result.implementation_notes); setOpen(false); }}>Use this text</Button></>
          : <Button loading={propose.isPending} onClick={() => propose.mutate(undefined)}><Sparkles /> Draft</Button>}>
        {!result ? (
          <Field label="Anything to include? (optional)" hint="For example: we use Microsoft Entra ID with Conditional Access; keep it to five bullet points.">
            <Input value={instruction} onChange={(e) => setInstruction(e.target.value)} maxLength={2000} />
          </Field>
        ) : (
          <div className="space-y-4">
            <div className="rounded-md border p-3"><Markdown>{result.implementation_notes}</Markdown></div>
            {result.notes.length > 0 && <div><p className="text-sm font-medium">Check before saving</p><ul className="list-disc pl-5 text-sm">{result.notes.map((n: string, i: number) => <li key={i}>{n}</li>)}</ul></div>}
            {result.evidence_suggestions.length > 0 && <div><p className="text-sm font-medium">Evidence an auditor would expect</p><ul className="list-disc pl-5 text-sm">{result.evidence_suggestions.map((n: string, i: number) => <li key={i}>{n}</li>)}</ul></div>}
          </div>
        )}
      </Dialog>
    </>
  );
}

/** Suggests risks the register may be missing; you choose which to add. */
export function RiskSuggestButton({ onAdded }: { onAdded?: () => void }) {
  const { can } = useAuth();
  const available = useAiAvailable();
  const [open, setOpen] = useState(false);
  const [focus, setFocus] = useState("");
  const [items, setItems] = useState<any[] | null>(null);
  const [picked, setPicked] = useState<Set<number>>(new Set());
  const suggest = useAction(() => api<any[]>("/ai/risks/suggest", { body: { focus: focus || null } }), { onSuccess: (r: any) => { setItems(r); setPicked(new Set(r.map((_: any, i: number) => i))); } });
  const add = useAction(async () => {
    for (const i of picked) {
      const s = items![i];
      await api("/ai/risks/accept", { body: { title: s.title, category: s.category, threat: s.threat, vulnerability: s.vulnerability, consequence: s.consequence, likelihood: s.likelihood, impact: s.impact, asset_ids: s.asset_ids, control_ids: s.control_ids } });
    }
    return picked.size;
  }, { success: (n: number) => `${n} risk(s) added to the register.`, invalidate: ["/risks", "/dashboard"], onSuccess: () => { setOpen(false); setItems(null); onAdded?.(); } });
  if (!available || !can("risk.write")) return null;
  return (
    <>
      <Button variant="outline" onClick={() => { setOpen(true); setItems(null); }}><Sparkles /> Suggest risks</Button>
      <Dialog open={open} onOpenChange={setOpen} wide title="Suggest risks" description="Claude sees your organisation profile, asset list and suppliers, not your existing risks. Suggestions that duplicate a risk you already have are removed before you see them."
        footer={items ? <><Button variant="ghost" onClick={() => setItems(null)}>Start over</Button><Button disabled={!picked.size} loading={add.isPending} onClick={() => add.mutate(undefined)}>Add {picked.size} to the register</Button></>
          : <Button loading={suggest.isPending} onClick={() => suggest.mutate(undefined)}><Sparkles /> Suggest</Button>}>
        {!items ? (
          <Field label="Focus (optional)" hint="For example: payments, seasonal staff, the hotel Wi-Fi."><Input value={focus} onChange={(e) => setFocus(e.target.value)} maxLength={1000} /></Field>
        ) : items.length === 0 ? <p className="text-sm text-muted-foreground">No new risks suggested: the ones Claude proposed are already in your register.</p> : (
          <ul className="space-y-3">
            {items.map((s, i) => (
              <li key={i} className="rounded-md border p-3">
                <label className="flex items-start gap-2">
                  <input type="checkbox" className="mt-1" checked={picked.has(i)} onChange={(e) => { const n = new Set(picked); if (e.target.checked) n.add(i); else n.delete(i); setPicked(n); }} />
                  <span className="min-w-0 flex-1">
                    <span className="font-medium">{s.title}</span> <Badge tone="outline">{titleCase(s.category)}</Badge> <Badge tone="neutral">L{s.likelihood} × I{s.impact}</Badge>
                    <span className="mt-1 block text-sm text-muted-foreground">{s.threat} exploits {s.vulnerability}: {s.consequence}</span>
                    {(s.assets.length > 0 || s.controls.length > 0) && <span className="mt-1 block text-xs text-muted-foreground">{s.assets.join(", ")}{s.assets.length && s.controls.length ? " · " : ""}{s.controls.join(", ")}</span>}
                  </span>
                </label>
              </li>
            ))}
          </ul>
        )}
      </Dialog>
    </>
  );
}
