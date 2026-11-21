import { useMemo, useState } from "react";
import { Sparkles } from "lucide-react";
import { api } from "@/lib/api";
import { useAction } from "@/lib/hooks";
import { lineDiff } from "@/lib/diff";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Textarea } from "@/components/ui/input";
import { Tabs } from "@/components/ui/tabs";
import { Markdown } from "@/components/Markdown";

const IDEAS = [
  "Write a first draft suitable for a small company",
  "Make it shorter and easier to read for all staff",
  "Add a section on roles and responsibilities",
  "Align it with ISO/IEC 27001:2022 Annex A",
  "Add exceptions and enforcement sections",
];

type Proposal = { base_label: string | null; base_body: string; body: string; change_summary: string; notes: string[] };

/** Asks Claude for a revision, shows it as a diff, and puts an accepted revision into a draft version. */
export function PolicyAssistant({ docId, unsaved, onClose, onAccepted }: { docId: number; unsaved: boolean; onClose: () => void; onAccepted: (body: string, summary: string) => void }) {
  const [instruction, setInstruction] = useState("");
  const [p, setP] = useState<Proposal | null>(null);
  const propose = useAction(() => api<Proposal>(`/ai/policies/${docId}/propose`, { body: { instruction } }), { invalidate: [], onSuccess: setP });
  const accept = useAction(() => api(`/ai/policies/${docId}/accept`, { body: { body: p!.body, change_summary: p!.change_summary } }), {
    success: (r: any) => `Saved into draft v${r.version_label}. Review it, then submit for approval.`,
    invalidate: ["/policies"],
    onSuccess: () => { onAccepted(p!.body, p!.change_summary); onClose(); },
  });
  const diff = useMemo(() => (p ? lineDiff(p.base_body, p.body) : []), [p]);
  const added = diff.filter((d) => d.kind === "add").length;
  const removed = diff.filter((d) => d.kind === "del").length;

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} wide title={<span className="flex items-center gap-2"><Sparkles className="size-4 text-primary" /> Policy assistant</span>}
      description="Claude proposes a revision. Nothing changes until you accept it, and accepted text still goes through review and approval."
      footer={p ? <><Button variant="ghost" onClick={() => setP(null)}>Try another instruction</Button><Button loading={accept.isPending} onClick={() => accept.mutate(undefined)}>Accept into draft</Button></>
        : <Button loading={propose.isPending} disabled={!instruction.trim()} onClick={() => propose.mutate(undefined)}><Sparkles /> Propose changes</Button>}>
      {!p ? (
        <div className="space-y-4">
          {unsaved && <p className="rounded-md bg-warning/10 px-3 py-2 text-sm">You have unsaved edits. The assistant works from the last saved text, so save your draft first.</p>}
          <Field label="What should change?" hint="The assistant sees this document, its linked controls and your organisation profile. It never sees people or user records.">
            <Textarea autoFocus className="min-h-28" value={instruction} maxLength={4000} onChange={(e) => setInstruction(e.target.value)} placeholder="For example: add a requirement that laptops are encrypted with BitLocker or FileVault" />
          </Field>
          <div className="flex flex-wrap gap-2">{IDEAS.map((i) => <button key={i} type="button" onClick={() => setInstruction(i)} className="rounded-full border px-3 py-1 text-xs text-muted-foreground transition hover:bg-accent hover:text-accent-foreground">{i}</button>)}</div>
          {propose.isPending && <p className="text-sm text-muted-foreground">Drafting… this can take a minute for long documents.</p>}
        </div>
      ) : (
        <div className="space-y-4">
          <div className="rounded-lg border bg-muted/40 px-4 py-3 text-sm">
            <div className="font-medium">{p.change_summary || "Proposed revision"}</div>
            <div className="mt-1 text-xs text-muted-foreground">{p.base_label ? `Compared with v${p.base_label}` : "New text"} · <span className="text-good-fg">+{added}</span> / <span className="text-critical">−{removed}</span> lines</div>
          </div>
          {p.notes.length > 0 && (
            <div className="rounded-lg border border-warning/30 bg-warning/5 px-4 py-3 text-sm">
              <div className="mb-1 font-medium">Check before accepting</div>
              <ul className="list-disc space-y-0.5 pl-5">{p.notes.map((n, i) => <li key={i}>{n}</li>)}</ul>
            </div>
          )}
          <Tabs tabs={[
            { value: "diff", label: "Changes", content: (
              <pre className="max-h-[28rem] overflow-auto rounded-md border font-mono text-xs leading-5">
                {diff.map((d, i) => (
                  <div key={i} className={cn("whitespace-pre-wrap px-3", d.kind === "add" && "bg-good/10", d.kind === "del" && "bg-critical/10 line-through decoration-critical/40")}>
                    <span className="mr-2 select-none text-muted-foreground" aria-hidden>{d.kind === "add" ? "+" : d.kind === "del" ? "−" : " "}</span>
                    <span className="sr-only">{d.kind === "add" ? "Added: " : d.kind === "del" ? "Removed: " : ""}</span>{d.text || " "}
                  </div>
                ))}
              </pre>
            ) },
            { value: "preview", label: "Preview", content: <div className="max-h-[28rem] overflow-auto rounded-md border p-4"><Markdown>{p.body}</Markdown></div> },
          ]} />
        </div>
      )}
    </Dialog>
  );
}
