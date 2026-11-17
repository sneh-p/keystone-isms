import { useMemo, useState } from "react";
import { GitCompare } from "lucide-react";
import { api } from "@/lib/api";
import { useAction } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { lineDiff } from "@/lib/diff";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { AudienceEditor, audienceText, type Audience } from "@/components/Training";

/** Side-by-side view of what changed between a version and the one before it. */
export function CompareVersions({ versions, version }: { versions: any[]; version: any }) {
  const [open, setOpen] = useState(false);
  const ordered = [...versions].sort((a, b) => a.id - b.id);
  const prev = ordered[ordered.findIndex((v) => v.id === version.id) - 1];
  const diff = useMemo(() => (open && prev ? lineDiff(prev.body ?? "", version.body ?? "") : []), [open, prev, version]);
  if (!prev) return null;
  const added = diff.filter((d) => d.kind === "add").length;
  const removed = diff.filter((d) => d.kind === "del").length;
  return (
    <>
      <Button size="sm" variant="ghost" onClick={() => setOpen(true)}><GitCompare /> Compare</Button>
      {open && (
        <Dialog open onOpenChange={(o) => !o && setOpen(false)} extraWide title={`v${prev.version_label} → v${version.version_label}`} description={`${added} line(s) added, ${removed} removed.${version.change_summary ? ` ${version.change_summary}` : ""}`}>
          {!prev.body && !version.body ? <p className="text-sm text-muted-foreground">These versions are attached files; download the PDFs to compare them.</p> : (
            <pre className="max-h-[60vh] overflow-auto rounded-md border text-xs leading-relaxed">
              {diff.map((d, i) => (
                <div key={i} className={cn("whitespace-pre-wrap px-3", d.kind === "add" && "bg-good/10", d.kind === "del" && "bg-critical/10 line-through decoration-critical/50")}>
                  <span aria-label={d.kind === "add" ? "Added" : d.kind === "del" ? "Removed" : undefined} className="mr-2 select-none text-muted-foreground">{d.kind === "add" ? "+" : d.kind === "del" ? "−" : " "}</span>{d.text || " "}
                </div>
              ))}
            </pre>
          )}
        </Dialog>
      )}
    </>
  );
}

/** Who must accept the document. Minor versions (1.0 to 1.1) keep earlier acceptances; major ones ask again. */
export function AckAudience({ doc }: { doc: any }) {
  const { can } = useAuth();
  const [edit, setEdit] = useState<Audience | undefined>(undefined);
  const save = useAction(() => api(`/policies/${doc.id}`, { method: "PATCH", body: { ack_audience: edit } }), { success: "Saved.", invalidate: ["/policies", "/people", "/dashboard"], onSuccess: () => setEdit(undefined) });
  if (!doc.requires_acknowledgement) return null;
  return (
    <div className="mt-4 space-y-2 text-sm">
      <div><span className="font-medium">Who must accept it:</span> {audienceText(doc.ack_audience)}</div>
      <p className="text-xs text-muted-foreground">A minor version (for example 1.0 to 1.1) keeps earlier acceptances; a major version (2.0) asks everyone again.</p>
      {can("policy.write") && (edit === undefined
        ? <Button size="sm" variant="outline" onClick={() => setEdit(doc.ack_audience ?? null)}>Change who must accept</Button>
        : <div className="space-y-3 rounded-lg border p-3"><AudienceEditor value={edit} onChange={setEdit} /><div className="flex gap-2"><Button size="sm" loading={save.isPending} onClick={() => save.mutate(undefined)}>Save</Button><Button size="sm" variant="ghost" onClick={() => setEdit(undefined)}>Cancel</Button></div></div>)}
    </div>
  );
}
