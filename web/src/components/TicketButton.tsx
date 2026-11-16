import { useState } from "react";
import { ExternalLink, Ticket } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { safeHref } from "@/lib/safe-url";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field } from "@/components/ui/input";
import { Select } from "@/components/ui/select";

const PERMISSION: Record<string, string> = { task: "task.write", nonconformity: "nc.write", incident: "incident.write", risk: "risk.write", asm_finding: "control.write", vulnerability: "control.write" };

/** Existing tickets for many records at once (one request), keyed by record id. */
export function useTickets(kind: string, ids: number[]) {
  const key = ids.slice(0, 500).join(",");
  const { data } = useApi<any[]>(key ? `/tickets?kind=${kind}&ids=${key}` : null);
  const by: Record<number, any[]> = {};
  for (const t of data ?? []) (by[t.record_id] ??= []).push(t);
  return by;
}

/** Shows a record's tickets, and offers to open one in a connected ticketing system. */
export function TicketButton({ kind, id, tickets }: { kind: string; id: number; tickets?: any[] }) {
  const { can } = useAuth();
  const systems = useApi<any[]>("/tickets/systems");
  const [open, setOpen] = useState(false);
  const [sys, setSys] = useState<string | null>(null);
  const create = useAction(() => api<any>("/tickets", { body: { integration_id: Number(sys), kind, record_id: id } }), { success: (r: any) => `Ticket ${r.key} created.`, invalidate: ["/tickets"], onSuccess: () => setOpen(false) });
  const list = tickets ?? [];
  const avail = (systems.data ?? []).filter((s: any) => !list.some((t) => t.system === s.name));
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {list.map((t) => {
        const href = t.url ? safeHref(t.url) : null;
        const badge = <Badge tone={t.state === "closed" ? "good" : "outline"} title={`${t.system}${t.automatic ? " (opened automatically)" : ""}`}><Ticket className="h-3 w-3" />{t.key}{t.state === "closed" ? " closed" : ""}</Badge>;
        return href ? <a key={t.id} href={href} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-0.5 hover:underline">{badge}<ExternalLink className="h-3 w-3 text-muted-foreground" /><span className="sr-only">(opens {t.system})</span></a> : <span key={t.id}>{badge}</span>;
      })}
      {can(PERMISSION[kind]) && avail.length > 0 && (
        <Button size="sm" variant="ghost" onClick={() => { setSys(String(avail[0].id)); setOpen(true); }}><Ticket /> Ticket</Button>
      )}
      <Dialog open={open} onOpenChange={setOpen} title="Open a ticket" description="Keystone sends a title, a short description and a link back to this record."
        footer={<Button loading={create.isPending} disabled={!sys} onClick={() => create.mutate(undefined)}>Create ticket</Button>}>
        <Field label="Ticketing system"><Select value={sys} onChange={setSys} ariaLabel="Ticketing system" options={avail.map((s: any) => ({ value: String(s.id), label: s.name }))} /></Field>
      </Dialog>
    </span>
  );
}
