import { useState } from "react";
import { Download, Users } from "lucide-react";
import { api, downloadUrl } from "@/lib/api";
import { useAction, useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/misc";
import { MultiSelect } from "@/components/ui/multiselect";
import { DataTable } from "@/components/ui/table";

export type Audience = { departments: string[]; employment_types: string[] } | null;

/** Describes an audience in words: "Everyone", or "Finance, IT · contractors". */
export function audienceText(a: Audience): string {
  if (!a || (!a.departments.length && !a.employment_types.length)) return "Everyone";
  return [a.departments.join(", "), a.employment_types.map((t) => `${t}s`).join(", ")].filter(Boolean).join(" · ");
}

/** Pick departments and employment types; nothing picked means everyone. */
export function AudienceEditor({ value, onChange }: { value: Audience; onChange: (a: Audience) => void }) {
  const { data: departments } = useApi<string[]>("/audience/departments");
  const a = value ?? { departments: [], employment_types: [] };
  const set = (patch: Partial<NonNullable<Audience>>) => {
    const next = { ...a, ...patch };
    onChange(next.departments.length || next.employment_types.length ? next : null);
  };
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <Field label="Departments" hint="From the People register. None: all departments.">
        <MultiSelect value={a.departments} onChange={(v) => set({ departments: v })} options={(departments ?? []).map((d) => ({ value: d, label: d }))} placeholder="All departments" />
      </Field>
      <Field label="Employment type"><MultiSelect value={a.employment_types} onChange={(v) => set({ employment_types: v })} options={[{ value: "employee", label: "Employees" }, { value: "contractor", label: "Contractors" }]} placeholder="Everyone" /></Field>
    </div>
  );
}

/** Training assignment (ISO 27001 A.6.3): who takes each module and how soon, with the training matrix to download. */
export function TrainingAssignments() {
  const { can } = useAuth();
  const { data } = useApi<any>("/training/assignments");
  const [edit, setEdit] = useState<any>(null);
  const save = useAction(() => api(`/training/assignments/${edit.key}`, { method: "PUT", body: { audience: edit.audience, due_days: Number(edit.due_days) } }),
    { success: "Assignment saved.", invalidate: ["/training", "/people", "/dashboard"], onSuccess: () => setEdit(null) });
  if (!data) return <Skeleton className="h-64" />;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-3xl text-sm text-muted-foreground">Each module applies to everyone unless you limit it to departments or employment types. A pass is valid for a year, and a new version of a module asks for it again. New starters have the number of days you set to complete it.</p>
        <a href={downloadUrl("/training/matrix.xlsx")}><Button variant="outline"><Download /> Training matrix</Button></a>
      </div>
      <DataTable rows={data.modules} rowKey={(m: any) => m.key} onRowClick={can("people.write") ? (m: any) => setEdit({ ...m }) : undefined} columns={[
        { key: "t", header: "Module", cell: (m: any) => <span><span className="font-medium">{m.title}</span><span className="block text-xs text-muted-foreground">v{m.version} · {m.minutes} min</span></span> },
        { key: "a", header: "Who", cell: (m: any) => <span className="flex items-center gap-1.5"><Users className="size-4 text-muted-foreground" />{audienceText(m.audience)}</span> },
        { key: "d", header: "Due within", cell: (m: any) => `${m.due_days} days of starting` },
        { key: "o", header: "Overdue", cell: (m: any) => (data.overdue[m.title] ? <Badge tone="critical">{data.overdue[m.title]} people</Badge> : <span className="text-muted-foreground">None</span>) },
      ]} />
      {edit && (
        <Dialog open onOpenChange={(o) => !o && setEdit(null)} title={`Assign: ${edit.title}`} footer={<Button loading={save.isPending} onClick={() => save.mutate(undefined)}>Save</Button>}>
          <div className="space-y-4">
            <AudienceEditor value={edit.audience} onChange={(audience) => setEdit({ ...edit, audience })} />
            <Field label="Days to complete it after starting" className="max-w-xs"><Input type="number" min={1} max={365} value={edit.due_days} onChange={(e) => setEdit({ ...edit, due_days: e.target.value })} /></Field>
          </div>
        </Dialog>
      )}
    </div>
  );
}
