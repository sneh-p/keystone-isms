import { Link } from "react-router";
import { UsersRound } from "lucide-react";
import { useApi } from "@/lib/hooks";
import { cn } from "@/lib/utils";
import { PageHeader, Skeleton } from "@/components/ui/misc";
import { DataTable } from "@/components/ui/table";

/** Who carries what: open and overdue tasks, items routed to each person, and what they own. */
export default function Workload() {
  const { data } = useApi<any[]>("/workload");
  if (!data) return <Skeleton className="h-96" />;
  const max = Math.max(1, ...data.map((r) => r.open_tasks));
  return (
    <div className="animate-fade-in">
      <PageHeader icon={UsersRound} title="Workload" description="Open work per person, to spot overload and gaps. Needs attention counts the dashboard items routed to each person." />
      <DataTable rows={data} rowKey={(r: any) => r.user_id ?? "none"} rowLabel={(r: any) => r.display_name} search={(r: any) => r.display_name} columns={[
        { key: "n", header: "Person", cell: (r: any) => <span className={cn("font-medium", r.user_id === null && "italic text-muted-foreground")}>{r.display_name}</span>, sort: (r: any) => r.display_name },
        { key: "t", header: "Open tasks", sort: (r: any) => r.open_tasks, cell: (r: any) => (
          <Link to={`/tasks?assignee=${r.user_id ?? "none"}`} className="flex items-center gap-2 hover:underline">
            <span className="w-8 text-right">{r.open_tasks}</span>
            <span aria-hidden className="h-2 rounded-full bg-primary/70" style={{ width: `${Math.round((r.open_tasks / max) * 120)}px` }} />
          </Link>
        ) },
        { key: "o", header: "Overdue", sort: (r: any) => r.overdue, cell: (r: any) => <span className={r.overdue ? "font-medium text-critical" : "text-muted-foreground"}>{r.overdue}</span> },
        { key: "d", header: "Due in 30 days", sort: (r: any) => r.due_30, cell: (r: any) => r.due_30 },
        { key: "a", header: "Needs attention", sort: (r: any) => r.needs_attention, cell: (r: any) => r.needs_attention },
        { key: "c", header: "Controls owned", sort: (r: any) => r.controls, cell: (r: any) => (r.user_id === null ? <Link to="/controls?owner=none" className="text-primary hover:underline">{r.controls} without owner</Link> : r.controls) },
        { key: "r", header: "Risks owned", sort: (r: any) => r.risks, cell: (r: any) => (r.user_id === null ? `${r.risks} without owner` : r.risks) },
      ]} />
    </div>
  );
}
