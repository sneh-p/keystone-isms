import { useMemo, useState, type ReactNode } from "react";
import { ArrowDown, ArrowUp, Search } from "lucide-react";
import { cn } from "@/lib/utils";
import { Input } from "./input";

export type Column<T> = { key: string; header: ReactNode; cell: (row: T) => ReactNode; sort?: (row: T) => string | number | null; className?: string };

/** Data table with optional search and column sorting. */
export function DataTable<T>({ rows, columns, onRowClick, search, empty = "Nothing here yet.", rowKey, toolbar }: {
  rows: T[];
  columns: Column<T>[];
  onRowClick?: (row: T) => void;
  search?: (row: T) => string;
  empty?: ReactNode;
  rowKey: (row: T) => string | number;
  toolbar?: ReactNode;
}) {
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 } | null>(null);
  const shown = useMemo(() => {
    let r = rows;
    if (search && q) r = r.filter((x) => search(x).toLowerCase().includes(q.toLowerCase()));
    if (sort) {
      const col = columns.find((c) => c.key === sort.key);
      if (col?.sort) r = [...r].sort((a, b) => {
        const va = col.sort!(a) ?? "", vb = col.sort!(b) ?? "";
        return (va > vb ? 1 : va < vb ? -1 : 0) * sort.dir;
      });
    }
    return r;
  }, [rows, q, sort, search, columns]);
  return (
    <div>
      {(search || toolbar) && (
        <div className="mb-3 flex flex-wrap items-center gap-2">
          {search && (
            <div className="relative w-full max-w-xs">
              <Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
              <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search…" className="pl-8" aria-label="Search table" />
            </div>
          )}
          {toolbar}
        </div>
      )}
      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b bg-muted/50 text-left text-xs uppercase tracking-wide text-muted-foreground">
              {columns.map((c) => (
                <th key={c.key} className={cn("whitespace-nowrap px-3 py-2.5 font-medium", c.sort && "cursor-pointer select-none hover:text-foreground", c.className)} onClick={() => c.sort && setSort((s) => (s?.key === c.key ? { key: c.key, dir: (s.dir * -1) as 1 | -1 } : { key: c.key, dir: 1 }))}>
                  <span className="inline-flex items-center gap-1">
                    {c.header === "" ? <span className="sr-only">Actions</span> : c.header}
                    {sort?.key === c.key && (sort.dir === 1 ? <ArrowUp className="size-3" /> : <ArrowDown className="size-3" />)}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {shown.length === 0 && (
              <tr>
                <td colSpan={columns.length} className="px-3 py-10 text-center text-muted-foreground">
                  {empty}
                </td>
              </tr>
            )}
            {shown.map((r) => (
              <tr key={rowKey(r)} onClick={onRowClick ? () => onRowClick(r) : undefined} className={cn("border-b last:border-0", onRowClick && "cursor-pointer hover:bg-muted/40")}>
                {columns.map((c) => (
                  <td key={c.key} className={cn("px-3 py-2.5 align-top", c.className)}>
                    {c.cell(r)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {search && q && <p className="mt-2 text-xs text-muted-foreground">{shown.length} of {rows.length} shown</p>}
    </div>
  );
}
