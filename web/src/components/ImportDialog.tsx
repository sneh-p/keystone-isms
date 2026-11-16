import { useRef, useState } from "react";
import { AlertTriangle, CheckCircle2, Download, Upload } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi } from "@/lib/hooks";
import { csvRecords, MAX_CSV_BYTES, toCsvLine } from "@/lib/csv";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";

type Result = { header_errors: string[]; rows: { row: number; label: string; errors: string[] }[]; ok: number; errors: number };

/**
 * Import a register from CSV. The file is read and parsed here in the browser; only the rows go to the server, as
 * JSON, where each one runs through the same rules as a manual entry. Preview first; import is all or nothing.
 */
export function ImportButton({ register, noun, invalidate }: { register: "assets" | "risks" | "vendors" | "people" | "devices"; noun: string; invalidate: string[] }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button variant="outline" onClick={() => setOpen(true)}><Upload /> Import CSV</Button>
      {open && <ImportDialog register={register} noun={noun} invalidate={invalidate} onClose={() => setOpen(false)} />}
    </>
  );
}

function ImportDialog({ register, noun, invalidate, onClose }: { register: string; noun: string; invalidate: string[]; onClose: () => void }) {
  const spec = useApi<any>(`/import/${register}`);
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<string | null>(null);
  const [rows, setRows] = useState<Record<string, string>[] | null>(null);
  const [readError, setReadError] = useState<string | null>(null);
  const [result, setResult] = useState<Result | null>(null);
  const preview = useAction((r: Record<string, string>[]) => api<Result>(`/import/${register}`, { body: { rows: r, preview: true } }), { onSuccess: setResult });
  const commit = useAction(() => api<Result>(`/import/${register}`, { body: { rows, preview: false } }), {
    success: (r) => `Imported ${r.ok} ${noun}.`, invalidate, onSuccess: onClose,
  });

  const choose = async (f: File | undefined) => {
    setResult(null); setRows(null); setReadError(null);
    if (!f) return;
    setFile(f.name);
    try {
      if (f.size > MAX_CSV_BYTES) throw new Error("The file is larger than 2 MB; split it into smaller files.");
      const { records } = csvRecords(await f.text());
      if (!records.length) throw new Error("The file has a header row but no data rows.");
      if (spec.data && records.length > spec.data.max_rows) throw new Error(`The file has ${records.length} rows; import at most ${spec.data.max_rows} at a time.`);
      setRows(records);
      preview.mutate(records);
    } catch (e) {
      setReadError((e as Error).message);
    }
  };

  const template = () => {
    const cols: any[] = spec.data?.columns ?? [];
    const blob = new Blob([toCsvLine(cols.map((c) => c.name)) + "\r\n"], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement("a"), { href: url, download: `${register}-template.csv` });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  };

  const ready = !!rows && !!result && result.errors === 0 && result.header_errors.length === 0;
  const bad = result?.rows.filter((r) => r.errors.length) ?? [];
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={`Import ${noun} from CSV`} wide
      description="Save your spreadsheet as CSV with a header row. Nothing is saved until you confirm, and the import is all or nothing."
      footer={<>
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button disabled={!ready} loading={commit.isPending} onClick={() => commit.mutate(undefined)}>{ready ? `Import ${result!.ok} ${noun}` : "Import"}</Button>
      </>}>
      <div className="space-y-4 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <input ref={input} type="file" accept=".csv,text/csv" className="sr-only" aria-label="CSV file" onChange={(e) => { void choose(e.target.files?.[0]); e.target.value = ""; }} />
          <Button onClick={() => input.current?.click()}><Upload /> Choose CSV file</Button>
          <Button variant="outline" onClick={template} disabled={!spec.data}><Download /> Download template</Button>
          {file && <span className="text-muted-foreground">{file}{rows ? ` · ${rows.length} rows` : ""}</span>}
        </div>
        {spec.data && (
          <details className="rounded-md border px-3 py-2">
            <summary className="cursor-pointer font-medium">Columns</summary>
            <ul className="mt-2 grid gap-1 sm:grid-cols-2">
              {spec.data.columns.map((c: any) => (
                <li key={c.name}><code className="text-xs">{c.name}</code>{c.required && <span className="text-critical"> (required)</span>}
                  <span className="text-xs text-muted-foreground"> {c.choices.length ? `one of: ${c.choices.join(", ")}` : c.help}</span></li>
              ))}
            </ul>
          </details>
        )}
        {readError && <p role="alert" className="flex items-start gap-2 text-critical"><AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden />{readError}</p>}
        {preview.isPending && <p className="text-muted-foreground">Checking every row…</p>}
        {result && (
          <div role="status" className="space-y-3">
            {result.header_errors.length > 0 ? (
              <div className="rounded-md border border-critical/40 bg-critical/5 p-3">
                <div className="mb-1 font-medium">The header row needs fixing</div>
                <ul className="list-inside list-disc">{result.header_errors.map((e) => <li key={e}>{e}</li>)}</ul>
              </div>
            ) : result.errors === 0 ? (
              <p className="flex items-center gap-2"><CheckCircle2 className="size-4 text-good" aria-hidden /> All {result.ok} rows are valid and ready to import.</p>
            ) : (
              <>
                <p className="flex items-center gap-2"><AlertTriangle className="size-4 text-warning" aria-hidden /> {result.errors} of {result.rows.length} rows need fixing. Correct the file and choose it again.</p>
                <div className="max-h-72 overflow-auto rounded-md border" tabIndex={0} aria-label="Rows with problems">
                  <table className="w-full text-left text-xs">
                    <thead className="sticky top-0 bg-muted"><tr><th className="px-2 py-1.5">Row</th><th className="px-2 py-1.5">Record</th><th className="px-2 py-1.5">Problem</th></tr></thead>
                    <tbody>{bad.slice(0, 200).map((r) => <tr key={r.row} className="border-t align-top"><td className="px-2 py-1.5 tabular-nums">{r.row}</td><td className="px-2 py-1.5">{r.label || "—"}</td><td className="px-2 py-1.5">{r.errors.join("; ")}</td></tr>)}</tbody>
                  </table>
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </Dialog>
  );
}
