import { useState } from "react";
import { usePeople } from "@/lib/hooks";
import { titleCase } from "@/lib/utils";
import { Input } from "./ui/input";
import { Select } from "./ui/select";

export function useForm<T extends Record<string, any>>(initial: T) {
  const [f, setF] = useState<T>(initial);
  const set = <K extends keyof T>(k: K) => (v: T[K]) => setF((prev) => ({ ...prev, [k]: v }));
  const ev = <K extends keyof T>(k: K) => (e: { target: { value: string } }) => setF((prev) => ({ ...prev, [k]: e.target.value }));
  return { f, setF, set, ev };
}

/** Strip empty strings to null so the API sees "not set" rather than "". */
export function clean<T extends Record<string, any>>(o: T): T {
  const out: any = {};
  for (const [k, v] of Object.entries(o)) out[k] = v === "" ? null : v;
  return out;
}

export function OwnerSelect({ value, onChange, disabled, emptyLabel = "Unassigned", ariaLabel }: { value: number | null | undefined; onChange: (v: number | null) => void; disabled?: boolean; emptyLabel?: string; ariaLabel?: string }) {
  const { people } = usePeople();
  return <Select value={value ? String(value) : null} onChange={(v) => onChange(v ? Number(v) : null)} allowEmpty emptyLabel={emptyLabel} options={people.map((p) => ({ value: String(p.id), label: p.display_name }))} disabled={disabled} ariaLabel={ariaLabel} />;
}

export function EnumSelect({ value, onChange, values, allowEmpty, disabled, labels }: { value: string | null | undefined; onChange: (v: any) => void; values: readonly string[]; allowEmpty?: boolean; disabled?: boolean; labels?: Record<string, string> }) {
  return <Select value={value ?? null} onChange={onChange} allowEmpty={allowEmpty} options={values.map((v) => ({ value: v, label: labels?.[v] ?? titleCase(v) }))} disabled={disabled} />;
}

export function DateInput({ value, onChange, disabled, ariaLabel }: { value: string | null | undefined; onChange: (v: string | null) => void; disabled?: boolean; ariaLabel?: string }) {
  return <Input type="date" value={value ?? ""} onChange={(e) => onChange(e.target.value || null)} disabled={disabled} aria-label={ariaLabel} />;
}

export function TriSelect({ value, onChange, disabled }: { value: boolean | null | undefined; onChange: (v: boolean | null) => void; disabled?: boolean }) {
  return <Select value={value === null || value === undefined ? null : value ? "yes" : "no"} onChange={(v) => onChange(v === null ? null : v === "yes")} allowEmpty emptyLabel="Unknown" options={[{ value: "yes", label: "Yes" }, { value: "no", label: "No" }]} disabled={disabled} />;
}

export function RangeInput({ label, value, onChange, step = 0.1, max, disabled }: { label: string; value: { min: number; ml: number; max: number } | null | undefined; onChange: (v: { min: number; ml: number; max: number }) => void; step?: number; max?: number; disabled?: boolean }) {
  const v = value ?? { min: 0, ml: 0, max: 0 };
  const field = (k: "min" | "ml" | "max", lab: string) => (
    <label className="grid gap-1 text-xs text-muted-foreground">
      {lab}
      <Input type="number" step={step} min={0} max={max} value={v[k]} onChange={(e) => onChange({ ...v, [k]: Number(e.target.value) })} disabled={disabled} />
    </label>
  );
  return (
    <div>
      <div className="mb-1 text-sm font-medium">{label}</div>
      <div className="grid grid-cols-3 gap-2">{field("min", "Minimum")}{field("ml", "Most likely")}{field("max", "Maximum")}</div>
    </div>
  );
}
