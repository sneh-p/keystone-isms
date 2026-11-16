import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function fmtDate(v?: string | null, withTime = false): string {
  if (!v) return "—";
  const d = new Date(v.length === 10 ? v + "T00:00:00" : v);
  if (Number.isNaN(d.getTime())) return v;
  return withTime
    ? d.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
    : d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

export function fmtMoney(n?: number | null): string {
  if (n === null || n === undefined) return "—";
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 }).format(n);
}

export function fmtNum(n: number): string {
  return Math.abs(n) >= 1000 ? new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 }).format(n) : String(Number(n.toFixed(3)));
}

export function titleCase(s?: string | null): string {
  if (!s) return "—";
  return s.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}

export function daysUntil(v?: string | null): number | null {
  if (!v) return null;
  const d = new Date(v.length === 10 ? v + "T00:00:00" : v).getTime();
  return Math.ceil((d - Date.now()) / 86400000);
}

export function tri(v: boolean | null | undefined, yes = "Yes", no = "No", unknown = "Unknown"): string {
  return v === null || v === undefined ? unknown : v ? yes : no;
}
