/** Configuration baselines: helpers for showing and editing rules. */

export interface Setting {
  key: string;
  type: "bool" | "int" | "str" | "list";
  title: string;
  description: string;
  requires: string | null;
  choices: string[];
  operators: string[];
  recommended: { operator: string; expected: unknown; severity: string; controls: string[] } | null;
  custom?: boolean;
}

const RESULT: Record<string, string> = { pass: "Pass", fail: "Fail", unknown: "Unknown", na: "Not applicable", excepted: "Exception" };

export function resultLabel(status: string): string {
  return RESULT[status] ?? status;
}

/** The text box shows a rule's expected value; lists are comma-separated. */
export function expectedToInput(expected: unknown): string {
  if (expected === null || expected === undefined) return "";
  if (Array.isArray(expected)) return expected.join(", ");
  return String(expected);
}

/** The value to send for a rule: nothing for on/off checks, a list for "one of", a number for numeric settings. */
export function expectedFromInput(setting: Pick<Setting, "type">, operator: string, text: string): unknown {
  if (["is_true", "is_false", "empty"].includes(operator)) return null;
  if (operator === "in" || operator === "not_in") return text.split(",").map((s) => s.trim()).filter(Boolean);
  if (setting.type === "int") {
    const n = Number(text.trim());
    return text.trim() !== "" && Number.isInteger(n) ? n : text.trim();
  }
  return text.trim();
}

export function describeExpected(operators: Record<string, string>, operator: string, expected: unknown): string {
  const label = operators[operator] ?? operator;
  if (expected === null || expected === undefined || expected === "") return label;
  return `${label} ${Array.isArray(expected) ? expected.join(", ") : String(expected)}`;
}

/** "web, DMZ ,,db" → ["web", "dmz", "db"]: tags are lower-case and unique. */
export function parseTags(text: string): string[] {
  const out: string[] = [];
  for (const t of text.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean)) if (!out.includes(t)) out.push(t);
  return out;
}

/** Host-name patterns keep their case and order. */
export function parseList(text: string): string[] {
  return text.split(",").map((s) => s.trim()).filter(Boolean);
}

export interface ProbeParam { name: string; label: string; kind: string; required: boolean; choices: string[]; hint: string }
export interface Probe { key: string; platforms: string[]; label: string; description: string; mode_param: string | null; types: Record<string, string[]>; default_allowed: boolean; reads_content: boolean; params: ProbeParam[] }

/** The value types a probe can report for the chosen mode or field ("" when it has none). */
export function allowedTypes(probe: Probe | undefined, params: Record<string, string>): string[] {
  if (!probe) return [];
  const mode = probe.mode_param ? params[probe.mode_param] ?? "" : "";
  return probe.types[mode] ?? [];
}
