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
