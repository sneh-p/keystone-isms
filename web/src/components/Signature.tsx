import { Input } from "@/components/ui/input";

const norm = (s: string) => s.split(/\s+/).filter(Boolean).join(" ").toLocaleLowerCase();

/** True when the typed name matches the signer's name (case and spacing ignored), as the server checks. */
export function signatureOk(typed: string, expected?: string | null) {
  return !!expected && norm(typed) !== "" && norm(typed) === norm(expected);
}

/** Electronic signature: the person types their full name. The server binds it to a fingerprint of the exact text. */
export function SignatureInput({ value, onChange, expected }: { value: string; onChange: (v: string) => void; expected?: string | null }) {
  const ok = signatureOk(value, expected);
  return (
    <label className="block min-w-64 flex-1 text-sm">
      <span className="mb-1 block font-medium">Sign by typing your full name{expected ? `: ${expected}` : ""}</span>
      <Input value={value} onChange={(e) => onChange(e.target.value)} autoComplete="off" aria-invalid={value !== "" && !ok} placeholder={expected ?? ""}
        className={value !== "" && !ok ? "border-critical" : undefined} />
    </label>
  );
}
