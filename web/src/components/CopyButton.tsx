import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";

/** Copies text. Falls back to a hidden textarea where the Clipboard API is unavailable (plain HTTP). */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (window.isSecureContext && navigator.clipboard) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fall through */
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  document.body.removeChild(ta);
  return ok;
}

export function CopyButton({ text, label = "Copy", size = "sm", variant = "outline" }: { text: string; label?: string; size?: "sm" | "md"; variant?: "outline" | "ghost" | "secondary" }) {
  const [done, setDone] = useState(false);
  return (
    <Button type="button" size={size} variant={variant} onClick={async () => {
      if (await copyText(text)) { setDone(true); setTimeout(() => setDone(false), 1500); }
      else toast.error("Copy failed. Select the text and copy it manually.");
    }}>
      {done ? <Check /> : <Copy />} {done ? "Copied" : label}
    </Button>
  );
}

/** A command or code snippet with a copy button. */
export function CodeBlock({ code, label }: { code: string; label?: string }) {
  return (
    <div className="group relative">
      <pre className="whitespace-pre-wrap break-all rounded-md border bg-muted/50 px-4 py-3 pr-28 font-mono text-xs leading-5" aria-label={label}>{code}</pre>
      <div className="absolute right-2 top-2"><CopyButton text={code} variant="secondary" /></div>
    </div>
  );
}
