/** SC-XSS-002 and SC-XSS-005: URLs taken from data must not execute code or leave the app. */

const ALLOWED_SCHEMES = new Set(["https:", "http:", "mailto:"]);

/** A safe href for a URL from data (Markdown, settings, API), or undefined if it isn't allowed. */
export function safeHref(raw: unknown): string | undefined {
  if (typeof raw !== "string" || raw.length > 4096) return undefined;
  const value = raw.trim();
  if (value.startsWith("/") && !value.startsWith("//") && !value.startsWith("/\\")) return value; // same-origin path
  if (value.startsWith("#")) return value;
  try {
    const url = new URL(value);
    return ALLOWED_SCHEMES.has(url.protocol) ? url.href : undefined;
  } catch {
    return undefined;
  }
}

/** A same-origin path to navigate to after sign-in; anything else becomes "/". */
export function safeRedirectPath(raw: unknown): string {
  return typeof raw === "string" && raw.startsWith("/") && !raw.startsWith("//") && !raw.startsWith("/\\") ? raw : "/";
}
