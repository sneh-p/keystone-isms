// Test cases for .semgrep/secure-coding.yml. Not compiled or executed.
import https from "node:https";
import { safeRedirectPath } from "./safe-url";

// ruleid: sc-cry-004-tls-verification-disabled-js
const insecure = new https.Agent({ keepAlive: true, rejectUnauthorized: false });
// ok: sc-cry-004-tls-verification-disabled-js
const secure = new https.Agent({ keepAlive: true });

export function afterLogin(nav: (p: string) => void, loc: { state: unknown }, params: URLSearchParams) {
  // ruleid: sc-xss-005-open-redirect-js
  nav((loc.state as any)?.from ?? "/");
  // ruleid: sc-xss-005-open-redirect-js
  window.location.href = params.get("next");
  // ok: sc-xss-005-open-redirect-js
  nav("/");
  // ok: sc-xss-005-open-redirect-js
  nav(safeRedirectPath((loc.state as any)?.from));
  return [insecure, secure];
}
