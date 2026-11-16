/** Fetch wrapper: same-origin cookies, CSRF header on writes, JSON errors as ApiError. */

let csrfToken: string | null = null;

export function setCsrf(token: string | null) {
  csrfToken = token;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function parse(res: Response) {
  const text = await res.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!res.ok) {
    let msg = res.statusText;
    if (data && typeof data === "object" && "detail" in data) {
      msg = Array.isArray(data.detail) ? data.detail.map((d: any) => `${(d.loc || []).slice(1).join(".")}: ${d.msg}`).join("; ") : String(data.detail);
    }
    throw new ApiError(res.status, msg);
  }
  return data;
}

function headers(method: string, json: boolean): HeadersInit {
  const h: Record<string, string> = {};
  if (json) h["Content-Type"] = "application/json";
  if (method !== "GET" && csrfToken) h["X-CSRF-Token"] = csrfToken;
  return h;
}

export async function api<T = any>(path: string, opts: { method?: string; body?: unknown; headers?: Record<string, string> } = {}): Promise<T> {
  const method = opts.method ?? (opts.body === undefined ? "GET" : "POST");
  const res = await fetch(`/api${path}`, {
    method,
    credentials: "same-origin",
    headers: { ...(headers(method, opts.body !== undefined) as Record<string, string>), ...(opts.headers ?? {}) },
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  });
  return parse(res);
}

export async function upload<T = any>(path: string, form: FormData, method = "POST"): Promise<T> {
  const res = await fetch(`/api${path}`, { method, credentials: "same-origin", headers: headers(method, false), body: form });
  return parse(res);
}

export function downloadUrl(path: string) {
  return `/api${path}`;
}

/** Downloads a file that needs request headers (for example an access token, which must not go in the URL). */
export async function saveDownload(path: string, extraHeaders: Record<string, string> = {}): Promise<void> {
  const res = await fetch(`/api${path}`, { credentials: "same-origin", headers: extraHeaders });
  if (!res.ok) await parse(res);
  const name = /filename="([^"]+)"/.exec(res.headers.get("content-disposition") ?? "")?.[1] ?? "download";
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** A secret from the URL fragment (#key=value). Fragments are never sent to the server, so they stay out of logs. */
export function fragmentParam(key: string): string | null {
  return new URLSearchParams(window.location.hash.replace(/^#/, "")).get(key);
}

/** A link the API handed out: its full URL when the server knows its public address, else this origin plus the path. */
export function absoluteLink(link: { url?: string | null; path: string }): string {
  return link.url ?? `${window.location.origin}${link.path}`;
}
