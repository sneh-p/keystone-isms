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

export async function api<T = any>(path: string, opts: { method?: string; body?: unknown } = {}): Promise<T> {
  const method = opts.method ?? (opts.body === undefined ? "GET" : "POST");
  const res = await fetch(`/api${path}`, {
    method,
    credentials: "same-origin",
    headers: headers(method, opts.body !== undefined),
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
