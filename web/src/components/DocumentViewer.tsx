import { useEffect, useState } from "react";
import { Download, Eye } from "lucide-react";
import { downloadUrl, fetchBytes } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/misc";

/**
 * In-app viewer for stored files. The server keeps sending files as downloads (SC-FILE-002); the viewer fetches the
 * bytes and builds its own Blob with a type chosen here from the file extension: PDF in a frame, images in <img>,
 * text as text. HTML, SVG and anything else is never rendered (download only), so a file can't run script in the app.
 */
const PREVIEW: Record<string, { kind: "pdf" | "image" | "text"; type: string }> = {
  pdf: { kind: "pdf", type: "application/pdf" },
  png: { kind: "image", type: "image/png" },
  jpg: { kind: "image", type: "image/jpeg" },
  jpeg: { kind: "image", type: "image/jpeg" },
  gif: { kind: "image", type: "image/gif" },
  txt: { kind: "text", type: "text/plain" },
  csv: { kind: "text", type: "text/plain" },
  md: { kind: "text", type: "text/plain" },
  json: { kind: "text", type: "text/plain" },
};

export function previewKind(filename: string | null | undefined) {
  const ext = (filename ?? "").split(".").pop()?.toLowerCase() ?? "";
  return PREVIEW[ext] ?? null;
}

export function DocumentViewer({ path, filename, title, onClose, headers }: { path: string; filename: string; title?: string; onClose: () => void; headers?: Record<string, string> }) {
  const p = previewKind(filename);
  const [url, setUrl] = useState<string | null>(null);
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const kind = p?.kind, type = p?.type;
  const headerKey = JSON.stringify(headers ?? {});
  useEffect(() => {
    if (!kind || !type) return;
    let made: string | null = null;
    let live = true;
    fetchBytes(path, JSON.parse(headerKey)).then((buf) => {
      if (!live) return;
      if (kind === "text") setText(new TextDecoder().decode(buf.slice(0, 2_000_000)));
      else { made = URL.createObjectURL(new Blob([buf], { type })); setUrl(made); }
    }, (e) => { if (live) setError((e as Error).message); });
    return () => { live = false; if (made) URL.revokeObjectURL(made); };
  }, [path, kind, type, headerKey]);
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={title ?? filename} description={filename} extraWide
      footer={<a href={downloadUrl(path)}><Button variant="outline"><Download /> Download</Button></a>}>
      {!p ? <p className="py-10 text-center text-sm text-muted-foreground">This file type can't be shown in the browser. Download it to open it.</p>
        : error ? <p role="alert" className="py-10 text-center text-sm text-critical">{error}</p>
        : p.kind === "text" ? (text === null ? <Skeleton className="h-96" /> : <pre className="max-h-[70vh] overflow-auto whitespace-pre-wrap rounded-md bg-muted p-4 text-xs">{text}</pre>)
        : !url ? <Skeleton className="h-[70vh]" />
        : p.kind === "pdf" ? <iframe src={url} title={`Preview of ${filename}`} className="h-[75vh] w-full rounded-md border" />
        : <img src={url} alt={`Preview of ${filename}`} className="mx-auto max-h-[75vh] max-w-full object-contain" />}
    </Dialog>
  );
}

/** A "View" button that opens the viewer for an attachment. */
export function ViewAttachment({ id, filename, title, size = "sm" }: { id: number; filename: string; title?: string; size?: "sm" | "icon" }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button size={size} variant="ghost" aria-label={`View ${title ?? filename}`} onClick={(e) => { e.stopPropagation(); setOpen(true); }}><Eye />{size === "sm" && " View"}</Button>
      {open && <DocumentViewer path={`/attachments/${id}`} filename={filename} title={title} onClose={() => setOpen(false)} />}
    </>
  );
}
