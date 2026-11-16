import { useMemo, useRef, useState } from "react";
import { MessageSquare } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi, usePeople } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/input";
import { Section } from "@/components/ui/misc";

type Kind = "risk" | "control" | "task" | "incident" | "policy" | "vendor" | "nonconformity" | "audit";

/** Comment text as plain text, with @mentions emphasised (never rendered as HTML). */
function Body({ text }: { text: string }) {
  const parts = text.split(/(@[A-Za-z0-9][A-Za-z0-9._-]+)/g);
  return <p className="whitespace-pre-wrap break-words">{parts.map((p, i) => (p.startsWith("@") ? <span key={i} className="font-medium text-primary">{p}</span> : p))}</p>;
}

/** Discussion on a record. Anyone who can read the record can comment; @username notifies that person. */
export function Comments({ kind, id }: { kind: Kind; id: number }) {
  const { can } = useAuth();
  const { name } = usePeople();
  const key = `/comments/${kind}/${id}`;
  const { data } = useApi<any[]>(key);
  const people = useApi<{ username: string; display_name: string }[]>("/mentionable");
  const [text, setText] = useState("");
  const [cursor, setCursor] = useState(0);
  const box = useRef<HTMLTextAreaElement>(null);
  const post = useAction(() => api(key, { body: { body: text } }), {
    success: (r: any) => (r.notified?.length ? `Comment added; notified ${r.notified.join(", ")}.` : "Comment added."), invalidate: [key], onSuccess: () => setText(""),
  });
  const query = useMemo(() => /(?:^|\s)@([\w.-]*)$/.exec(text.slice(0, cursor))?.[1] ?? null, [text, cursor]);
  const matches = query === null ? [] : (people.data ?? []).filter((p) => `${p.username} ${p.display_name}`.toLowerCase().includes(query.toLowerCase())).slice(0, 6);
  const pick = (u: string) => {
    const before = text.slice(0, cursor).replace(/@[\w.-]*$/, `@${u} `);
    const next = before + text.slice(cursor);
    setText(next);
    setCursor(before.length);
    requestAnimationFrame(() => { box.current?.focus(); box.current?.setSelectionRange(before.length, before.length); });
  };
  if (!can("read")) return null;
  return (
    <Section title={`Discussion (${data?.length ?? 0})`}>
      <ul className="space-y-2">
        {(data ?? []).map((c) => (
          <li key={c.id} className="rounded-md bg-muted/60 px-3 py-2 text-sm">
            <div className="mb-0.5 text-xs text-muted-foreground">{name(c.created_by_id)} · {fmtDate(c.created_at, true)}</div>
            <Body text={c.body} />
          </li>
        ))}
      </ul>
      <div className="relative mt-2">
        <Textarea ref={box} aria-label="Add a comment" placeholder="Add a comment. Type @ to mention someone." value={text} maxLength={5000} className="min-h-16"
          onChange={(e) => { setText(e.target.value); setCursor(e.target.selectionStart ?? e.target.value.length); }}
          onKeyUp={(e) => setCursor(e.currentTarget.selectionStart ?? 0)} onClick={(e) => setCursor(e.currentTarget.selectionStart ?? 0)} />
        {matches.length > 0 && (
          <ul role="listbox" aria-label="People to mention" className="absolute left-0 top-full z-20 mt-1 w-64 rounded-md border bg-popover py-1 text-sm shadow-lg">
            {matches.map((p) => (
              <li key={p.username} role="option" aria-selected={false}>
                <button type="button" className="w-full px-3 py-1.5 text-left hover:bg-muted" onMouseDown={(e) => { e.preventDefault(); pick(p.username); }}>
                  {p.display_name} <span className="text-xs text-muted-foreground">@{p.username}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
      <Button size="sm" className="mt-2" disabled={!text.trim()} loading={post.isPending} onClick={() => post.mutate(undefined)}><MessageSquare /> Comment</Button>
    </Section>
  );
}
