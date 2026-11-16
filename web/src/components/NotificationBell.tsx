import * as P from "@radix-ui/react-popover";
import { useNavigate } from "react-router-dom";
import { Bell, CheckCheck } from "lucide-react";
import { api } from "@/lib/api";
import { useAction, useApi } from "@/lib/hooks";
import { cn, fmtDate } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Switch } from "@/components/ui/misc";

type Item = { id: number; kind: string; title: string; page: string; due: string | null; read_at: string | null };

/** Header bell: the signed-in user's own inbox. Refreshes every minute. */
export function NotificationBell() {
  const nav = useNavigate();
  const { data } = useQuery<{ items: Item[]; unread: number }>({ queryKey: ["/portal/notifications"], queryFn: () => api("/portal/notifications"), refetchInterval: 60_000 });
  const read = useAction((ids: number[] | null) => api("/portal/notifications/read", { body: ids ? { ids } : {} }), { invalidate: ["/portal/notifications"] });
  const unread = data?.unread ?? 0;
  const open = (n: Item) => {
    if (!n.read_at) read.mutate([n.id]);
    nav(n.page);
  };
  return (
    <P.Root>
      <P.Trigger asChild>
        <button className="relative rounded-md p-2 hover:bg-muted" aria-label={unread ? `Notifications, ${unread} unread` : "Notifications"}>
          <Bell className="size-4" />
          {unread > 0 && <span className="absolute right-0.5 top-0.5 grid min-w-4 place-items-center rounded-full bg-critical px-1 text-[10px] font-semibold leading-4 text-white" aria-hidden>{unread > 99 ? "99+" : unread}</span>}
        </button>
      </P.Trigger>
      <P.Portal>
        <P.Content align="end" sideOffset={6} className="z-50 w-[min(24rem,calc(100vw-1rem))] rounded-lg border bg-popover shadow-xl">
          <div className="flex items-center justify-between border-b px-4 py-2.5">
            <h2 className="text-sm font-semibold">Notifications</h2>
            {unread > 0 && <button className="inline-flex items-center gap-1 text-xs text-primary hover:underline" onClick={() => read.mutate(null)}><CheckCheck className="size-3.5" aria-hidden /> Mark all read</button>}
          </div>
          <ul className="max-h-[60vh] divide-y overflow-y-auto">
            {(data?.items ?? []).length === 0 && <li className="px-4 py-8 text-center text-sm text-muted-foreground">Nothing needs you right now.</li>}
            {(data?.items ?? []).map((n) => (
              <li key={n.id}>
                <P.Close asChild>
                  <button onClick={() => open(n)} className={cn("flex w-full gap-3 px-4 py-2.5 text-left text-sm hover:bg-muted/60", !n.read_at && "bg-primary/5")}>
                    <span className={cn("mt-1.5 size-2 shrink-0 rounded-full", n.read_at ? "bg-transparent" : "bg-primary")} aria-hidden />
                    <span className="min-w-0 flex-1">
                      <span className={cn("block", !n.read_at && "font-medium")}>{n.title}</span>
                      <span className="text-xs text-muted-foreground">{n.read_at ? "" : "Unread · "}{n.due ? `Due ${fmtDate(n.due)}` : "Waiting on you"}</span>
                    </span>
                  </button>
                </P.Close>
              </li>
            ))}
          </ul>
        </P.Content>
      </P.Portal>
    </P.Root>
  );
}

/** "Daily email digest" switch for My account. */
export function DigestPreference() {
  const { data } = useApi<{ email_digest: boolean; has_email: boolean }>("/portal/notifications");
  const save = useAction((v: boolean) => api("/portal/notifications/prefs", { method: "PUT", body: { email_digest: v } }), { success: "Saved.", invalidate: ["/portal/notifications"] });
  if (!data) return null;
  return (
    <Card>
      <CardHeader title="Notifications" description="The bell at the top lists what needs you. A daily email lists anything still unread." />
      <CardBody className="space-y-2">
        <Switch checked={data.email_digest} onChange={(v) => save.mutate(v)} label="Daily email digest" />
        {!data.has_email && <p className="text-xs text-muted-foreground">Your account has no email address, so no digest can be sent. Ask an administrator to add one.</p>}
      </CardBody>
    </Card>
  );
}
