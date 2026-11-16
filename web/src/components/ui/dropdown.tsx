import * as M from "@radix-ui/react-dropdown-menu";
import type { ReactNode } from "react";

export function Menu({ trigger, items, align = "end" }: { trigger: ReactNode; items: ({ label: ReactNode; onSelect: () => void; icon?: any; danger?: boolean } | "sep")[]; align?: "start" | "end" }) {
  return (
    <M.Root>
      <M.Trigger asChild>{trigger}</M.Trigger>
      <M.Portal>
        <M.Content align={align} sideOffset={6} className="z-50 min-w-48 rounded-md border bg-popover p-1 text-sm shadow-lg animate-fade-in">
          {items.map((it, i) =>
            it === "sep" ? (
              <M.Separator key={i} className="my-1 h-px bg-border" />
            ) : (
              <M.Item key={i} onSelect={it.onSelect} className={`flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 outline-none data-[highlighted]:bg-muted ${it.danger ? "text-critical" : ""}`}>
                {it.icon && <it.icon className="size-4" />}
                {it.label}
              </M.Item>
            ),
          )}
        </M.Content>
      </M.Portal>
    </M.Root>
  );
}
