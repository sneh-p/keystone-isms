import * as T from "@radix-ui/react-tabs";
import type { ReactNode } from "react";

/** Uncontrolled by default; pass value and onValueChange to keep the active tab elsewhere (e.g. in the address). */
export function Tabs({ tabs, defaultValue, value, onValueChange }: { tabs: { value: string; label: ReactNode; content: ReactNode }[]; defaultValue?: string; value?: string; onValueChange?: (v: string) => void }) {
  const controlled = value !== undefined ? { value, onValueChange } : { defaultValue: defaultValue ?? tabs[0]?.value };
  return (
    <T.Root {...controlled}>
      {/* In-page tabs are a segmented control, so they read as a level below the underlined area tabs (AppShell). */}
      <T.List className="mb-5 flex max-w-full gap-0.5 overflow-x-auto rounded-lg border bg-muted/70 p-1 sm:w-fit">
        {tabs.map((t) => (
          <T.Trigger key={t.value} value={t.value} className="whitespace-nowrap rounded-md px-3 py-1.5 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring data-[state=active]:bg-card data-[state=active]:text-foreground data-[state=active]:shadow-card">
            {t.label}
          </T.Trigger>
        ))}
      </T.List>
      {tabs.map((t) => (
        <T.Content key={t.value} value={t.value} className="animate-fade-in focus:outline-none">
          {t.content}
        </T.Content>
      ))}
    </T.Root>
  );
}
