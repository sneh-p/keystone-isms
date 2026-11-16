import * as T from "@radix-ui/react-tabs";
import type { ReactNode } from "react";

/** Uncontrolled by default; pass value and onValueChange to keep the active tab elsewhere (e.g. in the address). */
export function Tabs({ tabs, defaultValue, value, onValueChange }: { tabs: { value: string; label: ReactNode; content: ReactNode }[]; defaultValue?: string; value?: string; onValueChange?: (v: string) => void }) {
  const controlled = value !== undefined ? { value, onValueChange } : { defaultValue: defaultValue ?? tabs[0]?.value };
  return (
    <T.Root {...controlled}>
      <T.List className="mb-4 flex gap-1 overflow-x-auto border-b">
        {tabs.map((t) => (
          <T.Trigger key={t.value} value={t.value} className="-mb-px whitespace-nowrap border-b-2 border-transparent px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground data-[state=active]:border-primary data-[state=active]:text-foreground">
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
