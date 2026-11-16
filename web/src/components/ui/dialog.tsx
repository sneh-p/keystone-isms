import * as D from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export function Dialog({ open, onOpenChange, title, description, children, footer, wide, extraWide }: { open: boolean; onOpenChange: (o: boolean) => void; title: ReactNode; description?: ReactNode; children: ReactNode; footer?: ReactNode; wide?: boolean; extraWide?: boolean }) {
  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-40 bg-black/40 backdrop-blur-[2px] animate-fade-in" />
        <D.Content className={cn("fixed inset-0 z-50 flex flex-col bg-card shadow-2xl animate-fade-in sm:inset-auto sm:left-1/2 sm:top-1/2 sm:max-h-[90vh] sm:w-[calc(100vw-2rem)] sm:-translate-x-1/2 sm:-translate-y-1/2 sm:rounded-lg sm:border", extraWide ? "max-w-5xl" : wide ? "max-w-3xl" : "max-w-lg")}>
          <div className="flex items-start justify-between gap-4 border-b px-5 py-4">
            <div>
              <D.Title className="font-semibold">{title}</D.Title>
              {description && <D.Description className="mt-1 text-sm text-muted-foreground">{description}</D.Description>}
            </div>
            <D.Close className="rounded p-1 text-muted-foreground hover:bg-muted" aria-label="Close">
              <X className="size-4" />
            </D.Close>
          </div>
          <div className="flex-1 overflow-y-auto px-5 py-4 sm:flex-initial">{children}</div>
          {footer && <div className="flex justify-end gap-2 border-t px-5 py-3">{footer}</div>}
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}

/** Right-hand drawer for detail views. */
export function Sheet({ open, onOpenChange, title, subtitle, children, actions }: { open: boolean; onOpenChange: (o: boolean) => void; title: ReactNode; subtitle?: ReactNode; children: ReactNode; actions?: ReactNode }) {
  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-40 bg-black/30 animate-fade-in" />
        <D.Content className="fixed inset-y-0 right-0 z-50 flex w-full max-w-2xl flex-col border-l bg-card shadow-2xl animate-fade-in">
          <div className="flex items-start justify-between gap-4 border-b px-4 py-4 sm:px-6">
            <div className="min-w-0">
              <D.Title className="truncate text-lg font-semibold">{title}</D.Title>
              {subtitle && <D.Description className="mt-0.5 text-sm text-muted-foreground">{subtitle}</D.Description>}
            </div>
            <div className="flex items-center gap-2">
              {actions}
              <D.Close className="rounded p-1 text-muted-foreground hover:bg-muted" aria-label="Close">
                <X className="size-5" />
              </D.Close>
            </div>
          </div>
          <div className="flex-1 overflow-y-auto px-4 py-5 sm:px-6">{children}</div>
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}
