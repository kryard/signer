import type { ReactNode } from "react";
import { AlertTriangle, Loader2 } from "lucide-react";
import { cn } from "@/lib/cn";

/** Inline loading row used while a fetch is in flight. */
export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 py-6 text-sm text-mist">
      <Loader2 className="h-4 w-4 animate-spin text-signal" aria-hidden />
      {label}
    </div>
  );
}

/** Inline error note with the server's message. */
export function ErrorNote({ message, className }: { message: string; className?: string }) {
  return (
    <div
      role="alert"
      className={cn(
        "flex items-start gap-2 rounded-lg border border-danger/40 bg-danger/10 px-3.5 py-2.5 text-sm text-danger",
        className,
      )}
    >
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
      <span className="break-words">{message}</span>
    </div>
  );
}

/** Friendly empty state for tables / lists. */
export function EmptyState({
  title,
  children,
}: {
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center gap-2 py-10 text-center">
      <p className="font-display text-base text-paper/80">{title}</p>
      {children && <div className="text-sm text-mist">{children}</div>}
    </div>
  );
}
