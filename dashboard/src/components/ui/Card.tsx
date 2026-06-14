import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

interface CardProps {
  children: ReactNode;
  className?: string;
  title?: string;
  /** Right-aligned header content (buttons, counts). */
  actions?: ReactNode;
}

/** Standard console panel: ink-2 surface, hairline border, mono eyebrow title. */
export function Card({ children, className, title, actions }: CardProps) {
  return (
    <section className={cn("rounded-xl border border-line bg-ink-2", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-4 border-b border-line px-5 py-3.5">
          {title && <h2 className="eyebrow text-mist-2">{title}</h2>}
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}
