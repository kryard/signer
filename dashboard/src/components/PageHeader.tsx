import type { ReactNode } from "react";

/** Standard page header: display-font title + optional description/actions. */
export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="font-display text-2xl font-semibold tracking-[-0.02em] text-paper">
          {title}
        </h1>
        {description && <p className="mt-1 text-sm text-mist-2">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </header>
  );
}
