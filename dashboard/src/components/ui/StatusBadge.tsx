import { cn } from "@/lib/cn";

/**
 * Color-coded activity/status badge:
 * COMPLETED → signal green, FAILED/REJECTED → red, PENDING → amber.
 */
export function statusTone(status: string): "ok" | "bad" | "warn" | "neutral" {
  const s = status.toUpperCase();
  if (s.includes("COMPLETED") || s === "ACTIVE" || s === "ALLOWED") return "ok";
  if (s.includes("FAILED") || s.includes("REJECTED") || s.includes("DENIED") || s === "DISABLED")
    return "bad";
  if (s.includes("PENDING") || s.includes("REQUIRES")) return "warn";
  return "neutral";
}

const tones = {
  ok: "border-signal/40 bg-signal/10 text-signal",
  bad: "border-danger/40 bg-danger/10 text-danger",
  warn: "border-amber/40 bg-amber/10 text-amber",
  neutral: "border-line bg-ink-3 text-mist-2",
} as const;

export function StatusBadge({ status, className }: { status: string; className?: string }) {
  return (
    <span
      className={cn(
        "eyebrow inline-flex items-center rounded-full border px-2.5 py-1",
        tones[statusTone(status)],
        className,
      )}
    >
      {status.replace(/^ACTIVITY_STATUS_/, "")}
    </span>
  );
}
