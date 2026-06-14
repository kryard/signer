import { cn } from "@/lib/cn";

/**
 * Kryard brand mark — ported from apps/web (kryptonite crystal in the Ethereum
 * octahedron silhouette). Faceted signal-green gem with a tone-adaptive
 * outline, so the single mark reads on light or dark surfaces.
 */
export function LogoMark({
  className,
  tone = "paper",
}: {
  className?: string;
  tone?: "ink" | "paper";
}) {
  const SIGNAL = "var(--color-signal)";
  return (
    <svg
      viewBox="0 0 28 28"
      className={cn(
        "h-[1.6rem] w-[1.6rem]",
        tone === "ink" ? "text-ink" : "text-paper",
        className,
      )}
      fill="none"
      aria-hidden
    >
      {/* faceted gem body — four facets, left-lit for a crystal sheen */}
      <polygon points="14,1.6 3.8,14 14,14" fill={SIGNAL} opacity="0.95" />
      <polygon points="14,1.6 14,14 24.2,14" fill={SIGNAL} opacity="0.62" />
      <polygon points="3.8,14 14,14 14,26.4" fill={SIGNAL} opacity="0.8" />
      <polygon points="14,14 24.2,14 14,26.4" fill={SIGNAL} opacity="0.46" />

      {/* crystalline belt + central ridge */}
      <g
        stroke="currentColor"
        strokeWidth="0.9"
        strokeLinejoin="round"
        strokeLinecap="round"
        opacity="0.28"
      >
        <polyline points="3.8,14 14,8.4 24.2,14" />
        <polyline points="3.8,14 14,19.6 24.2,14" />
        <line x1="14" y1="1.6" x2="14" y2="26.4" />
      </g>

      {/* tone-adaptive outline keeps the silhouette crisp on any background */}
      <path
        d="M14 1.6 L24.2 14 L14 26.4 L3.8 14 Z"
        stroke="currentColor"
        strokeWidth="1.3"
        strokeLinejoin="round"
      />
    </svg>
  );
}
