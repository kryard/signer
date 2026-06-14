import clsx, { type ClassValue } from "clsx";

/**
 * Merge conditional class names. Thin wrapper over clsx so every component
 * imports from one place (and we can swap in tailwind-merge later if needed).
 */
export function cn(...inputs: ClassValue[]): string {
  return clsx(inputs);
}
