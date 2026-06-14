import { NavLink, Outlet } from "react-router-dom";
import {
  Activity,
  Gauge,
  KeyRound,
  PenLine,
  Settings as SettingsIcon,
  ShieldCheck,
  UserRound,
  Wallet as WalletIcon,
} from "lucide-react";
import { cn } from "@/lib/cn";
import { useOrg } from "@/context/OrgContext";
import { LogoMark } from "./LogoMark";
import { OrgSwitcher } from "./OrgSwitcher";
import { BootstrapCard } from "./BootstrapCard";
import { ErrorNote, Loading } from "./ui/Feedback";

const NAV = [
  { to: "/", label: "Overview", icon: Gauge, end: true },
  { to: "/wallets", label: "Wallets", icon: WalletIcon },
  { to: "/policies", label: "Policies", icon: ShieldCheck },
  { to: "/activities", label: "Activities", icon: Activity },
  { to: "/keys", label: "API keys", icon: KeyRound },
  { to: "/sign", label: "Sign", icon: PenLine },
] as const;

const SECONDARY_NAV = [
  { to: "/settings", label: "Settings", icon: SettingsIcon },
  { to: "/profile", label: "Profile", icon: UserRound },
] as const;

/** Console chrome: fixed left nav (brand, org switcher, links) + page outlet. */
export function Shell() {
  const { orgs, loading, error, refresh } = useOrg();

  return (
    <div className="flex min-h-screen">
      <aside className="flex w-60 shrink-0 flex-col border-r border-line bg-ink-2">
        <div className="flex items-center gap-2.5 border-b border-line px-5 py-4">
          <LogoMark tone="paper" />
          <span className="font-display text-lg font-semibold tracking-[-0.02em] text-paper">
            Kryard
          </span>
          <span className="eyebrow rounded-full border border-line px-2 py-0.5 text-mist">
            Console
          </span>
        </div>

        <div className="border-b border-line px-5 py-4">
          <OrgSwitcher />
        </div>

        <nav className="flex-1 space-y-0.5 px-3 py-4">
          {NAV.map(({ to, label, icon: Icon, ...rest }) => (
            <NavLink
              key={to}
              to={to}
              end={"end" in rest ? rest.end : false}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors duration-150",
                  isActive
                    ? "bg-signal/10 text-signal"
                    : "text-mist-2 hover:bg-ink-3 hover:text-paper",
                )
              }
            >
              <Icon className="h-4 w-4" aria-hidden />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="space-y-0.5 border-t border-line px-3 py-3">
          {SECONDARY_NAV.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors duration-150",
                  isActive
                    ? "bg-signal/10 text-signal"
                    : "text-mist-2 hover:bg-ink-3 hover:text-paper",
                )
              }
            >
              <Icon className="h-4 w-4" aria-hidden />
              {label}
            </NavLink>
          ))}
        </div>

        <div className="border-t border-line px-5 py-3">
          <p className="eyebrow text-mist">Turnkey-compatible</p>
          <p className="mt-1 text-xs text-mist">Keys you never touch.</p>
        </div>
      </aside>

      <main className="min-w-0 flex-1 px-8 py-8">
        {loading ? (
          <Loading label="Loading organizations…" />
        ) : error ? (
          <div className="max-w-xl space-y-3">
            <ErrorNote message={`Could not load organizations: ${error}`} />
            <button
              type="button"
              className="text-sm text-signal underline-offset-4 hover:underline"
              onClick={() => void refresh()}
            >
              Retry
            </button>
          </div>
        ) : orgs.length === 0 ? (
          <BootstrapCard />
        ) : (
          <Outlet />
        )}
      </main>
    </div>
  );
}
