/**
 * OrgContext — the selected organization, shared by every console page.
 * The selection persists to localStorage so reloads keep the same org.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { client } from "@/lib/client";
import type { OrgSummary } from "@/lib/types";
import { getErrorMessage } from "@/lib/format";

const ORG_STORAGE_KEY = "kryard.console.orgId";

interface OrgContextValue {
  orgs: OrgSummary[];
  selectedOrg: OrgSummary | null;
  loading: boolean;
  error: string | null;
  selectOrg: (orgId: string) => void;
  createOrg: (name: string) => Promise<void>;
  refresh: () => Promise<void>;
}

const OrgContext = createContext<OrgContextValue | null>(null);

export function OrgProvider({ children }: { children: ReactNode }) {
  const [orgs, setOrgs] = useState<OrgSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(
    () => localStorage.getItem(ORG_STORAGE_KEY),
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setError(null);
    try {
      const list = await client.listOrgs();
      setOrgs(list);
    } catch (err: unknown) {
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const selectOrg = useCallback((orgId: string) => {
    setSelectedId(orgId);
    localStorage.setItem(ORG_STORAGE_KEY, orgId);
  }, []);

  const createOrg = useCallback(
    async (name: string) => {
      const created = await client.createOrg(name);
      await refresh();
      selectOrg(created.organizationId);
    },
    [refresh, selectOrg],
  );

  const selectedOrg = useMemo(() => {
    if (orgs.length === 0) return null;
    return orgs.find((o) => o.id === selectedId) ?? orgs[0] ?? null;
  }, [orgs, selectedId]);

  const value = useMemo<OrgContextValue>(
    () => ({ orgs, selectedOrg, loading, error, selectOrg, createOrg, refresh }),
    [orgs, selectedOrg, loading, error, selectOrg, createOrg, refresh],
  );

  return <OrgContext.Provider value={value}>{children}</OrgContext.Provider>;
}

export function useOrg(): OrgContextValue {
  const ctx = useContext(OrgContext);
  if (!ctx) throw new Error("useOrg must be used inside <OrgProvider>");
  return ctx;
}
