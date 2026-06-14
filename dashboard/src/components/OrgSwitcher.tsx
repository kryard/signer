import { useState } from "react";
import { Plus } from "lucide-react";
import { useOrg } from "@/context/OrgContext";
import { getErrorMessage } from "@/lib/format";
import { Button } from "./ui/Button";
import { ErrorNote } from "./ui/Feedback";

/**
 * Org switcher pinned to the top of the left nav: select an organization
 * (persisted to localStorage) or create a new one inline.
 */
export function OrgSwitcher() {
  const { orgs, selectedOrg, selectOrg, createOrg } = useOrg();
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    if (!name.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      await createOrg(name.trim());
      setName("");
      setCreating(false);
    } catch (err: unknown) {
      setError(getErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-2">
      <span className="eyebrow block text-mist">Organization</span>
      {orgs.length > 0 && (
        <select
          value={selectedOrg?.id ?? ""}
          onChange={(e) => selectOrg(e.target.value)}
          className="field-input appearance-none"
          aria-label="Select organization"
        >
          {orgs.map((org) => (
            <option key={org.id} value={org.id}>
              {org.name}
            </option>
          ))}
        </select>
      )}

      {creating ? (
        <div className="space-y-2">
          <input
            autoFocus
            value={name}
            placeholder="Org name"
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void submit();
              if (e.key === "Escape") setCreating(false);
            }}
            className="field-input"
          />
          <div className="flex gap-2">
            <Button size="sm" onClick={() => void submit()} disabled={busy || !name.trim()}>
              {busy ? "Creating…" : "Create"}
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setCreating(false)}>
              Cancel
            </Button>
          </div>
          {error && <ErrorNote message={error} />}
        </div>
      ) : (
        <button
          type="button"
          onClick={() => setCreating(true)}
          className="inline-flex items-center gap-1.5 text-xs text-mist transition-colors hover:text-signal"
        >
          <Plus className="h-3.5 w-3.5" /> New org
        </button>
      )}
    </div>
  );
}
