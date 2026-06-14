import { useState } from "react";
import { useOrg } from "@/context/OrgContext";
import { client, isLocalMode } from "@/lib/client";
import { useAsync } from "@/lib/useAsync";
import { formatTime, getErrorMessage } from "@/lib/format";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Field } from "@/components/ui/Field";
import { MonoCopy } from "@/components/ui/CopyButton";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { ErrorNote, Loading } from "@/components/ui/Feedback";

/** Map a service status string onto the console's badge colors. */
function serviceBadge(status: string): string {
  if (status === "ok") return "COMPLETED";
  if (status === "disabled") return "PENDING";
  return "FAILED";
}

export function Settings() {
  const { selectedOrg, refresh } = useOrg();
  const orgId = selectedOrg?.id ?? "";

  const { data, loading, error, reload } = useAsync(async () => {
    const [org, status] = await Promise.all([
      client.getOrg(orgId),
      client.getStatus().catch((e: unknown) => ({ error: getErrorMessage(e) })),
    ]);
    return { org, status };
  }, [orgId]);

  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [renameError, setRenameError] = useState<string | null>(null);
  const [renamed, setRenamed] = useState(false);

  const rename = async () => {
    if (!name.trim() || busy) return;
    setBusy(true);
    setRenameError(null);
    setRenamed(false);
    try {
      await client.renameOrg(orgId, name.trim());
      setRenamed(true);
      setName("");
      await refresh(); // org switcher + header pick up the new name
      await reload();
    } catch (err: unknown) {
      setRenameError(getErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  if (!selectedOrg) return null;

  const status =
    data && !("error" in (data.status as Record<string, unknown>))
      ? (data.status as { api: string; signer: string })
      : null;
  const statusError =
    data && "error" in (data.status as Record<string, unknown>)
      ? (data.status as { error: string }).error
      : null;

  return (
    <>
      <PageHeader
        title="Settings"
        description="Organization settings and environment status."
      />

      {loading && <Loading />}
      {error && <ErrorNote message={error} />}

      {data && (
        <div className="space-y-6">
          <Card title="Organization">
            <div className="space-y-4">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="eyebrow w-32 shrink-0 text-mist">Name</span>
                <span className="text-paper">{data.org.name}</span>
              </div>
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="eyebrow w-32 shrink-0 text-mist">Organization id</span>
                <MonoCopy value={data.org.id} />
              </div>
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="eyebrow w-32 shrink-0 text-mist">Created</span>
                <span className="text-mist-2">{formatTime(data.org.createdAt)}</span>
              </div>

              <div className="max-w-md space-y-3 border-t border-line pt-4">
                <Field label="Rename organization" value={name} onChange={setName} placeholder={data.org.name} />
                {renameError && <ErrorNote message={renameError} />}
                {renamed && <p className="text-sm text-signal">Organization renamed.</p>}
                <Button size="sm" onClick={() => void rename()} disabled={!name.trim() || busy}>
                  {busy ? "Renaming…" : "Rename"}
                </Button>
              </div>
            </div>
          </Card>

          <Card title="Actors">
            {data.org.actors.length === 0 ? (
              <p className="text-sm text-mist">No actors.</p>
            ) : (
              <ul className="space-y-2">
                {data.org.actors.map((a) => (
                  <li key={a.id} className="flex flex-wrap items-center gap-3 text-sm">
                    <span className="text-paper">{a.name}</span>
                    <span className="font-mono text-xs text-mist">{a.id}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card title="Environment">
            {isLocalMode && (
              <p className="mb-3 text-xs text-mist">
                Running locally, no auth — the dashboard talks directly to your local Kryard
                API with no Cloudflare Access and no admin token.
              </p>
            )}
            {status ? (
              <div className="space-y-3">
                {(
                  [
                    ["API", status.api, "Turnkey-compatible API (Cloudflare Worker + Postgres)"],
                    ["Wallet signer", status.signer, "secp256k1 EVM signing — Go signer + KMS envelope encryption"],
                  ] as const
                ).map(([label, value, hint]) => (
                  <div key={label} className="flex flex-wrap items-center gap-3 text-sm">
                    <span className="eyebrow w-32 shrink-0 text-mist">{label}</span>
                    <StatusBadge status={serviceBadge(value)} />
                    <span className="font-mono text-xs text-mist-2">{value}</span>
                    <span className="text-xs text-mist">{hint}</span>
                  </div>
                ))}
              </div>
            ) : (
              <ErrorNote message={`Status unavailable: ${statusError ?? "unknown error"}`} />
            )}
          </Card>
        </div>
      )}
    </>
  );
}
