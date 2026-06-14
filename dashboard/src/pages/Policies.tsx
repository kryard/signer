import { useState } from "react";
import { Trash2 } from "lucide-react";
import { useOrg } from "@/context/OrgContext";
import { client } from "@/lib/client";
import { useAsync } from "@/lib/useAsync";
import { getErrorMessage, truncateMiddle } from "@/lib/format";
import type { Wallet } from "@/lib/types";
import { PageHeader } from "@/components/PageHeader";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { MonoCopy } from "@/components/ui/CopyButton";
import { Table, THead, TBody, Tr, Td } from "@/components/ui/Table";
import { EmptyState, ErrorNote, Loading } from "@/components/ui/Feedback";
import { CreatePolicyForm } from "@/components/policies/CreatePolicyForm";
import { AddDestinationForm } from "@/components/policies/AddDestinationForm";

function walletLabel(wallets: Wallet[], privateKeyId?: string): string {
  if (!privateKeyId) return "—";
  const w = wallets.find((x) => x.id === privateKeyId);
  return w?.name ?? truncateMiddle(privateKeyId);
}

function DeleteButton({ label, onDelete }: { label: string; onDelete: () => Promise<void> }) {
  const [busy, setBusy] = useState(false);
  const run = async () => {
    if (busy) return;
    if (!window.confirm(`Delete this ${label}? This cannot be undone.`)) return;
    setBusy(true);
    await onDelete().finally(() => setBusy(false));
  };
  return (
    <button
      type="button"
      onClick={() => void run()}
      disabled={busy}
      aria-label={`Delete ${label}`}
      className="rounded p-1.5 text-mist transition-colors hover:text-danger disabled:opacity-45"
    >
      <Trash2 className="h-4 w-4" />
    </button>
  );
}

export function Policies() {
  const { selectedOrg } = useOrg();
  const orgId = selectedOrg?.id ?? "";
  const [actionError, setActionError] = useState<string | null>(null);

  const { data, loading, error, reload } = useAsync(async () => {
    const [policies, wallets, org] = await Promise.all([
      client.getPolicies(orgId),
      client.listWallets(orgId),
      client.getOrg(orgId),
    ]);
    return { policies, wallets, actors: org.actors };
  }, [orgId]);

  const runDelete = (fn: () => Promise<void>) => async () => {
    setActionError(null);
    try {
      await fn();
      reload();
    } catch (err: unknown) {
      setActionError(getErrorMessage(err));
    }
  };

  if (!selectedOrg) return null;

  return (
    <>
      <PageHeader
        title="Policies"
        description="Deterministic policy tables: actor bindings, per-chain wallet rules, and destination allowlists. A denial never reaches the signer."
      />

      {loading && <Loading />}
      {error && <ErrorNote message={error} />}
      {actionError && <ErrorNote message={actionError} className="mb-4" />}

      {data && (
        <div className="space-y-6">
          <Card title="Create policy">
            {data.wallets.length === 0 ? (
              <EmptyState title="No wallets yet">
                Create a wallet first — policies attach to a wallet's private key.
              </EmptyState>
            ) : (
              <CreatePolicyForm
                orgId={orgId}
                wallets={data.wallets}
                actors={data.actors}
                onCreated={reload}
              />
            )}
          </Card>

          <Card title={`Bindings · ${data.policies.bindings.length}`}>
            {data.policies.bindings.length === 0 ? (
              <EmptyState title="No bindings" />
            ) : (
              <Table>
                <THead columns={["Actor", "Resource", "Allowed activity", ""]} />
                <TBody>
                  {data.policies.bindings.map((b) => (
                    <Tr key={b.id}>
                      <Td mono>{b.actorId ? truncateMiddle(b.actorId) : "—"}</Td>
                      <Td mono>
                        {b.resourceType ?? "private_key"} · {walletLabel(data.wallets, b.resourceId)}
                      </Td>
                      <Td mono className="text-mist-2">
                        {b.allowedActivityType ?? "—"}
                      </Td>
                      <Td className="w-10 text-right">
                        <DeleteButton
                          label="binding"
                          onDelete={runDelete(() => client.deleteBinding(orgId, b.id))}
                        />
                      </Td>
                    </Tr>
                  ))}
                </TBody>
              </Table>
            )}
          </Card>

          <Card title={`Rules · ${data.policies.rules.length}`}>
            {data.policies.rules.length === 0 ? (
              <EmptyState title="No rules" />
            ) : (
              <Table>
                <THead columns={["Wallet", "Chain", "Selectors", "Max value (wei)", "Raw payload", ""]} />
                <TBody>
                  {data.policies.rules.map((r) => (
                    <Tr key={r.id}>
                      <Td>{walletLabel(data.wallets, r.privateKeyId)}</Td>
                      <Td mono>{r.chainId ?? "—"}</Td>
                      <Td mono>{r.methodSelectorAllowlist.join(", ") || "—"}</Td>
                      <Td mono>{r.maxNativeValueWei ?? "0"}</Td>
                      <Td>
                        <StatusBadge status={r.allowRawPayloadSigning ? "ALLOWED" : "DISABLED"} />
                      </Td>
                      <Td className="w-10 text-right">
                        <DeleteButton
                          label="rule"
                          onDelete={runDelete(() => client.deleteRule(orgId, r.id))}
                        />
                      </Td>
                    </Tr>
                  ))}
                </TBody>
              </Table>
            )}
          </Card>

          <Card title={`Destination allowlist · ${data.policies.destinations.length}`}>
            <div className="space-y-5">
              {data.wallets.length > 0 && (
                <AddDestinationForm orgId={orgId} wallets={data.wallets} onAdded={reload} />
              )}
              {data.policies.destinations.length === 0 ? (
                <EmptyState title="No allowlisted destinations" />
              ) : (
                <Table>
                  <THead columns={["Wallet", "Chain", "Address", ""]} />
                  <TBody>
                    {data.policies.destinations.map((d) => (
                      <Tr key={d.id}>
                        <Td>{walletLabel(data.wallets, d.privateKeyId)}</Td>
                        <Td mono>{d.chainId ?? "—"}</Td>
                        <Td mono>
                          <MonoCopy value={d.address} />
                        </Td>
                        <Td className="w-10 text-right">
                          <DeleteButton
                            label="destination"
                            onDelete={runDelete(() => client.deleteDestination(orgId, d.id))}
                          />
                        </Td>
                      </Tr>
                    ))}
                  </TBody>
                </Table>
              )}
            </div>
          </Card>
        </div>
      )}
    </>
  );
}
