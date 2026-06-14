import { useState } from "react";
import { useOrg } from "@/context/OrgContext";
import { client } from "@/lib/client";
import { useAsync } from "@/lib/useAsync";
import { formatTime, getErrorMessage, truncateMiddle } from "@/lib/format";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { MonoCopy } from "@/components/ui/CopyButton";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { Table, THead, TBody, Tr, Td } from "@/components/ui/Table";
import { EmptyState, ErrorNote, Loading } from "@/components/ui/Feedback";
import { RegisterKeyForm } from "@/components/keys/RegisterKeyForm";

export function Keys() {
  const { selectedOrg } = useOrg();
  const orgId = selectedOrg?.id ?? "";
  const [actionError, setActionError] = useState<string | null>(null);
  const [disabling, setDisabling] = useState<string | null>(null);

  const { data: org, loading, error, reload } = useAsync(() => client.getOrg(orgId), [orgId]);

  const disable = async (apiKeyId: string) => {
    if (disabling) return;
    if (!window.confirm("Disable this API key? Stamps signed with it will stop verifying.")) return;
    setDisabling(apiKeyId);
    setActionError(null);
    try {
      await client.disableApiKey(orgId, apiKeyId);
      reload();
    } catch (err: unknown) {
      setActionError(getErrorMessage(err));
    } finally {
      setDisabling(null);
    }
  };

  if (!selectedOrg) return null;

  return (
    <>
      <PageHeader
        title="API keys"
        description="P-256 stamp public keys. Every request to the public API is X-Stamp signed by one of these — Kryard never holds the private half."
      />

      {loading && <Loading />}
      {error && <ErrorNote message={error} />}
      {actionError && <ErrorNote message={actionError} className="mb-4" />}

      {org && (
        <div className="space-y-6">
          <Card title="Register a key">
            <RegisterKeyForm orgId={orgId} actors={org.actors} onRegistered={reload} />
          </Card>

          <Card title={`Keys · ${org.apiKeys.length}`}>
            {org.apiKeys.length === 0 ? (
              <EmptyState title="No API keys yet">
                Register a stamp public key above to call the public API.
              </EmptyState>
            ) : (
              <Table>
                <THead columns={["Name", "Public key", "Scheme", "Status", "Created", ""]} />
                <TBody>
                  {org.apiKeys.map((k) => (
                    <Tr key={k.id}>
                      <Td>{k.name ?? "—"}</Td>
                      <Td mono>
                        <MonoCopy value={k.publicKey} display={truncateMiddle(k.publicKey, 10, 8)} />
                      </Td>
                      <Td mono className="text-mist-2">
                        {k.scheme}
                      </Td>
                      <Td>
                        <StatusBadge status={k.disabled ? "DISABLED" : "ACTIVE"} />
                      </Td>
                      <Td className="text-mist-2">{formatTime(k.createdAt)}</Td>
                      <Td className="w-24 text-right">
                        {!k.disabled && (
                          <Button
                            size="sm"
                            variant="danger"
                            onClick={() => void disable(k.id)}
                            disabled={disabling === k.id}
                          >
                            {disabling === k.id ? "…" : "Disable"}
                          </Button>
                        )}
                      </Td>
                    </Tr>
                  ))}
                </TBody>
              </Table>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
