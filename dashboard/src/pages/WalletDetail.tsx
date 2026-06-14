import { Link, useParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { useOrg } from "@/context/OrgContext";
import { client } from "@/lib/client";
import { useAsync } from "@/lib/useAsync";
import { formatTime, truncateMiddle } from "@/lib/format";
import { PageHeader } from "@/components/PageHeader";
import { Card } from "@/components/ui/Card";
import { MonoCopy } from "@/components/ui/CopyButton";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { Table, THead, TBody, Tr, Td } from "@/components/ui/Table";
import { EmptyState, ErrorNote, Loading } from "@/components/ui/Feedback";

export function WalletDetail() {
  const { id = "" } = useParams();
  const { selectedOrg } = useOrg();
  const orgId = selectedOrg?.id ?? "";

  const { data, loading, error } = useAsync(async () => {
    const [wallets, policies] = await Promise.all([
      client.listWallets(orgId),
      client.getPolicies(orgId),
    ]);
    const wallet = wallets.find((w) => w.id === id) ?? null;
    return {
      wallet,
      rules: policies.rules.filter((r) => r.privateKeyId === id),
      destinations: policies.destinations.filter((d) => d.privateKeyId === id),
    };
  }, [orgId, id]);

  if (!selectedOrg) return null;

  return (
    <>
      <Link
        to="/wallets"
        className="mb-4 inline-flex items-center gap-1.5 text-sm text-mist transition-colors hover:text-signal"
      >
        <ArrowLeft className="h-4 w-4" /> Wallets
      </Link>

      {loading && <Loading />}
      {error && <ErrorNote message={error} />}
      {data && !data.wallet && <ErrorNote message={`Wallet ${id} not found in this organization.`} />}

      {data?.wallet && (
        <>
          <PageHeader
            title={data.wallet.name ?? truncateMiddle(data.wallet.id)}
            description={`Created ${formatTime(data.wallet.createdAt)}`}
          />

          <div className="space-y-6">
            <Card title="Key material (public)">
              <dl className="space-y-3 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <dt className="eyebrow w-36 shrink-0 text-mist">Private key id</dt>
                  <dd>
                    <MonoCopy value={data.wallet.id} />
                  </dd>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <dt className="eyebrow w-36 shrink-0 text-mist">Curve</dt>
                  <dd className="font-mono text-xs text-paper/85">
                    {data.wallet.curve ?? "CURVE_SECP256K1"}
                  </dd>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <dt className="eyebrow w-36 shrink-0 text-mist">Public key</dt>
                  <dd className="min-w-0">
                    {data.wallet.publicKey ? <MonoCopy value={data.wallet.publicKey} /> : "—"}
                  </dd>
                </div>
                {data.wallet.addresses.map((addr) => (
                  <div key={addr} className="flex flex-wrap items-center gap-2">
                    <dt className="eyebrow w-36 shrink-0 text-mist">Address</dt>
                    <dd>
                      <MonoCopy value={addr} />
                    </dd>
                  </div>
                ))}
              </dl>
            </Card>

            <Card title="Policy rules">
              {data.rules.length === 0 ? (
                <EmptyState title="No rules for this wallet">
                  Seed one from the <Link to="/policies" className="text-signal hover:underline">Policies</Link> page.
                </EmptyState>
              ) : (
                <Table>
                  <THead columns={["Chain", "Selectors", "Max value (wei)", "Raw payload"]} />
                  <TBody>
                    {data.rules.map((r) => (
                      <Tr key={r.id}>
                        <Td mono>{r.chainId ?? "—"}</Td>
                        <Td mono>{r.methodSelectorAllowlist.join(", ") || "—"}</Td>
                        <Td mono>{r.maxNativeValueWei ?? "0"}</Td>
                        <Td>
                          <StatusBadge status={r.allowRawPayloadSigning ? "ALLOWED" : "DISABLED"} />
                        </Td>
                      </Tr>
                    ))}
                  </TBody>
                </Table>
              )}
            </Card>

            <Card title="Destination allowlist">
              {data.destinations.length === 0 ? (
                <EmptyState title="No allowlisted destinations">
                  Transactions to any address will be denied until you allowlist destinations.
                </EmptyState>
              ) : (
                <Table>
                  <THead columns={["Chain", "Address"]} />
                  <TBody>
                    {data.destinations.map((d) => (
                      <Tr key={d.id}>
                        <Td mono>{d.chainId ?? "—"}</Td>
                        <Td mono>
                          <MonoCopy value={d.address} />
                        </Td>
                      </Tr>
                    ))}
                  </TBody>
                </Table>
              )}
            </Card>
          </div>
        </>
      )}
    </>
  );
}
