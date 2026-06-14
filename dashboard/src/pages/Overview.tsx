import { Link } from "react-router-dom";
import { useOrg } from "@/context/OrgContext";
import { client } from "@/lib/client";
import { useAsync } from "@/lib/useAsync";
import { formatActivityType, formatTime, truncateMiddle } from "@/lib/format";
import { PageHeader } from "@/components/PageHeader";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { Table, THead, TBody, Tr, Td } from "@/components/ui/Table";
import { EmptyState, ErrorNote, Loading } from "@/components/ui/Feedback";

function StatCard({ label, value, to }: { label: string; value: number; to: string }) {
  return (
    <Link
      to={to}
      className="block rounded-xl border border-line bg-ink-2 p-5 transition-colors hover:border-signal/50"
    >
      <p className="eyebrow text-mist">{label}</p>
      <p className="mt-2 font-display text-3xl font-semibold text-paper">{value}</p>
    </Link>
  );
}

export function Overview() {
  const { selectedOrg } = useOrg();
  const orgId = selectedOrg?.id ?? "";

  const { data, loading, error } = useAsync(async () => {
    const [wallets, activities, org] = await Promise.all([
      client.listWallets(orgId),
      client.listActivities(orgId, 50),
      client.getOrg(orgId),
    ]);
    return { wallets, activities, org };
  }, [orgId]);

  if (!selectedOrg) return null;

  return (
    <>
      <PageHeader
        title="Overview"
        description={`Organization ${selectedOrg.name} · ${truncateMiddle(selectedOrg.id)}`}
      />

      {loading && <Loading />}
      {error && <ErrorNote message={error} />}

      {data && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <StatCard label="Wallets" value={data.wallets.length} to="/wallets" />
            <StatCard label="Activities" value={data.activities.length} to="/activities" />
            <StatCard label="API keys" value={data.org.apiKeys.length} to="/keys" />
          </div>

          <Card title="Recent activity">
            {data.activities.length === 0 ? (
              <EmptyState title="No activity yet">
                Submit a signing request from the{" "}
                <Link to="/sign" className="text-signal hover:underline">
                  Sign playground
                </Link>{" "}
                to see it here.
              </EmptyState>
            ) : (
              <Table>
                <THead columns={["Type", "Status", "Activity", "Time"]} />
                <TBody>
                  {data.activities.slice(0, 8).map((a) => (
                    <Tr key={a.id}>
                      <Td>{formatActivityType(a.type)}</Td>
                      <Td>
                        <StatusBadge status={a.status} />
                      </Td>
                      <Td mono>
                        <Link to={`/activities/${a.id}`} className="text-signal hover:underline">
                          {truncateMiddle(a.id)}
                        </Link>
                      </Td>
                      <Td className="text-mist-2">{formatTime(a.createdAt)}</Td>
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
