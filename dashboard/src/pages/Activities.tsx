import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useOrg } from "@/context/OrgContext";
import { client } from "@/lib/client";
import type { ActivitySummary } from "@/lib/types";
import { formatActivityType, formatTime, getErrorMessage, truncateMiddle } from "@/lib/format";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { Table, THead, TBody, Tr, Td } from "@/components/ui/Table";
import { EmptyState, ErrorNote, Loading } from "@/components/ui/Feedback";

const PAGE_LIMIT = 50;

export function Activities() {
  const { selectedOrg } = useOrg();
  const navigate = useNavigate();
  const orgId = selectedOrg?.id ?? "";

  const [items, setItems] = useState<ActivitySummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // A short page means the source is exhausted — hide "Load more".
  const [exhausted, setExhausted] = useState(false);

  const loadFirstPage = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const page = await client.listActivities(orgId, PAGE_LIMIT);
      setItems(page);
      setExhausted(page.length < PAGE_LIMIT);
    } catch (err: unknown) {
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }, [orgId]);

  useEffect(() => {
    void loadFirstPage();
  }, [loadFirstPage]);

  const loadMore = async () => {
    const cursor = items[items.length - 1]?.createdAt;
    if (!cursor || loadingMore) return;
    setLoadingMore(true);
    setError(null);
    try {
      const page = await client.listActivities(orgId, PAGE_LIMIT, cursor);
      setItems((prev) => [...prev, ...page]);
      setExhausted(page.length < PAGE_LIMIT);
    } catch (err: unknown) {
      setError(getErrorMessage(err));
    } finally {
      setLoadingMore(false);
    }
  };

  if (!selectedOrg) return null;

  return (
    <>
      <PageHeader
        title="Activities"
        description="Every sensitive operation is an immutable activity — the unit of work, idempotency, and audit."
      />

      {loading && <Loading />}
      {error && <ErrorNote message={error} />}

      {!loading && (
        <Card title={`Activities (${items.length}${exhausted ? "" : "+"})`}>
          {items.length === 0 ? (
            <EmptyState title="No activities yet">
              Submit a signing request from the Sign playground to create one.
            </EmptyState>
          ) : (
            <>
              <Table>
                <THead columns={["Type", "Status", "Activity", "Time"]} />
                <TBody>
                  {items.map((a) => (
                    <Tr key={a.id} onClick={() => navigate(`/activities/${a.id}`)}>
                      <Td>{formatActivityType(a.type)}</Td>
                      <Td>
                        <StatusBadge status={a.status} />
                      </Td>
                      <Td mono className="text-signal">
                        {truncateMiddle(a.id)}
                      </Td>
                      <Td className="text-mist-2">{formatTime(a.createdAt)}</Td>
                    </Tr>
                  ))}
                </TBody>
              </Table>
              {!exhausted && (
                <div className="mt-4 flex justify-center">
                  <Button variant="ghost" size="sm" onClick={() => void loadMore()} disabled={loadingMore}>
                    {loadingMore ? "Loading…" : "Load more"}
                  </Button>
                </div>
              )}
            </>
          )}
        </Card>
      )}
    </>
  );
}
