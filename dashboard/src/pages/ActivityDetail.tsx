import { Link, useParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { useOrg } from "@/context/OrgContext";
import { client } from "@/lib/client";
import { useAsync } from "@/lib/useAsync";
import { formatActivityType, formatTime } from "@/lib/format";
import { PageHeader } from "@/components/PageHeader";
import { Card } from "@/components/ui/Card";
import { JsonViewer } from "@/components/ui/JsonViewer";
import { MonoCopy } from "@/components/ui/CopyButton";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { ErrorNote, Loading } from "@/components/ui/Feedback";

export function ActivityDetail() {
  const { id = "" } = useParams();
  const { selectedOrg } = useOrg();
  const orgId = selectedOrg?.id ?? "";

  const { data: activity, loading, error } = useAsync(
    () => client.getActivity(orgId, id),
    [orgId, id],
  );

  if (!selectedOrg) return null;

  return (
    <>
      <Link
        to="/activities"
        className="mb-4 inline-flex items-center gap-1.5 text-sm text-mist transition-colors hover:text-signal"
      >
        <ArrowLeft className="h-4 w-4" /> Activities
      </Link>

      {loading && <Loading />}
      {error && <ErrorNote message={error} />}

      {activity && (
        <>
          <PageHeader
            title={formatActivityType(activity.type)}
            description={`Created ${formatTime(activity.createdAt)}`}
            actions={<StatusBadge status={activity.status} />}
          />

          <div className="space-y-6">
            <Card title="Activity">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="eyebrow w-28 shrink-0 text-mist">Activity id</span>
                <MonoCopy value={activity.id} />
              </div>
            </Card>

            {activity.policyDecision != null && (
              <Card title="Policy decision">
                <div className="mb-4 flex flex-wrap items-center gap-4">
                  {typeof activity.policyDecision.outcome === "string" && (
                    <StatusBadge status={activity.policyDecision.outcome} />
                  )}
                  {typeof activity.policyDecision.reasonCode === "string" && (
                    <span className="font-mono text-xs text-paper/85">
                      {activity.policyDecision.reasonCode}
                    </span>
                  )}
                </div>
                <JsonViewer value={activity.policyDecision} maxHeight="16rem" />
              </Card>
            )}

            {activity.intent != null && (
              <Card title="Intent">
                <JsonViewer value={activity.intent} />
              </Card>
            )}

            {activity.result != null && (
              <Card title="Result">
                <JsonViewer value={activity.result} />
              </Card>
            )}

            {activity.failure != null && (
              <Card title="Failure">
                <JsonViewer value={activity.failure} maxHeight="16rem" />
              </Card>
            )}

            {activity.signerReceipt != null && (
              <Card title="Signer receipt">
                <JsonViewer value={activity.signerReceipt} maxHeight="16rem" />
              </Card>
            )}

            <Card title="Raw record">
              <JsonViewer value={activity.raw} />
            </Card>
          </div>
        </>
      )}
    </>
  );
}
