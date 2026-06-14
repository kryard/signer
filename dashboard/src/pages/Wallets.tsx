import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Plus } from "lucide-react";
import { useOrg } from "@/context/OrgContext";
import { client } from "@/lib/client";
import { useAsync } from "@/lib/useAsync";
import { formatTime, getErrorMessage, truncateMiddle } from "@/lib/format";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Field } from "@/components/ui/Field";
import { Modal } from "@/components/ui/Modal";
import { MonoCopy } from "@/components/ui/CopyButton";
import { Table, THead, TBody, Tr, Td } from "@/components/ui/Table";
import { EmptyState, ErrorNote, Loading } from "@/components/ui/Feedback";

export function Wallets() {
  const { selectedOrg } = useOrg();
  const navigate = useNavigate();
  const orgId = selectedOrg?.id ?? "";

  const { data: wallets, loading, error, reload } = useAsync(
    () => client.listWallets(orgId),
    [orgId],
  );

  const [modalOpen, setModalOpen] = useState(false);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const create = async () => {
    if (busy) return;
    setBusy(true);
    setCreateError(null);
    try {
      await client.createWallet(orgId, name.trim() || undefined);
      setModalOpen(false);
      setName("");
      reload();
    } catch (err: unknown) {
      setCreateError(getErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  if (!selectedOrg) return null;

  return (
    <>
      <PageHeader
        title="Wallets"
        description="Keys are generated inside the isolated signer and stored KMS-encrypted — the console only ever sees public material."
        actions={
          <Button onClick={() => setModalOpen(true)}>
            <Plus className="h-4 w-4" /> Create wallet
          </Button>
        }
      />

      {loading && <Loading />}
      {error && <ErrorNote message={error} />}

      {wallets && (
        <Card>
          {wallets.length === 0 ? (
            <EmptyState title="No wallets yet">
              Create your first wallet — the private key is generated inside the signer.
            </EmptyState>
          ) : (
            <Table>
              <THead columns={["Name", "Address", "Curve", "Created"]} />
              <TBody>
                {wallets.map((w) => (
                  <Tr key={w.id} onClick={() => navigate(`/wallets/${w.id}`)}>
                    <Td>{w.name ?? "—"}</Td>
                    <Td mono>
                      {w.addresses[0] ? (
                        <span onClick={(e) => e.stopPropagation()}>
                          <MonoCopy
                            value={w.addresses[0]}
                            display={truncateMiddle(w.addresses[0], 10, 8)}
                          />
                        </span>
                      ) : (
                        "—"
                      )}
                    </Td>
                    <Td mono className="text-mist-2">
                      {w.curve ?? "CURVE_SECP256K1"}
                    </Td>
                    <Td className="text-mist-2">{formatTime(w.createdAt)}</Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          )}
        </Card>
      )}

      <Modal open={modalOpen} title="Create wallet" onClose={() => setModalOpen(false)}>
        <div className="space-y-4">
          <p className="text-sm text-mist-2">
            A new secp256k1 key is generated inside the signer VM and envelope-encrypted with
            KMS. You will get back the Ethereum address and public key only.
          </p>
          <Field label="Name (optional)" value={name} onChange={setName} placeholder="treasury-1" />
          {createError && <ErrorNote message={createError} />}
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setModalOpen(false)}>
              Cancel
            </Button>
            <Button onClick={() => void create()} disabled={busy}>
              {busy ? "Creating…" : "Create wallet"}
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
}
