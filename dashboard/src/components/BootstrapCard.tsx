import { useState } from "react";
import { motion } from "framer-motion";
import { useOrg } from "@/context/OrgContext";
import { getErrorMessage } from "@/lib/format";
import { LogoMark } from "./LogoMark";
import { Button } from "./ui/Button";
import { Field } from "./ui/Field";
import { ErrorNote } from "./ui/Feedback";

/** Friendly first-run state: no organizations exist yet. */
export function BootstrapCard() {
  const { createOrg } = useOrg();
  const [name, setName] = useState("my-org");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    if (!name.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      await createOrg(name.trim());
    } catch (err: unknown) {
      setError(getErrorMessage(err));
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-[70vh] items-center justify-center">
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
        className="w-full max-w-md rounded-2xl border border-line bg-ink-2 p-8 text-center"
      >
        <div className="mx-auto mb-5 flex h-14 w-14 items-center justify-center rounded-2xl border border-line bg-ink">
          <LogoMark tone="paper" className="h-8 w-8" />
        </div>
        <h1 className="font-display text-2xl font-semibold text-paper">
          Welcome to Kryard
        </h1>
        <p className="mt-2 text-sm text-mist-2">
          Create your first organization to start managing wallets, policies,
          and signing activity.
        </p>
        <div className="mt-6 space-y-3 text-left">
          <Field label="Organization name" value={name} onChange={setName} />
          {error && <ErrorNote message={error} />}
          <Button className="w-full" onClick={() => void submit()} disabled={busy || !name.trim()}>
            {busy ? "Creating…" : "Create organization"}
          </Button>
        </div>
      </motion.div>
    </div>
  );
}
