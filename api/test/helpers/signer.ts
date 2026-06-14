import { execFileSync, spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import * as path from "node:path";
import * as net from "node:net";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** A random-hex 32-byte key usable as KMS_MASTER_KEY in tests. */
export const TEST_KMS_MASTER_KEY =
  "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

/** A well-known secp256k1 private key (test vector) + its expected address.
 *  priv = 0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b2
 *  address = 0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1  (Ganache account #0) */
export const TEST_IMPORT_PRIV_HEX =
  "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d";
export const TEST_IMPORT_ADDRESS =
  "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1";

/** Handle returned from startTestSigner. */
export interface TestSigner {
  baseUrl: string;
  stop: () => void;
}

/** Get a random free TCP port. */
async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address() as net.AddressInfo;
      srv.close((err) => (err ? reject(err) : resolve(addr.port)));
    });
  });
}

/** Poll /internal/health until it returns {"status":"ok"} or timeout. */
async function waitForHealth(baseUrl: string, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${baseUrl}/internal/health`);
      if (res.ok) {
        const body = (await res.json()) as { status?: string };
        if (body.status === "ok") return;
      }
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`Signer at ${baseUrl} did not become healthy within ${timeoutMs}ms`);
}

/** Build the signer binary once (cached in services/signer/.bin/signer).
 *  Returns the path to the binary. */
function buildSigner(): string {
  const signerDir = path.resolve(__dirname, "../../../", "signer");
  const binDir = path.join(signerDir, ".bin");
  const binPath = path.join(binDir, "signer");

  // Check if go is available.
  try {
    execFileSync("go", ["version"], { stdio: "ignore" });
  } catch {
    return "";
  }

  mkdirSync(binDir, { recursive: true });
  execFileSync("go", ["build", "-o", binPath, "./cmd/signer"], { cwd: signerDir, stdio: "pipe" });
  return binPath;
}

/** Start an isolated signer process on a random port for integration tests.
 *
 * Skips (returns null) when the Go toolchain is absent — callers should
 * check and call `it.skip()` / `describe.skip()` accordingly.
 *
 * @param allowImport — set ALLOW_KEY_IMPORT=true on the signer process.
 */
export async function startTestSigner(allowImport = false): Promise<TestSigner | null> {
  let binPath: string;
  try {
    binPath = buildSigner();
  } catch (err) {
    // Build failed — treat as skip.
    console.warn("[signer helper] go build failed:", err);
    return null;
  }

  if (!binPath) {
    console.warn("[signer helper] go is not installed — skipping signer integration tests");
    return null;
  }

  const port = await freePort();
  const baseUrl = `http://127.0.0.1:${port}`;

  const proc = spawn(binPath, [], {
    env: {
      ...process.env,
      SIGNER_ADDR: `:${port}`,
      KMS_MASTER_KEY: TEST_KMS_MASTER_KEY,
      ALLOW_KEY_IMPORT: allowImport ? "true" : "false",
    },
    stdio: "pipe",
  });

  proc.on("error", (err) => {
    console.error("[signer] process error:", err);
  });

  try {
    await waitForHealth(baseUrl);
  } catch (err) {
    proc.kill();
    throw err;
  }

  return {
    baseUrl,
    stop: () => {
      proc.kill();
    },
  };
}
