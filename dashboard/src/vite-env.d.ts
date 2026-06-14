/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** When "true", run in zero-auth localhost mode (talk directly to VITE_API_BASE). */
  readonly VITE_LOCAL?: string;
  /** Base URL of the local Kryard API in local mode. Default http://localhost:8787. */
  readonly VITE_API_BASE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
