import { createRequire } from "node:module";

// Resolves to the repo-root package.json from both src/telemetry (tsx) and dist/telemetry (compiled).
const pkg = createRequire(import.meta.url)("../../package.json") as { version: string };

export const SERVICE_NAME = "wifisentinel";
export const SERVICE_VERSION = pkg.version;
