import type { NextConfig } from "next";
import path from "path";

const wifisentinelSrc = path.resolve(process.cwd(), "../src");

const nextConfig: NextConfig = {
  transpilePackages: ["../src"],
  serverExternalPackages: ["zod"],
  // Silence the "multiple lockfiles detected" warning by anchoring tracing
  // to this dashboard directory rather than the repo root.
  outputFileTracingRoot: process.cwd(),
  // We re-use the CLI's ESM sources from ../src, which import each other with
  // explicit `.js` extensions (TypeScript ESM convention). Turbopack's resolver
  // doesn't yet implement webpack's `extensionAlias` (.js → .ts/.tsx), so we
  // stay on the webpack builder and configure both the alias and the extension
  // remap here. Build with `next build --webpack` (the dev command can opt in
  // to Turbopack independently if desired).
  webpack: (config) => {
    config.resolve.alias["@wifisentinel"] = wifisentinelSrc;
    config.resolve.extensionAlias = {
      ...config.resolve.extensionAlias,
      ".js": [".ts", ".tsx", ".js", ".jsx"],
    };
    return config;
  },
};

export default nextConfig;
