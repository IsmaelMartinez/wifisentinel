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
    // The dashboard reuses sources from ../src that import packages like `zod`.
    // Webpack's default resolution walks up from the file's directory, which
    // never reaches dashboard/node_modules. Prepend the absolute path so those
    // imports resolve against the dashboard's installed dependencies, while
    // also keeping the relative "node_modules" entry to preserve webpack's
    // standard upward traversal for everything else.
    const existingModules = config.resolve.modules ?? [];
    config.resolve.modules = [
      path.resolve(process.cwd(), "node_modules"),
      ...existingModules,
      ...(existingModules.includes("node_modules") ? [] : ["node_modules"]),
    ];
    return config;
  },
};

export default nextConfig;
