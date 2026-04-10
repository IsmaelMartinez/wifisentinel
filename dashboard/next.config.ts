import type { NextConfig } from "next";
import path from "path";

const src = path.resolve(process.cwd(), "../src");

const nextConfig: NextConfig = {
  transpilePackages: ["../src"],
  serverExternalPackages: ["zod"],
  // Turbopack (default in Next.js 16) does not support extensionAlias.
  // Map each @wifisentinel/*.js import to the real .ts source file using
  // relative paths from the dashboard directory (where Next.js runs from).
  turbopack: {
    resolveAlias: {
      "@wifisentinel/analyser/rf/index.js": "../src/analyser/rf/index.ts",
      "@wifisentinel/analyser/score.js": "../src/analyser/score.ts",
      "@wifisentinel/reporter/html.reporter.js": "../src/reporter/html.reporter.ts",
      "@wifisentinel/store/index.js": "../src/store/index.ts",
    },
  },
  webpack: (config) => {
    config.resolve.alias["@wifisentinel"] = src;
    config.resolve.extensionAlias = {
      ...config.resolve.extensionAlias,
      ".js": [".ts", ".tsx", ".js", ".jsx"],
    };
    return config;
  },
};

export default nextConfig;
