import type { NextConfig } from "next";
import path from "path";

const src = path.resolve(process.cwd(), "../src");

const nextConfig: NextConfig = {
  transpilePackages: ["../src"],
  serverExternalPackages: ["zod"],
  // Turbopack (default in Next.js 16) does not support extensionAlias, so we
  // map each @wifisentinel/*.js import to the real .ts source file explicitly.
  turbopack: {
    resolveAlias: {
      "@wifisentinel/analyser/rf/index.js": path.join(src, "analyser/rf/index.ts"),
      "@wifisentinel/analyser/score.js": path.join(src, "analyser/score.ts"),
      "@wifisentinel/reporter/html.reporter.js": path.join(src, "reporter/html.reporter.ts"),
      "@wifisentinel/store/index.js": path.join(src, "store/index.ts"),
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
