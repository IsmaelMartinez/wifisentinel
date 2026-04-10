import type { NextConfig } from "next";
import path from "path";

const nextConfig: NextConfig = {
  transpilePackages: ["../src"],
  serverExternalPackages: ["zod"],
  turbopack: {
    resolveAlias: {
      "@wifisentinel": path.resolve(process.cwd(), "../src"),
    },
  },
  webpack: (config) => {
    config.resolve.alias["@wifisentinel"] = path.resolve(process.cwd(), "../src");
    config.resolve.extensionAlias = {
      ...config.resolve.extensionAlias,
      ".js": [".ts", ".tsx", ".js", ".jsx"],
    };
    return config;
  },
};

export default nextConfig;
