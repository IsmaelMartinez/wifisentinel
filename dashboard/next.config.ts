import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  transpilePackages: ["../src"],
  serverExternalPackages: ["zod"],
};

export default nextConfig;
