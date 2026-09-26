// typescript-eslint needs TypeScript's JS compiler API, which TypeScript 7
// (the dashboard's compiler) no longer ships. ESLint and its plugins therefore
// resolve from the repo-root install (TypeScript 6): run `npm ci` at the root
// before `npm run lint` here.
import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    ignores: [".next/", "node_modules/", "next-env.d.ts"],
  },
  {
    rules: {
      "@typescript-eslint/no-unused-vars": ["warn", { argsIgnorePattern: "^_" }],
    },
  },
);
