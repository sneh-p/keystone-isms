// Web app lint rules, including the secure coding standard (.knowledge/secure-coding/).
// Protected file (SC-AGT-002): changes need AppSec review.
import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import react from "eslint-plugin-react";
import security from "eslint-plugin-security";
import noUnsanitized from "eslint-plugin-no-unsanitized";
import comments from "@eslint-community/eslint-plugin-eslint-comments/configs";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "node_modules"] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended, security.configs.recommended, noUnsanitized.configs.recommended, comments.recommended],
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
      // Type information for the promise and implied-eval rules below.
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    linterOptions: { reportUnusedDisableDirectives: "error" },
    plugins: { "react-hooks": reactHooks, react },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // The browser is not a trust boundary in this app: the API validates every input with Pydantic
      // (SC-VAL-001), so API responses are typed loosely here. no-unsafe-* is therefore not enabled.
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_", destructuredArrayIgnorePattern: "^_" }],

      // SC-INJ-004: no dynamic code execution
      "no-eval": "error",
      "no-new-func": "error",
      "no-implied-eval": "off",
      "@typescript-eslint/no-implied-eval": "error",
      // SC-XSS-001: no raw HTML sinks
      "react/no-danger": "error",
      "react/jsx-no-target-blank": "error",
      // SC-ERR-003: no floating or misused promises
      "@typescript-eslint/no-floating-promises": ["error", { ignoreVoid: true }],
      "@typescript-eslint/no-misused-promises": ["error", { checksVoidReturn: { attributes: false } }],
      // SC-CRY-002: cryptographic randomness only
      "no-restricted-properties": ["error", { object: "Math", property: "random", message: "SC-CRY-002: use crypto.getRandomValues() or crypto.randomUUID()." }],
      // SC-AGT-001: every suppression must be scoped and explained
      "@typescript-eslint/ban-ts-comment": ["error", { "ts-ignore": true, "ts-nocheck": true, "ts-expect-error": "allow-with-description" }],
      "@eslint-community/eslint-comments/require-description": "error",
      "@eslint-community/eslint-comments/no-unlimited-disable": "error",
      // Very noisy on typed object access; noise trains people and agents to suppress. Validation and
      // authorization on the server cover the real risk.
      "security/detect-object-injection": "off",
    },
  },
  {
    // Vitest files run in Node, not the browser bundle.
    files: ["src/**/*.test.ts"],
    languageOptions: { globals: globals.node },
  },
);
