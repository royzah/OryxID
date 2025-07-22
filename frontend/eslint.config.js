import globals from "globals";
import tseslint from "typescript-eslint";
import pluginReact from "eslint-plugin-react";
import hooksPlugin from "eslint-plugin-react-hooks";
import refreshPlugin from "eslint-plugin-react-refresh";

export default [
  // Global ignore pattern
  {
    ignores: ["dist/**"],
  },

  // Base configuration for all relevant files
  {
    files: ["src/**/*.{js,jsx,ts,tsx}"],
    plugins: {
      react: pluginReact,
      "react-hooks": hooksPlugin,
      "react-refresh": refreshPlugin,
    },
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.es2020,
      },
      parser: tseslint.parser,
      parserOptions: {
        ecmaFeatures: { jsx: true },
      },
    },
    rules: {
      // Base rules from plugins
      ...pluginReact.configs.recommended.rules,
      ...hooksPlugin.configs.recommended.rules,

      // Turn off rules that are no longer necessary with modern React/Vite
      "react/react-in-jsx-scope": "off",
      "react/jsx-uses-react": "off",

      // Rule for Vite's Fast Refresh
      "react-refresh/only-export-components": "warn",
    },
  },

  // Apply TypeScript-specific rules
  ...tseslint.configs.recommended,
];
