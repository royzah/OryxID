import path from 'path';
import { fileURLToPath } from 'url';
import js from '@eslint/js';
import globals from 'globals';
import parser from '@typescript-eslint/parser';
import deprecation from 'eslint-plugin-deprecation';
import tseslint from '@typescript-eslint/eslint-plugin';
import { fixupPluginRules } from '@eslint/compat';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default [
  // 1. ESLint core recommended rules
  js.configs.recommended,

  // 2. Ignore build outputs & generated UI components
  {
    ignores: [
      'dist/**',
      'build/**',
      'node_modules/**',
      'src/components/ui/**',
      '*.min.js',
      '*.min.css',
      'vite.config.ts',
      'tailwind.config.js',
      'postcss.config.cjs',
      'src/vite-env.d.ts',
    ],
  },

  // 3. TS/TSX override: set parser + globals
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      parser,
      parserOptions: {
        project: ['./tsconfig.app.json', './tsconfig.node.json'],
        tsconfigRootDir: __dirname,
        ecmaVersion: 2020,
        sourceType: 'module',
        ecmaFeatures: { jsx: true },
      },
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
    // 4. Register plugins
    plugins: {
      '@typescript-eslint': tseslint,
      deprecation: fixupPluginRules(deprecation),
    },
    // 5. Rules configuration
    rules: {
      // Disable base rule and use TypeScript-aware version
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          args: 'all',
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],

      // Deprecation warnings
      'deprecation/deprecation': 'warn',
    },
  },
];
