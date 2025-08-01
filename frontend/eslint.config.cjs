const js = require('@eslint/js');
const globals = require('globals');
const reactHooks = require('eslint-plugin-react-hooks');
const reactRefresh = require('eslint-plugin-react-refresh');
const tseslint = require('typescript-eslint');
const { globalIgnores } = require('eslint/config');

module.exports = tseslint.config([
  globalIgnores(['dist', 'node_modules', 'src/components/ui']),

  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs['recommended-latest'],
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
    rules: {
      'react-refresh/only-export-components': 'off',

      // ← We can drop in any other rules,
      //    e.g. to globally mute unused-vars in ui components:
      // 'no-unused-vars': ['error', { varsIgnorePattern: '^cva' }],
    },
  },
]);
