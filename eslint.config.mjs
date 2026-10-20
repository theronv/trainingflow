import { readdirSync, readFileSync } from 'node:fs'
import js from '@eslint/js'
import globals from 'globals'
import html from '@html-eslint/eslint-plugin'
import htmlParser from '@html-eslint/parser'

// The frontend is plain <script> files that share top-level names, so every
// top-level declaration in js/ counts as a global for no-undef.
const appGlobals = {}
for (const file of readdirSync('js').filter((f) => f.endsWith('.js'))) {
  const src = readFileSync(`js/${file}`, 'utf8')
  for (const m of src.matchAll(/^(?:async\s+)?(?:const|let|var|function|class)\s+([A-Za-z_$][\w$]*)/gm)) {
    appGlobals[m[1]] = 'writable'
  }
}

export default [
  { ignores: ['node_modules/**', 'worker/node_modules/**', 'worker/.wrangler/**', 'docs/**', 'assets/**', 'content/**'] },
  {
    files: ['js/**/*.js'],
    ...js.configs.recommended,
    languageOptions: {
      sourceType: 'script',
      globals: { ...globals.browser, ...appGlobals, html2canvas: 'readonly', jspdf: 'readonly', confetti: 'readonly', marked: 'readonly', Clerk: 'readonly' },
    },
    rules: {
      ...js.configs.recommended.rules,
      'no-unused-vars': 'off',
      'no-console': ['error', { allow: ['warn', 'error'] }],
      'no-empty': ['error', { allowEmptyCatch: true }],
      'no-redeclare': ['error', { builtinGlobals: false }],
    },
  },
  {
    files: ['worker/**/*.js', 'worker/**/*.mjs', 'scripts/**/*.mjs', '*.mjs'],
    ...js.configs.recommended,
    languageOptions: { sourceType: 'module', globals: { ...globals.node, ...globals.serviceworker } },
    rules: { ...js.configs.recommended.rules, 'no-empty': ['error', { allowEmptyCatch: true }], 'no-unused-vars': ['error', { argsIgnorePattern: '^_', caughtErrors: 'none' }] },
  },
  {
    files: ['index.html'],
    plugins: { '@html-eslint': html },
    languageOptions: { parser: htmlParser },
    rules: {
      '@html-eslint/require-img-alt': 'error',
      '@html-eslint/no-duplicate-id': 'error',
      '@html-eslint/require-button-type': 'error',
      '@html-eslint/require-lang': 'error',
      '@html-eslint/require-title': 'error',
      '@html-eslint/no-duplicate-attrs': 'error',
      '@html-eslint/require-meta-viewport': 'error',
    },
  },
]
