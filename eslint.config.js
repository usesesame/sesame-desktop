import js from '@eslint/js'
import globals from 'globals'
import svelte from 'eslint-plugin-svelte'
import svelteParser from 'svelte-eslint-parser'
import tseslint from 'typescript-eslint'

const noConsole = {
  'no-console': 'error',
}

// Surfaces are separate products with different trust boundaries and deployment targets; they must not share code across directories.
const crossSurfaceImports = (surfaces) => ({
  'no-restricted-imports': [
    'error',
    {
      patterns: surfaces.map((surface) => ({
        regex: `^(\\.\\./)+${surface}/`,
        message: `Do not import ${surface}/ from another surface.`,
      })),
    },
  ],
})

// Sesame renders user-controlled strings: entry titles, folder names, imported site names, and support text.
const noHtmlSinks = {
  'no-restricted-syntax': [
    'error',
    {
      selector: "MemberExpression[property.name='innerHTML']",
      message: 'Assign textContent instead. Vault fields are user-controlled strings.',
    },
    {
      selector: "MemberExpression[property.name='outerHTML']",
      message: 'Assign textContent instead. Vault fields are user-controlled strings.',
    },
    {
      selector: "MemberExpression[property.name='insertAdjacentHTML']",
      message: 'Build nodes instead. Vault fields are user-controlled strings.',
    },
    {
      selector: "CallExpression[callee.object.name='document'][callee.property.name='write']",
      message: 'document.write is not used in this codebase.',
    },
    {
      selector: "NewExpression[callee.name='Function']",
      message: 'No runtime code construction. It defeats the content security policy.',
    },
  ],
  'no-eval': 'error',
  'no-implied-eval': 'error',
}

const typeAwareRules = {
  ...noConsole,
  ...noHtmlSinks,
  '@typescript-eslint/no-explicit-any': 'error',
  '@typescript-eslint/no-floating-promises': 'error',
  '@typescript-eslint/no-misused-promises': 'error',
  '@typescript-eslint/await-thenable': 'error',
  '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
}

export default tseslint.config(
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/dist-ssr/**',
      '**/build/**',
      '**/target/**',
      '**/test-results/**',
      '**/.ssr/**',
      '.gocache/**',
      'isolated-target/**',
      '.phase4-target/**',
      'src-tauri/**',
      'backend/**',
      'extensions/sesame/**',
      'public/**',
      'website/public/**',
      'admin/public/**',
      'assets/**',
      'release-artifacts/**',
      'release-evidence/**',
    ],
  },

  js.configs.recommended,

  {
    rules: {
      'prefer-const': ['error', { ignoreReadBeforeAssign: true }],
      'no-useless-assignment': 'off',
    },
  },

  {
    files: ['src/**/*.ts'],
    extends: [tseslint.configs.recommended],
    languageOptions: {
      parserOptions: { project: ['./tsconfig.app.json'], tsconfigRootDir: import.meta.dirname },
      globals: globals.browser,
    },
    rules: {
      ...typeAwareRules,
      ...crossSurfaceImports(['website', 'admin', 'extensions', 'backend']),
    },
  },

  {
    files: ['website/src/**/*.ts'],
    extends: [tseslint.configs.recommended],
    languageOptions: {
      parserOptions: { project: ['./website/tsconfig.json'], tsconfigRootDir: import.meta.dirname },
      globals: globals.browser,
    },
    rules: {
      ...typeAwareRules,
      ...crossSurfaceImports(['src', 'admin', 'extensions', 'backend']),
    },
  },

  {
    files: ['admin/src/**/*.ts'],
    extends: [tseslint.configs.recommended],
    languageOptions: {
      parserOptions: { project: ['./admin/tsconfig.json'], tsconfigRootDir: import.meta.dirname },
      globals: globals.browser,
    },
    rules: {
      ...typeAwareRules,
      ...crossSurfaceImports(['src', 'website', 'extensions', 'backend']),
    },
  },

  {
    files: ['**/*.svelte'],
    extends: [tseslint.configs.base, svelte.configs.recommended],
    languageOptions: {
      parser: svelteParser,
      parserOptions: { parser: tseslint.parser, extraFileExtensions: ['.svelte'] },
      globals: globals.browser,
    },
    rules: {
      ...noConsole,
      ...noHtmlSinks,
      'no-undef': 'off',
      'no-unused-vars': 'off',
      'no-useless-assignment': 'off',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'svelte/no-at-html-tags': 'error',
      'svelte/no-target-blank': 'error',
      'svelte/require-each-key': 'warn',
      'svelte/prefer-svelte-reactivity': 'warn',
    },
  },

  {
    files: ['src/**/*.svelte'],
    rules: crossSurfaceImports(['website', 'admin', 'extensions', 'backend']),
  },
  {
    files: ['website/src/**/*.svelte'],
    rules: crossSurfaceImports(['src', 'admin', 'extensions', 'backend']),
  },
  {
    files: ['admin/src/**/*.svelte'],
    rules: crossSurfaceImports(['src', 'website', 'extensions', 'backend']),
  },

  {
    files: ['tools/**/*.{js,mjs,ts}', 'website/tools/**/*.mjs', 'admin/tools/**/*.mjs', '*.config.ts', '*.config.js'],
    extends: [tseslint.configs.recommended],
    languageOptions: {
      globals: globals.node,
      parserOptions: { project: null },
    },
    rules: {
      'no-console': 'off',
      ...noHtmlSinks,
      '@typescript-eslint/no-explicit-any': 'error',
    },
  },
)
