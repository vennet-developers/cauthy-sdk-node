import path from 'node:path'
import { defineConfig } from 'vitest/config'

// The example and the conformance target import `@cauthyhq/node` as an
// application would; in tests that name is the sources, with no build.
const src = path.resolve('src')

export default defineConfig({
  resolve: {
    alias: [
      { find: /^@cauthyhq\/node$/, replacement: `${src}/index.ts` },
      { find: /^@cauthyhq\/node\/keys$/, replacement: `${src}/keystores.ts` },
      { find: /^@cauthyhq\/node\/(express|fastify|hono|next|mcp|theme)$/, replacement: `${src}/$1.ts` },
    ],
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts', 'examples/**/*.test.ts'],
    // cauthy-auth 0.42's ESM build imports `next/headers` without an extension,
    // which Node's own resolver refuses; Vite resolves it.
    server: { deps: { inline: ['cauthy-auth'] } },
  },
})
