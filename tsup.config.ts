import { defineConfig } from 'tsup'

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    express: 'src/express.ts',
    fastify: 'src/fastify.ts',
    hono: 'src/hono.ts',
    next: 'src/next.ts',
    mcp: 'src/mcp.ts',
    keys: 'src/keystores.ts',
    theme: 'src/theme.ts',
    testing: 'src/testing.ts',
  },
  format: ['cjs', 'esm'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  target: 'node20',
  // Peer dependencies are the application's own; jose is the one dependency.
  external: ['jose', 'fastify', 'hono', 'next', /^next\//, 'express'],
})
