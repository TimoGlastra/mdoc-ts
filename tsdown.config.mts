import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: 'src/index.ts',
  format: 'esm',
  dts: true,
  clean: true,
  sourcemap: true,
  failOnWarn: true,
  // TypeScript 7 declarations are generated with tsgo, which always emits this notice
  suppressWarnings: 'TypeScript 7.0 does not yet have a stable API and is experimental',
  deps: {
    onlyBundle: [],
  },
})
