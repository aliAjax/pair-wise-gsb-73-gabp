// 最小 ESM loader：用 esbuild 把 .ts 转成 JS，并把 '@/...' 别名解析到 src/。
// 仅供 Node 20 下直接运行服务层单测（项目本身由 Vite 构建）。
import { build } from 'esbuild'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { existsSync } from 'node:fs'
import path from 'node:path'

const SRC_ROOT = path.resolve(process.cwd(), 'src')

const resolveAlias = (specifier) => {
  if (specifier.startsWith('@/')) {
    const rel = specifier.slice(2)
    const candidates = [
      path.join(SRC_ROOT, `${rel}.ts`),
      path.join(SRC_ROOT, rel, 'index.ts'),
    ]
    for (const candidate of candidates) {
      if (existsSync(candidate)) return candidate
    }
  }
  return null
}

export async function resolve(specifier, context, nextResolve) {
  const aliased = resolveAlias(specifier)
  if (aliased) {
    return { url: pathToFileURL(aliased).href, shortCircuit: true }
  }
  return nextResolve(specifier, context)
}

export async function load(url, context, nextLoad) {
  if (url.endsWith('.ts') && !url.includes('node_modules')) {
    const filePath = fileURLToPath(url)
    const result = await build({
      entryPoints: [filePath],
      bundle: false,
      write: false,
      format: 'esm',
      platform: 'node',
      target: 'node20',
    })
    return { format: 'module', source: result.outputFiles[0].text, shortCircuit: true }
  }
  return nextLoad(url, context)
}
