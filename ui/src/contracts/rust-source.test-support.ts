/**
 * TS 侧读 Rust 源码的唯一入口 —— `crates/source-probe` 的镜像。
 *
 * # 为什么要有这层
 *
 * 一个 Rust 模块 `foo` 的源码天然分布在两处：`foo.rs`（或 `foo/mod.rs`）与目录 `foo/`。
 * 把测试实体外移成 `foo/tests/mod.rs` 之后，任何写死 `readFileSync('…/foo.rs')` 的跨语言门
 * 都会**静默失去**它原本要扫的那一半：断言若是「必须包含 X」当场转红（还算体面），若是
 * 「不得包含 X」则变成恒真 —— 门还在、报告还是绿的，判据已经没了。
 *
 * 因此本模块不接受「文件路径」，只接受**模块路径**（不带扩展名），由它自己去解析这个模块
 * 到底落在哪些文件上。
 *
 * # 取材面二选一，必须显式选
 *
 * - [`moduleSource`]：只要生产源码（剔除 `tests/` 目录）。断言「生产代码里不得出现 X」用它 ——
 *   把测试代码混进来，测试里的一个同形串就能让判据假红。
 * - [`moduleSourceWithTests`]：模块的全部源码。断言「某个测试/夹具还在」用它。
 *
 * 两者都**故障关闭**：模块解析不到、或取材面为空，直接抛 —— 空取材面上的否定型断言恒真，
 * 那正是本模块要根除的失效形态。
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));

function collectRs(dir: string, out: string[]): void {
  for (const entry of readdirSync(dir).sort()) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) collectRs(full, out);
    else if (entry.endsWith('.rs')) out.push(full);
  }
}

/** 模块 `relModule`（仓库相对、**不带扩展名**）落在的全部 `.rs` 文件，已排序。 */
function moduleFiles(relModule: string, includeTests: boolean): string[] {
  const base = join(REPO_ROOT, relModule);
  const root = existsSync(`${base}.rs`)
    ? `${base}.rs`
    : existsSync(join(base, 'mod.rs'))
      ? join(base, 'mod.rs')
      : null;
  if (root === null) {
    throw new Error(
      `模块 \`${relModule}\` 解析不到：既没有 ${relModule}.rs 也没有 ${relModule}/mod.rs。` +
        `路径写错或模块被搬走了 —— 别把它当成「这个模块是空的」。`,
    );
  }
  const files = [root];
  if (existsSync(base) && statSync(base).isDirectory()) {
    const rest: string[] = [];
    collectRs(base, rest);
    for (const file of rest) {
      if (file === root) continue;
      const isTest = file.slice(base.length).replaceAll('\\', '/').includes('/tests/');
      if (isTest && !includeTests) continue;
      files.push(file);
    }
  }
  return files;
}

function read(relModule: string, includeTests: boolean, what: string): string {
  const files = moduleFiles(relModule, includeTests);
  const source = files.map((file) => readFileSync(file, 'utf8')).join('\n');
  if (source.trim() === '') {
    throw new Error(`模块 \`${relModule}\` 的${what}取材面是空的 —— 其上的否定型断言会恒真。`);
  }
  return source;
}

/** 模块的**生产**源码（剔除 `tests/` 目录下的一切）。 */
export function moduleSource(relModule: string): string {
  return read(relModule, false, '生产');
}

/**
 * 目录树 `relRoot`（仓库相对）下的全部**生产** `.rs` 文件（剔除任意层级的 `tests/`），已排序。
 *
 * 用于「整片代码区里不得出现 X」这类断言 —— 按模块逐个登记的白名单只堵住模块内搬家，
 * **跨模块新增一个消费点仍在射程外**；取材面必须是整片生产区，白名单只用来放行已知真值点。
 * 取材根解析不到直接抛：空文件表上的否定型断言恒真，正是本模块要根除的失效形态。
 */
export function productionRsFilesUnder(relRoot: string): string[] {
  const base = join(REPO_ROOT, relRoot);
  if (!existsSync(base) || !statSync(base).isDirectory()) {
    throw new Error(
      `取材根 \`${relRoot}\` 不是目录（不存在或已被搬走）—— 别把它当成「这片区域没有代码」。`,
    );
  }
  const all: string[] = [];
  collectRs(base, all);
  return all.filter((file) => !file.slice(base.length).replaceAll('\\', '/').includes('/tests/'));
}

/** 模块的**全部**源码（含 `tests/` 目录）。 */
export function moduleSourceWithTests(relModule: string): string {
  return read(relModule, true, '全量');
}
