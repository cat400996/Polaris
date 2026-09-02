//! 测试专用夹具：临时目录守卫 + **源码级门的取材锚点**。
//!
//! # 临时目录守卫（[`TestDir`]）
//!
//! 手工在测试尾部 `remove_dir_all` 遇到 `assert!` / `#[should_panic]` 时必然失效；本守卫把清理
//! 绑定到栈展开，并保留 `PathBuf` 的调用手感，避免每个测试模块各写一份不完整生命周期。
//!
//! # 取材锚点（[`crate_source`] / [`crate_file`] / [`repo_file`] / [`module_source`]）
//!
//! 本 crate 的源码级门此前一律用 `include_str!` 取材，而 `include_str!` 的相对路径锚在
//! **含它的那个文件**：测试实体从 `foo.rs` 搬进 `foo/tests/mod.rs` 的那一刻，143 处锚点全部
//! 平移一层，失败模式是「解析到另一个真实存在的文件 ⇒ 编译通过、门继续绿、扫的却是别的东西」。
//!
//! 下面四个 wrapper 把锚点换成 `CARGO_MANIFEST_DIR`（crate 根，不随测试位置动）。**`env!` 必须
//! 写在本 crate 里**——写进 `polaris-source-probe` 内部就会解析成 `crates/source-probe`，
//! 全部取材当场跑偏；实现单点在那个 crate，锚点单点在这里。语义与边界见该 crate 的模块文档。

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

pub(crate) struct TestDir(PathBuf);

impl TestDir {
    pub(crate) fn new(prefix: &str) -> Self {
        assert!(
            !prefix.is_empty() && !prefix.contains(['/', '\\']),
            "测试临时目录前缀必须是单个安全路径段"
        );
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let sequence = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("{prefix}{}-{nonce}-{sequence}", std::process::id()));
        std::fs::create_dir(&path).expect("测试临时目录必须唯一且可创建");
        Self(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Deref for TestDir {
    type Target = PathBuf;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<Path> for TestDir {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ── 源码级门的取材锚点 ────────────────────────────────────────────────────
//
// 这几个 wrapper 都只做一件事：把**本 crate** 的 `CARGO_MANIFEST_DIR` 传给单点实现。

/// `src-tauri/src/<rel>` 的全文。取代 `include_str!("tray.rs")` / `include_str!("runtime/stats.rs")`。
pub(crate) fn crate_source(rel: &str) -> String {
    polaris_source_probe::crate_source_in(env!("CARGO_MANIFEST_DIR"), rel)
}

/// `src-tauri/<rel>` 的全文（`Cargo.toml` / `tauri.conf.json` / `capabilities/*.json`）。
/// 取代 `include_str!("../Cargo.toml")`。
pub(crate) fn crate_file(rel: &str) -> String {
    polaris_source_probe::crate_file_in(env!("CARGO_MANIFEST_DIR"), rel)
}

/// 仓库根下 `<rel>` 的全文（`ui/**` / `scripts/**`）。取代
/// `include_str!("../../../../scripts/verify-packaging.mjs")` —— 那串 `../` 的**个数**本身
/// 就是随调用方深度变化的锚点。
pub(crate) fn repo_file(rel: &str) -> String {
    polaris_source_probe::repo_file_in(env!("CARGO_MANIFEST_DIR"), rel)
}

/// `src-tauri/<rel>` 的**原始字节**（`icons/*.png` 等随包二进制资产）。
/// 取代 `include_bytes!("../../../icons/tray-on-black.png")` —— 那串 `..` 的个数随测试位置变。
pub(crate) fn crate_bytes(rel: &str) -> Vec<u8> {
    polaris_source_probe::crate_bytes_in(env!("CARGO_MANIFEST_DIR"), rel)
}

/// `src-tauri/src/<dir_rel>` 下全部生产 `.rs`（递归，排除 `tests/`）的拼接。
///
/// 相对逐个 `include_str!` 列清单的优势是**新增子模块自动进取材面**——手写清单的门在
/// 「有人新加了一个文件」时静默失去覆盖，而这是本仓已经吃过的亏。
pub(crate) fn module_source(dir_rel: &str) -> String {
    polaris_source_probe::module_source_in(env!("CARGO_MANIFEST_DIR"), dir_rel)
}

/// 取材面的**字面量面**：注释按字节抹成空格（偏移与行号不变），字符串/字符字面量原样保留。
///
/// 实现单点在 `polaris-source-probe`（与 `crates/system-integration` 的 `literal_face` 同一份），
/// 射程与已知边界见该函数的文档。[`module_code`] / [`crate_code`] 是它的两个取材形态。
pub(crate) use polaris_source_probe::mask_comments as literal_face;

/// [`module_source`] 的**剥注释**形态（[`literal_face`]）。
///
/// # 什么时候必须用它
///
/// 判据是**全文正面** `contains` / `matches().count()` 时。这类腿的针只要在注释里出现过一次，
/// 就有一份与生产调用点**无关**的证据源：生产侧删光、注释留着 ⇒ 门照绿。本仓实测：
/// `tray.rs:25` 的模块文档写着 `window::TRAY_IDLE_RECLAIM_SECS`，把常量的全部代码位改名，
/// `overlay_lifecycle_gate.rs` 那条正面断言仍然绿。
///
/// # 射程（如实登记）
///
/// **剥**：行注释 `//`（含 `///` / `//!`）—— **行首与行尾同等对待**；块注释 `/* */`（含嵌套），
/// 行中间起笔的也剥。**保留**：字符串 / 原始字符串 / 字符与字节字面量，故字面量内部的 `//`
/// （`"http://a // b"`）不会被误当成注释起笔。**不做**条件编译求值：`#[cfg(test)]` 关掉的代码
/// 仍在面上 —— 排除测试代码是 [`module_source`] 那一层的职责（它剔 `tests/`），不是这里。
///
/// # 为什么不是符号面（连字符串一起抹）
///
/// 本 crate 的消费方里有多条针**就是字符串字面量**（`"phase": "fetching"` / `"subscriptionId"` /
/// `"keepTrayMenuWarm"`）。连字符串一起抹，这些针在净化面上永远命中不到 —— 判据不是变弱，
/// 是消失。要按符号扫时用 `polaris_source_probe::mask_comments_and_strings`。
///
/// 切片型取材器（[`crate::commands::guard_scan::top_level_fn_body`] /
/// `impl_method_body` / `method_scan::method_body`）内部还会再剥一道整行注释，幂等无副作用；
/// 但它们**只**剥整行，故喂它们的取材仍应先过这里，行尾/块注释才有人管。
pub(crate) fn module_code(dir_rel: &str) -> String {
    literal_face(&module_source(dir_rel))
}

/// [`crate_source`] 的**剥注释**形态。取舍与射程同 [`module_code`]。
pub(crate) fn crate_code(rel: &str) -> String {
    literal_face(&crate_source(rel))
}

/// 逐文件形态，用于让失败信息说得出「哪个文件」。
pub(crate) fn module_files(dir_rel: &str) -> Vec<(String, String)> {
    polaris_source_probe::module_files_in(env!("CARGO_MANIFEST_DIR"), dir_rel)
}

pub(crate) use polaris_source_probe::expect_marker;

#[cfg(test)]
mod tests;
