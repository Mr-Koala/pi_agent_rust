# GitHub Workflow 老版本 Linux 构建手册（C / Go / Rust）

> 目标：用 GitHub Actions 稳定产出可在老 Linux 环境运行的二进制包。  
> 适用：需要兼容 CentOS 7.x、老 glibc 环境，或无法使用官方预编译包的场景。

## 1. 先定兼容策略

在写 workflow 前，先固定“运行时基线”。

1. 主包策略：`glibc` 基线包（常见是 `glibc 2.17`，对应 CentOS 7.x）。
2. 兜底策略：`musl` 静态包（最大化可运行性，避免 glibc 版本问题）。
3. 命名规范：把兼容信息写进资产名，避免误用。
4. 验收标准：发布前必须通过符号版本检查和真实机器烟测。

推荐资产命名：

- `tool-linux-amd64-glibc217.tar.xz`
- `tool-linux-amd64-musl.tar.xz`

## 2. 通用 Workflow 结构

建议把“兼容构建”做成独立 workflow（不要一开始就混进现有主发布流程）。

标准步骤：

1. `workflow_dispatch` 手动触发，先跑通。
2. 矩阵定义目标（`gnu.2.17` + `musl`）。
3. 安装工具链（语言编译器 + zig 或交叉编译器）。
4. 构建。
5. 兼容性校验（`objdump/readelf/ldd/file`）。
6. 打包 + `upload-artifact`。
7. 稳定后再接入 release。

## 3. Rust 实战模板

核心建议：

1. `gnu.2.17` 使用 `cargo-zigbuild`。
2. 明确 `rustup target add`。
3. 为 zig 单独缓存目录，减少偶发缓存问题。
4. 对 `gnu.2.17` 做 `GLIBC_*` 上限检查。

示例（精简）：

```yaml
name: Legacy Linux Build

on:
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        include:
          - target: x86_64-unknown-linux-gnu.2.17
            rust_target: x86_64-unknown-linux-gnu
            asset: tool-linux-amd64-glibc217
          - target: x86_64-unknown-linux-musl
            rust_target: x86_64-unknown-linux-musl
            asset: tool-linux-amd64-musl
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - uses: mlugg/setup-zig@v1
      - run: cargo install cargo-zigbuild --locked
      - run: rustup target add "${{ matrix.rust_target }}"
      - run: |
          export ZIG_LOCAL_CACHE_DIR="${PWD}/.zig-cache-${{ matrix.target }}"
          mkdir -p "${ZIG_LOCAL_CACHE_DIR}"
          cargo zigbuild --release --locked --target "${{ matrix.target }}"
      - run: |
          BIN="target/${{ matrix.rust_target }}/release/your_bin"
          objdump -T "$BIN" | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -V | tail -n1
      - uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.asset }}
          path: target/**/release/your_bin
```

## 4. Go 实战要点

优先分两种模式：

1. 纯 Go：`CGO_ENABLED=0`，直接静态包，兼容性最好。
2. 含 CGO：必须控制 C 工具链基线（建议 zig 或容器基线）。

纯 Go 例子：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o tool
```

CGO 例子（glibc 2.17 思路）：

```bash
CC="zig cc -target x86_64-linux-gnu.2.17" \
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
go build -trimpath -ldflags="-s -w" -o tool
```

Go 校验建议：

1. `file tool` 看是否静态/动态。
2. `ldd tool` 看运行时依赖。
3. `objdump -T tool | grep GLIBC_` 看符号上限。

## 5. C/C++ 实战要点

老系统兼容最稳的是“固定构建基线”：

1. `glibc` 路线：在老基线容器里构建（如 manylinux2014 / CentOS7 toolchain）。
2. 静态路线：`musl` 交叉构建（需评估 NSS、DNS、插件等差异）。

关键原则：

1. 不在 `ubuntu-latest` 直接出 `gnu` 包（会抬高 glibc 依赖）。
2. 明确编译器与链接器版本。
3. 对动态库依赖做白名单审计（`libstdc++`, `libgcc_s`, `libpthread` 等）。

## 6. 统一校验清单（发布前必做）

每个产物都执行：

1. `file <bin>`：确认架构与静态/动态属性。
2. `ldd <bin>`：动态包必须检查依赖是否符合预期。
3. `objdump -T <bin> | grep GLIBC_`：确认符号版本上限。
4. 目标机器烟测：至少执行 `--version` 和一条核心命令。
5. 记录证据：把检查输出保存为 artifact。

## 7. 接入 Release 的方式

稳定后再并入 release workflow：

1. 在 release 构建矩阵增加 `glibc217` 和 `musl` 条目。
2. 使用与独立 workflow 相同的构建与校验逻辑。
3. 在 release notes 的“Manual Install”表格增加这两个包名。
4. 让 `SHA256SUMS` 自动覆盖新增资产。

## 8. 实战闭环流程（本次已验证）

下面是这次在 `Mr-Koala/pi_agent_rust` 上实际跑通的闭环流程，可直接复用。

1. 新增独立 workflow（先不动 release）：
   - 文件：`.github/workflows/linux-legacy-build.yml`
   - 目标：`x86_64-unknown-linux-gnu.2.17` + `x86_64-unknown-linux-musl`
2. 首次提交并推送：
   - `git add .github/workflows/linux-legacy-build.yml`
   - `git commit -m "ci: add legacy linux compatible build workflow"`
   - `git push`
3. 触发并观察 run：
   - 自动触发（push 命中 paths）或手动触发：
     - `gh workflow run linux-legacy-build.yml --ref main`
   - 查看最近 run：
     - `gh run list --workflow linux-legacy-build.yml --limit 3`
4. 如果失败，拉失败细节：
   - `gh run view <run_id> --json jobs,status,conclusion,url`
   - `gh run view <run_id> --log-failed`
5. 基于日志修复后再次提交：
   - 典型修复项（本次实际遇到）：
     - 增加 `rust_target` + `rustup target add`
     - 修正打包阶段的目标目录探测
     - `cargo-zigbuild` 增加独立 `ZIG_LOCAL_CACHE_DIR`
     - 构建步骤失败后自动重试一次
   - 提交推送：
     - `git add ...`
     - `git commit -m "<fix message>"`
     - `git push`
6. 回归验证通过后，确认产物：
   - `gh run view <run_id> --json jobs`
   - `gh api repos/<owner>/<repo>/actions/runs/<run_id>/artifacts`
   - 预期看到：
     - `pi-linux-amd64-glibc217`
     - `pi-linux-amd64-musl`
7. 最后再接入 release workflow：
   - 在 `release.yml` 增加 legacy Linux 矩阵条目
   - 复用同样的 zig 构建与校验逻辑
   - 更新 release notes 资产列表

建议保留“先独立 workflow 验证、后并入 release”的节奏，避免直接污染主发布链路。

## 9. 常见故障与处理

1. 构建偶发失败（`parser.o not found` 之类）：
   - 给 zig 配独立缓存目录。
   - 构建步骤加一次重试。
2. 产物路径不一致：
   - 同时探测 `target/<full-target>/release` 和 `target/<rust-target>/release`。
3. 运行时报 `GLIBC_2.xx not found`：
   - 说明构建基线过新，回到 `gnu.2.17` 或改发 `musl` 包。
4. 本地可跑、老机不可跑：
   - 以老机烟测结果为准，不要只看 CI 成功。

## 10. 维护建议

1. 把“兼容构建”当产品能力长期维护（不是一次性脚本）。
2. 每次升级编译器/依赖后都重跑老环境烟测。
3. 用固定命名与固定检查，减少人为判断误差。
4. 给每个目标维护最小可用验证命令集，防止“能启动但不可用”。
