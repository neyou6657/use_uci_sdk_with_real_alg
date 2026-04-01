# use_uci_sdk_with_real_alg

这是一个“使用 UCI SDK”的公开实例仓库，不是 UCI SDK 私有源码仓库本体。

这个仓库保留了三类对外有意义的内容：

1. `new/`
   这次真实实验的核心材料都在这里，包括：
   - vendoring 进来的真实 PQ 变种算法源码
   - `pqvariantprovider` provider 源码
   - 算法配置
   - 构建出的 provider `.so`
   - patch 配置和安装脚本

2. `cli/`
   一个上层应用示例，只链接导出的 UCI 头文件和 `libuci.so`，演示如何像第三方应用一样加载 provider 并发起调用。

3. 预编译运行时产物与日志
   - `runtime/lib/libuci.so`
   - `runtime/lib/libmtoken_gm3000.so`
   - `new/output/providers/pqvariantprovider.so`
   - `new/output/pqvariantprovider.patch.conf`
   - `logs/pqvariant_cli_run.log`

## 这次做了什么

这次验证的不是教学空壳，而是真实实验性 PQ 变种算法：

- KEM：`sntrup761`
- Signature：`cross-rsdp-128-small`

这两套算法的 clean/ref 数学实现已经直接 vendoring 在 `new/alg/experimental_pq/` 下，不依赖 `liboqs` 动态库，也不走 `oqs-provider`。

## 事例在哪

如果你要看“真实算法接入”本体，先看：

- `new/alg/experimental_pq/`
- `new/provider/pqvariant/`
- `new/Config/pq_variant_algorithms.json`

如果你要看“上层应用怎么用”，看：

- `cli/uciapi.c`
- `cli/build.sh`
- `logs/pqvariant_cli_run.log`

## 构建产物在哪

运行时基础库在：

- `runtime/lib/libuci.so`
- `runtime/lib/libmtoken_gm3000.so`

Provider 产物在：

- `new/output/providers/pqvariantprovider.so`

路由 patch 和构建摘要在：

- `new/output/pqvariantprovider.patch.conf`
- `new/output/last_build.json`

## 如何安装并跑 CLI

先把仓库内置的运行时文件导出到一个独立目录：

```bash
./new/output/install.sh /tmp/pqvariant_pkg
```

然后像第三方应用一样构建 CLI：

```bash
./cli/build.sh /tmp/pqvariant_pkg /tmp/pqvariant_cli
```

运行 KEM 示例并记录日志：

```bash
export OPENSSL_MODULES=/tmp/pqvariant_pkg/lib/ossl-modules
export LD_LIBRARY_PATH=/tmp/pqvariant_pkg/lib:${LD_LIBRARY_PATH:-}
export SDFR_PATCH_FILE=/tmp/pqvariant_pkg/etc/uci/pqvariantprovider.patch.conf

/tmp/pqvariant_cli/uciapi \
  --enable-log \
  --log-file /tmp/pqvariant_cli.log \
  --operation kem-demo \
  --provider pqvariantprovider \
  --algorithm sntrup761 \
  --algid 0x00F3E761 \
  --pin 12345678
```

仓库里已经附带一份真实跑出来的日志：

- `logs/pqvariant_cli_run.log`

## 仓库边界

这个公开仓库故意不包含 UCI SDK 的私有核心实现源码，例如原始 `src/` 目录及其完整内部构建链。

你看到的是“如何使用 UCI SDK + 如何挂接真实算法 + 构建后的可运行产物 + 上层调用例子”，不是 SDK 内核总仓。
