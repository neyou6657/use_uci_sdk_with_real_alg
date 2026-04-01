# new/

`new/` 是这次真实算法接入实验的核心目录。

这里保留的是“算法和 provider 这一侧”的材料，而不是 UCI SDK 的私有内核源码。

## 目录说明

- `alg/experimental_pq/`
  vendoring 进来的真实实验性 PQ 变种算法 clean/ref 实现
- `provider/pqvariant/`
  `pqvariantprovider` 的 provider 源码
- `Config/pq_variant_algorithms.json`
  真实算法配置
- `scripts/build_new_provider.py`
  直接从配置构建 provider `.so`
- `output/`
  已经构建好的 provider 产物、patch、摘要和安装脚本

## 这次用到的真实算法

- `sntrup761`
- `cross-rsdp-128-small`

它们的数学实现源码位于：

- `alg/experimental_pq/sntrup761_clean/`
- `alg/experimental_pq/cross-rsdp-128-small_clean/`

## 直接刷新 provider 产物

这个公开实例仓库仍然可以重新编译 provider：

```bash
./new/build_oneclick.sh
```

默认会：

1. 读取 `new/Config/algorithms.json`
2. 重新编译 `pqvariantprovider.so`
3. 生成 `new/output/pqvariantprovider.patch.conf`
4. 保持 `new/output/install.sh` 这份自包含安装脚本可直接使用

这里不会再尝试构建私有 SDK 全量源码，也不会跑原仓库里的完整测试矩阵。这个公开仓库的重点是：

- 保留真实算法接入事例
- 保留可直接使用的运行时产物
- 保留上层 CLI 调用例子和日志

## 安装导出

把仓库内置头文件、运行时 `.so`、provider `.so` 和 patch 导出到独立目录：

```bash
./new/output/install.sh /tmp/pqvariant_pkg
```

导出后即可配合 `cli/` 目录里的示例程序使用。
