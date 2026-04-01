# Experimental PQ Variants

本目录 vendoring 了两套来自 `liboqs` 的 clean/ref 参考实现，目的是走通 `uciapi/new/` 的真实算法接入链路，而不是继续拿 `xiaoming` 逗构建器玩。

选型如下：

- `sntrup761`（KEM）
  - 具体参数集明确，不是族名泛指。
  - clean/ref 目录依赖面很小，只需要随机数和 `SHA-512` 胶水，适合最小 vendoring。
  - 在 provider 侧可以直接映射成 `KEYMGMT + KEM`。
- `cross-rsdp-128-small`（签名）
  - 属于明确的实验性签名参数集，且 clean/ref 版本结构清晰。
  - 依赖集中在本目录自带源码和 `SHAKE128` 胶水，便于直接 vendoring。
  - 可以直接映射成 `KEYMGMT + SIGNATURE`，覆盖 `SDFR` 的签名语义路径。

来源与许可：

- `sntrup761_clean/` 来自 `/workspace/liboqs-src/src/kem/ntruprime/pqclean_sntrup761_clean/`
- `cross-rsdp-128-small_clean/` 来自 `/workspace/liboqs-src/src/sig/cross/upcross_cross-rsdp-128-small_clean/`
- 对应目录内保留上游 `LICENSE`

`common/` 下的文件不是来自 `liboqs` 运行时，而是本仓库为这两套 ref 实现补的最小 OpenSSL 封装层，用于替代 `liboqs` 的 `randombytes/sha2/fips202` shim。
