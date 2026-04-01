# new/provider/

本公开实例仓库只保留一个真实 provider 例子：

- `pqvariant/pqvariant_provider.c`

它直接暴露：

- `sntrup761`（KEM）
- `cross-rsdp-128-small`（SIGNATURE）

对应的数学实现源码位于 `new/alg/experimental_pq/`。
