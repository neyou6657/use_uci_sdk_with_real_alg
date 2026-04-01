# pqvariantprovider

`pqvariantprovider` 是 `new/` 工作区下的真实实验性 PQ 变种 provider，当前暴露：

- `sntrup761`：`KEYMGMT + KEM`
- `cross-rsdp-128-small`：`KEYMGMT + SIGNATURE`

它直接 vendoring `liboqs` 的 clean/ref 源码，不链接 `liboqs`、不依赖 `oqs-provider`。构建时只链接 OpenSSL `libcrypto`，数学实现全部来自 `new/alg/experimental_pq/`。
