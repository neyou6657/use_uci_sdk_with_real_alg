# runtime/

这里放的是已经构建好的 UCI SDK 运行时基础库：

- `lib/libuci.so`
- `lib/libmtoken_gm3000.so`

这两个 `.so` 供上层应用示例和 `new/output/install.sh` 直接打包使用。

本公开仓库不包含它们对应的私有 SDK 内核源码，只保留运行时产物。
