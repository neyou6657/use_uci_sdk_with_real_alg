# cli/

`uciapi` 是一个上层应用示例。

它只使用：

- 导出的 `include/uci/*.h`
- `libuci.so`
- provider `.so`
- patch 配置

这个目录的目的很简单：演示第三方应用如何使用已经打包好的运行时文件，而不是依赖私有 SDK 源码树。

## 用法

先导出运行时包：

```bash
./new/output/install.sh /tmp/pqvariant_pkg
```

构建 CLI：

```bash
./cli/build.sh /tmp/pqvariant_pkg /tmp/pqvariant_cli
```

运行：

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

仓库内已有一份实跑日志：

- `logs/pqvariant_cli_run.log`
