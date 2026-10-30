# wyx 核心候选验证记录

日期：2026-10-30。基础提交：`71277de69efbbc86c23ad8ae02b68efd174e5756`。
验证在该基础提交加本次候选补丁的工作树上完成，二进制标记 `vcs.modified=true`；
不是声称发布构建来自一个尚未生成的提交。

## 工具链和依赖

- Go 1.27.0；`GOEXPERIMENT=jsonv2`；`CGO_ENABLED=0`。
- wyx Xray：`v0.0.0-20260930151924-e087e74a1bf2`。
- wyx sing-box：`8d054dcd8bfec013c675eb2d246fcb98f5c9c870` 加 `compat/sing-box.patch`。
- sing-tun：`v0.8.0-beta.11` 加 `compat/sing-tun.patch`。
- Hysteria core/extras：`v2.12.0`。

## 可重复执行的入口

```sh
./scripts/verify-wyx-cores.sh
```

该脚本依次执行 module 校验、core 包和兼容回归测试，使用完整发布功能标签
构建 Linux amd64、arm64，并导出两份 `go version -m` 信息。
脚本退出码为 0，两种架构构建均成功；amd64 的 `version` 子命令实际运行成功。
交叉构建的 arm64 二进制没有在本机执行。

测试和依赖校验的原始输出：

```text
all modules verified
?   	github.com/InazumaV/V2bX/core	[no test files]
?   	github.com/InazumaV/V2bX/core/hy2	[no test files]
?   	github.com/InazumaV/V2bX/core/imports	[no test files]
?   	github.com/InazumaV/V2bX/core/sing	[no test files]
?   	github.com/InazumaV/V2bX/core/xray	[no test files]
?   	github.com/InazumaV/V2bX/core/xray/app	[no test files]
ok  	github.com/InazumaV/V2bX/core/xray/app/dispatcher	0.008s
?   	github.com/InazumaV/V2bX/core/xray/distro/all	[no test files]
ok  	github.com/sagernet/sing-box/common/tls	0.037s
ok  	github.com/sagernet/sing-box/dns	0.003s
ok  	github.com/sagernet/sing-box/transport/v2rayhttp	0.040s
```

新增测试覆盖 Xray 域名/IP 排除规则、DNS 缓存 TTL/响应复制/清空、TLS 超时与
Clone、HTTP/2 活动流关闭和重新拨号。这些是局部回归，不是完整协议验收。

## 未验收范围

Docker、GitHub Actions 全平台矩阵、真实客户端协议握手、动态用户撤销、
限速/计费/设备限制和生产审计回归均未完成。候选尚未迁入现有生产审计补丁。
提交或推送本分支不代表这些验证已通过；线上服务和配置没有通过本分支部署。
