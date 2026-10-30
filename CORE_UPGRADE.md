# wyx 核心更新候选（2026-10-30）

本地分支 `maintenance/wyx-core-update-20261030`，基于 amo0114/V2bX
`71277de69efbbc86c23ad8ae02b68efd174e5756`。保留 wyx 定制核心路线。
本分支用于源码维护和候选验证；不代表正式发布或生产部署。

| 核心 | 原 pin | 本候选 |
|---|---|---|
| wyx Xray | `63db1dc9e9e2`，2025-12-02 | `e087e74a1bf2`，2026-09-30 UTC |
| wyx sing-box_mod | `8d054dcd8bfe`，2025-12-02 | 同一提交加本地兼容补丁；这是核查时 wyx 最新提交 |

原项目的 `go.mod` 已通过 `replace` 使用 wyx，两者都固定到具体提交，
不会随远端 HEAD 自动更新。Xray 的新 replace 为
`github.com/wyx2685/xray-core v0.0.0-20260930151924-e087e74a1bf2`。
未将核心切换到官方 Xray 或官方 sing-box。

来源：[原 go.mod](https://github.com/amo0114/V2bX/blob/71277de69efbbc86c23ad8ae02b68efd174e5756/go.mod)、
[wyx Xray](https://github.com/wyx2685/Xray-core/commit/e087e74a1bf25b46f2776d1a3b53a68f6018d654)、
[wyx sing-box](https://github.com/wyx2685/sing-box_mod/commit/8d054dcd8bfec013c675eb2d246fcb98f5c9c870)。

## 必要适配

新 Xray 要求 Go 1.27 和 sing v0.9.6。两个核心处在同一个 Go 模块中，
共享依赖由 Go MVS 统一选择，不能分别保留两个不兼容的 sing 版本。

- V2bX Xray dispatcher 使用新 geodata 域名/IP matcher；补充 IP 排除语义。
- 更新 sniffing 配置类型、geodata 注册和错误 API，移除已删除的伪装头导入。
- Xray 已移除 SS `none/plain` cipher 和 IVCheck 配置；`DisableIVCheck=true`
  会明确报不再支持，不能静默忽略。使用这些旧配置的节点需要单独迁移。
- Hysteria core/extras 从 2.6.4 连带升到 2.12.0，以匹配新 Xray 引入的
  apernet QUIC 接口；Salamander wrapper 同步适配。
- sing-quic 使用 0.6.0-beta.5，sagernet/quic-go 使用 0.57.1-sing-box-mod.1，
  适配同图中的 qpack 0.6；不是将 sing-box 更新为官方新版本。
- `compat/sing-box` 保留 wyx 最新基线，适配 DNS 缓存、SOCKS 参数、TLS
  超时接口及 Go 1.27 的 HTTP/2 连接关闭。详见其 V2BX_COMPAT.md。
- `compat/sing-tun` 保留 0.8.0-beta.11 的旧接口，只适配缓存 API。
  直接换成 0.9 会丢失该 wyx sing-box 仍调用的 direct-route 接口。

本地副本使用仓库相对路径，保留上游许可证；`compat/*-source.json` 和
`compat/*.patch` 记录来源和差异。没有修改全局 Go module cache。
如后续另建自己的核心 fork，可以把这些兼容补丁迁入固定提交，再移除本地副本。

## 验证与复现

```sh
./scripts/verify-wyx-cores.sh
```

脚本固定 Go 1.27.0、GOEXPERIMENT=jsonv2、CGO_ENABLED=0，使用原发布功能标签：
`sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor`。
测试 core 包及新增的 DNS、TLS、HTTP/2 回归，构建 Linux amd64/arm64 并导出 buildinfo。

本地已通过上述两种架构构建及回归测试；命令、结果和验证边界见
[仓库内验证记录](docs/wyx-core-validation-20261030.md)。
尚未完成 Docker、GitHub Actions 全架构矩阵、所有实际协议端到端握手、
动态用户撤销、限速/计费/设备限制和生产审计回归。编译通过不能作为上线验收。

特别注意：本候选基于用户的干净 fork，未迁入现有生产 node-audit 补丁，
不能直接覆盖线上审计版。线上服务和配置均未改变。
这次更新不证明旧核心导致 GFW 识别，也不能承诺解除 DMIT IPv4 阻断。
