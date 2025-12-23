> [!WARNING]
>
> **请注意，这是社区驱动的官方 syzkaller 文档翻译。当前文档的最新版本（英文版）可在 [docs/configuration.md](/docs/configuration.md) 中找到。**

# 配置

Syzkaller 系统中的 `syz-manager` 进程操作由一个配置文件控制，该文件在调用时通过 `-config` 选项传递。
这个配置可基于[示例](/pkg/mgrconfig/testdata/qemu.cfg)进行编写。
文件为 JSON 格式，包含[多个参数](/pkg/mgrconfig/config.go)。

## QEMU 虚拟机选项

使用 QEMU 虚拟机类型时，可以在 `vm` 部分指定以下选项：

### `ssh_port`

设置 `ssh_port` 可以为虚拟机实例指定一个基础 SSH 端口。指定后，虚拟机实例将使用从该值开始的连续端口（`ssh_port + index`）。例如，如果 `ssh_port` 设置为 10022 且有 4 个虚拟机，则它们将分别使用端口 10022、10023、10024 和 10025。

如果未指定（值为 0），系统将为每个虚拟机自动选择随机可用端口。

此选项在以下情况下很有用：
- 需要为外部脚本或调试使用可预测的 SSH 端口
- 避免与其他服务的端口冲突
- 需要提前配置防火墙规则

配置示例：
```json
{
    "vm": {
        "count": 4,
        "ssh_port": 10022,
        "kernel": "/path/to/bzImage",
        "cpu": 2,
        "mem": 2048
    }
}
```