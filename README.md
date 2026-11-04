# auto_proxy

手里小鸡太多了，每次买新机器都要手动配置，VB了一个落地机上用的一键部署脚本，用sing-box走HY2协议。

## 配置逻辑

- 检查系统环境（Debian/Ubuntu、amd64/arm64）并补齐依赖，自动拉取对应架构的 sing-box 1.14.3（本地已有同版本就直接复用）。
- 默认只配 HY2 协议，并打开 HY2 自带的 BBR（配置里的 `bbr_profile`）。如果检测到旧的 VLESS+REALITY 配置或 `keypair.txt`、`uuid.txt`，会先询问是否清理。
- 检测机器上原有的 HY2 密码和证书，有效的话询问是否直接复用（省得中转机还要改配置）；不复用或新机器就自动生成随机密码和自签名证书。
- 先跑 `sing-box check` 校验，没问题再备份原文件、写入配置并注册 systemd 开机自启；如果启动或监听失败会自动回滚。部署途中 SSH 断了会自己跑完，按 Ctrl-C 会回滚到原样。
- 顺带会问要不要开系统 TCP BBR，设置写在 `/etc/sysctl.d/99-zz-auto-proxy-bbr.conf`，删掉它重启就恢复，脚本也会打印立即撤销的命令。容器小鸡（OpenVZ/LXC）改不了内核参数，会自动跳过。它只管 TCP，HY2 走 UDP 不受影响，主要是给保留的 VLESS 和本机其他 TCP 连接用。
- 把中转机对接需要的地址、端口、密码、SNI 和公有证书打印到终端，并保存到 `/etc/sing-box/relay-info.md`。

## 用法

```bash
sudo bash bash.sh
```


