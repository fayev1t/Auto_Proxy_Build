# auto_proxy

手里小鸡太多了，每次买新机器都要手动配置，VB了一个落地机上用的一键部署脚本，用sing-box走HY2协议。

## 配置逻辑

- 检查系统环境（Debian/Ubuntu、amd64/arm64）并补齐依赖，自动拉取对应架构的 sing-box 1.14.3（本地已有同版本就直接复用）。
- 默认只配 HY2 协议，并打开 HY2 自带的 BBR（配置里的 `bbr_profile`）。如果检测到旧的 VLESS+REALITY 配置或 `keypair.txt`、`uuid.txt`，会先询问是否清理。
- 检测机器上原有的 HY2 密码和证书，有效的话询问是否直接复用（省得中转机还要改配置）；不复用或新机器就自动生成随机密码和自签名证书。
- 自动在路由规则最前面给 HY2 入站加两条规则：先解析目标域名，再拒绝本机、内网和云元数据（如 `169.254.169.254`）这类非公网地址，免得通过代理反过来摸到落地机自己的内部服务。路由里已有拒绝 IPv6 的规则时，域名只解析 IPv4。规则已经在就不重复加，重跑脚本不会叠加。
- 先跑 `sing-box check` 校验，没问题再备份原文件、写入配置并注册 systemd 开机自启；如果启动或监听失败会自动回滚。部署途中 SSH 断了会自己跑完，按 Ctrl-C 会回滚到原样。
- 会问要不要给 HY2 端口加 IP 白名单，没有云安全组的小鸡建议开。选是就输入中转机的 IP 或网段，多个用逗号或空格隔开（不支持域名），没装 nftables 会自动装。规则是 nftables 里单独一张 `inet auto_proxy` 表，只拦发到这个 UDP 端口的名单外来源，SSH 和其他端口不受影响；规则文件在 `/etc/sing-box/hy2-whitelist.nft`，每次 sing-box 启动前加载，加载不上 sing-box 就不启动，免得裸奔。加减 IP 或者取消，重跑脚本就行。它只拦不开：本机开着 ufw 之类的防火墙的话端口还得自己放行；要是有东西清空了整套 nftables 规则（比如 nftables.service 默认配置里的 flush ruleset），重启一下 sing-box 白名单就回来了。
- 顺带会问要不要开系统 TCP BBR，设置写在 `/etc/sysctl.d/99-zz-auto-proxy-bbr.conf`，删掉它重启就恢复，脚本也会打印立即撤销的命令。容器小鸡（OpenVZ/LXC）改不了内核参数，会自动跳过。它只管 TCP，HY2 走 UDP 不受影响，主要是给保留的 VLESS 和本机其他 TCP 连接用。
- 把中转机对接需要的地址、端口、密码、SNI 和公有证书打印到终端，并保存到 `/etc/sing-box/relay-info.md`。

## 用法

```bash
sudo bash bash.sh
```


