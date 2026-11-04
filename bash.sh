#!/usr/bin/env bash
set -euo pipefail

script_path="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/$(basename -- "${BASH_SOURCE[0]}")"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'HELP'
用法：sudo bash bash.sh [--address 公网地址] [--port UDP端口] [--sni 证书名称]
交互安装 sing-box 上游代理。支持 Debian/Ubuntu、systemd、amd64/arm64。
会检查依赖、备份旧安装，并询问旧配置清理、凭据复用和是否开启系统 TCP BBR。
HELP
  exit 0
fi

if [[ "$(id -u)" != 0 ]]; then
  if ! command -v sudo >/dev/null; then
    printf '%s\n' '需要 root 权限，请切换 root 后运行。' >&2
    exit 1
  fi
  exec sudo -- bash "$script_path" "$@"
fi

if [[ ! -f /etc/os-release ]]; then
  printf '%s\n' '无法识别发行版，仅支持 Debian/Ubuntu。' >&2
  exit 1
fi
. /etc/os-release
case "${ID:-}" in
  debian|ubuntu) ;;
  *) printf '%s\n' '仅支持 Debian/Ubuntu。' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|aarch64|arm64) ;;
  *) printf '%s\n' '仅支持 amd64/arm64。' >&2; exit 1 ;;
esac
if [[ ! -d /run/systemd/system ]] || ! systemctl show --property=Version --value >/dev/null 2>&1; then
  printf '%s\n' '需要正在运行的 systemd。' >&2
  exit 1
fi

packages=()
for item in python3:python3 curl:curl openssl:openssl ss:iproute2; do
  if ! command -v "${item%%:*}" >/dev/null; then
    packages+=("${item#*:}")
  fi
done
if [[ ! -s /etc/ssl/certs/ca-certificates.crt ]]; then
  packages+=(ca-certificates)
fi
if ((${#packages[@]})); then
  printf '安装缺失依赖：%s\n' "${packages[*]}"
  apt-get update
  apt-get install -y --no-install-recommends "${packages[@]}"
fi
if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))'; then
  printf '%s\n' '需要 Python 3.9 或更新版本（建议 Debian 11+ / Ubuntu 22.04+）。' >&2
  exit 1
fi

# Keep stdin connected to the terminal for interactive confirmations.
exec python3 /dev/fd/3 "$@" 3<<'AUTO_PROXY_PYTHON'
from __future__ import annotations

import argparse
import contextlib
import copy
import fcntl
import fnmatch
import grp
import hashlib
import ipaddress
import json
import os
import platform
import pwd
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

SING_BOX_VERSION = "1.14.3"


class InstallError(Exception):
    """An installation cannot safely continue."""


def say(*values, file=None) -> None:
    """Print status; a vanished terminal (dropped SSH) must never abort or skip a rollback."""
    try:
        print(*values, file=file or sys.stdout, flush=True)
    except (OSError, ValueError):
        pass


class Runner:
    def run(
        self,
        args: list[str],
        *,
        check: bool = True,
        cwd: Path | None = None,
        timeout: int = 40,
    ) -> subprocess.CompletedProcess:
        env = dict(os.environ, LC_ALL="C", SYSTEMD_COLORS="0", SYSTEMD_PAGER="cat")
        # sing-box otherwise uses the invoking sudo user's ownership for new files.
        for name in ("SUDO_USER", "SUDO_UID", "SUDO_GID"):
            env.pop(name, None)
        try:
            result = subprocess.run(
                [str(arg) for arg in args],
                capture_output=True,
                text=True,
                cwd=cwd,
                env=env,
                timeout=timeout,
                check=False,
                # Ctrl-C and SSH hangups reach only the installer, which decides whether
                # to stop, finish or roll back; a killed systemctl could break a rollback.
                start_new_session=True,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise InstallError(f"无法执行 {Path(args[0]).name}：{error}") from error
        if check and result.returncode:
            detail = (result.stderr or result.stdout).strip()[-2000:]
            raise InstallError(f"{Path(args[0]).name} 执行失败：{detail}")
        return result


class Prompt:
    def ask(self, message: str, default: str = "") -> str:
        suffix = f" [{default}]" if default else ""
        try:
            return input(f"{message}{suffix}：").strip() or default
        except EOFError as error:
            raise InstallError("输入已结束，安装取消。") from error

    def confirm(self, message: str, default: bool = True) -> bool:
        while True:
            answer = self.ask(message + " (y/n)", "y" if default else "n").lower()
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no"):
                return False
            print("请输入 y 或 n。")

    def choose(self, message: str, choices: list[str]) -> int:
        if len(choices) == 1:
            return 0
        print(message)
        for index, label in enumerate(choices, 1):
            print(f"  {index}. {label}")
        while True:
            answer = self.ask("选择编号", "1")
            if answer.isdigit() and 1 <= int(answer) <= len(choices):
                return int(answer) - 1
            print("请输入列表中的编号。")


class SignalGuard:
    """Ctrl-C, SIGTERM and SSH hangups stop the installer, except while it deploys.

    While deploying, a signal only takes effect at the next checkpoint, so files and the
    service are never left half-changed and a rollback always runs to the end. A hangup
    alone is just recorded: nothing needs the terminal any more, so finishing is better.
    """

    signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)

    def __init__(self) -> None:
        self.deferring = False
        self.received: list[int] = []
        self.previous: dict = {}

    def install(self) -> None:
        for signum in self.signals:
            self.previous[signum] = signal.signal(signum, self.handle)

    def restore(self) -> None:
        for signum, handler in self.previous.items():
            signal.signal(signum, handler)
        self.previous.clear()

    def handle(self, signum, frame) -> None:
        self.received.append(signum)
        if not self.deferring:
            raise InstallError(f"收到信号 {signum}，安装终止。")

    @property
    def stop_requested(self) -> bool:
        return any(signum != signal.SIGHUP for signum in self.received)

    def checkpoint(self) -> None:
        if self.stop_requested:
            raise InstallError("收到中断信号，安装终止。")

    @contextlib.contextmanager
    def deferred(self):
        # A signal already swallowed by an earlier best-effort step must not cancel this.
        self.received.clear()
        self.deferring = True
        try:
            yield
        finally:
            self.deferring = False


def json_bytes(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def load_config(path: Path) -> dict:
    if not path.exists():
        return {
            "log": {"level": "info", "timestamp": True},
            "inbounds": [],
            "outbounds": [{"type": "direct", "tag": "out-direct"}],
            "route": {
                "rules": [{"ip_version": 6, "action": "reject"}],
                "final": "out-direct",
            },
        }
    try:
        value = json.loads(path.read_text())
    except (ValueError, OSError) as error:
        raise InstallError(f"无法读取 {path}，需要有效 JSON；原文件未修改。") from error
    if not isinstance(value, dict) or not isinstance(value.get("inbounds", []), list):
        raise InstallError("旧配置必须是 JSON 对象，inbounds 必须是数组。")
    if any(not isinstance(item, dict) for item in value.get("inbounds", [])):
        raise InstallError("旧配置包含无法识别的入站。")
    for section in ("route", "dns"):
        if section in value and not isinstance(value[section], dict):
            raise InstallError(f"旧配置的 {section} 必须是 JSON 对象。")
    for inbound in value.get("inbounds", []):
        tls = inbound.get("tls", {})
        if not isinstance(tls, dict) or not isinstance(tls.get("reality", {}), dict):
            raise InstallError("旧配置的 TLS/REALITY 格式无法识别。")
    return value


def validate_name(value: str) -> str:
    if not isinstance(value, str):
        raise InstallError("请输入有效 IP 或域名。")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        ascii_name = value.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise InstallError("请输入有效 IP 或域名。") from error
    labels = ascii_name.rstrip(".").split(".")
    if len(ascii_name) > 253 or any(
        not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in labels
    ):
        raise InstallError("请输入有效 IP 或域名，不要包含协议、端口或路径。")
    return ascii_name.rstrip(".")


def validate_port(value: str | int) -> int:
    try:
        port = int(value)
    except (ValueError, TypeError) as error:
        raise InstallError("端口必须是 1～65535 的整数。") from error
    if str(port) != str(value) or not 1 <= port <= 65535:
        raise InstallError("端口必须是 1～65535 的整数。")
    return port


def is_legacy(inbound: dict) -> bool:
    return inbound.get("type") == "vless" and bool(
        inbound.get("tls", {}).get("reality", {}).get("enabled")
    )


def prune_rule(rule: dict, removed_tags: set[str]) -> dict | None:
    """A removed inbound cannot match; never turn a narrow rule into a catch-all."""
    result = copy.deepcopy(rule)
    if result.get("type") == "logical":
        children = [prune_rule(child, removed_tags) for child in result["rules"]]
        if children == result["rules"]:
            return result
        if result.get("invert"):
            raise InstallError("旧配置的反向逻辑规则引用了待清理入站，请先保留旧配置。")
        if result.get("mode") == "and" and any(child is None for child in children):
            return None
        result["rules"] = [child for child in children if child is not None]
        return result if result["rules"] else None
    tags = result.get("inbound")
    if tags is None:
        return result
    tags = [tags] if isinstance(tags, str) else tags
    if not removed_tags.intersection(tags):
        return result
    if result.get("invert"):
        raise InstallError("旧配置的反向规则引用了待清理入站，请先保留旧配置。")
    remaining = [tag for tag in tags if tag not in removed_tags]
    if not remaining:
        return None
    result["inbound"] = remaining
    return result


def remove_legacy(config: dict) -> dict:
    result = copy.deepcopy(config)
    removed = {
        item["tag"] for item in result.get("inbounds", []) if is_legacy(item) and item.get("tag")
    }
    result["inbounds"] = [item for item in result.get("inbounds", []) if not is_legacy(item)]
    for section in ("route", "dns"):
        if "rules" in result.get(section, {}):
            rules = [prune_rule(rule, removed) for rule in result[section]["rules"]]
            result[section]["rules"] = [rule for rule in rules if rule is not None]
    return result


def choose_inbound(config: dict, prompt) -> tuple[dict, int | None]:
    candidates = [
        (index, item)
        for index, item in enumerate(config.get("inbounds", []))
        if item.get("type") == "hysteria2"
    ]
    if candidates:
        choice = prompt.choose(
            "发现多个 HY2 入站，请选择要管理的入站：",
            [
                f"{item.get('tag', '(无 tag)')} / UDP {item.get('listen_port', '?')}"
                for _, item in candidates
            ],
        )
        index, inbound = candidates[choice]
        return copy.deepcopy(inbound), index
    tags = {item.get("tag") for item in config.get("inbounds", [])}
    tag = "in-hy2-relay"
    while tag in tags:
        tag += "-new"
    return {
        "type": "hysteria2",
        "tag": tag,
        "listen": "0.0.0.0",
        "listen_port": 443,
        "users": [{"name": "HK-Relay"}],
        "tls": {"enabled": True},
        "bbr_profile": "standard",
    }, None


def public_certificate(path: Path) -> str:
    # Some existing PEM files combine certificates and private keys.
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----",
        path.read_text(),
    )
    if not blocks:
        raise InstallError("证书文件中没有可导出的 PEM 公有证书。")
    return "\n".join(blocks) + "\n"


def relay_report(address: str, inbound: dict, user: dict, certificate: str) -> str:
    details = [
        f"- 地址：`{address}`",
        f"- UDP 端口：`{inbound['listen_port']}`",
        f"- 密码：`{user['password']}`",
        f"- SNI：`{inbound['tls']['server_name']}`",
    ]
    for name, value in (inbound.get("obfs") or {}).items():
        details.append(f"- 混淆 {name}：`{value}`")
    alpn = inbound["tls"].get("alpn")
    if alpn:
        details.append(f"- ALPN：`{alpn if isinstance(alpn, str) else ', '.join(alpn)}`")
    return (
        "# HY2 上游对接信息\n\n"
        + "\n".join(details)
        + f"\n\n## 公有证书\n\n```pem\n{certificate.strip()}\n```\n"
    )


SERVICE = "sing-box.service"


@dataclass
class Layout:
    root: Path = Path("/")

    def at(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    @property
    def config(self) -> Path:
        return self.at("/etc/sing-box/config.json")

    @property
    def binary(self) -> Path:
        return self.at("/usr/local/bin/sing-box")

    @property
    def unit(self) -> Path:
        return self.at(f"/etc/systemd/system/{SERVICE}")

    @property
    def report(self) -> Path:
        return self.at("/etc/sing-box/relay-info.md")


@dataclass
class Service:
    exists: bool
    binary: Path
    config: Path
    cwd: Path
    base_dir: Path
    active: bool = False
    enabled: str = "disabled"
    uid: int = 0
    gid: int = 0
    main_pid: int = 0
    control_group: str = ""
    files: list[Path] = field(default_factory=list)


def parse_exec_start(unit_text: str, cwd: Path) -> tuple[Path, Path, Path]:
    section = ""
    commands = []
    for line in re.sub(r"\\\n\s*", " ", unit_text).splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
        elif section == "Service" and re.match(r"ExecStart\s*=", line):
            command = line.split("=", 1)[1].strip()
            if command:
                commands.append(command)
            else:
                commands.clear()
    if len(commands) != 1 or any(char in commands[0] for char in ("$", "%", "\x00", "\\")):
        raise InstallError(
            "无法安全识别 ExecStart（多命令、变量、转义或占位符），请先整理现有服务。"
        )
    try:
        args = shlex.split(commands[0])
    except ValueError as error:
        raise InstallError("ExecStart 引号格式无法识别。") from error
    if not args or not args[0].startswith("/") or Path(args[0]).name != "sing-box":
        raise InstallError("现有服务需要直接使用绝对路径启动 sing-box，暂不支持 shell 包装。")
    parser = argparse.ArgumentParser(add_help=False, exit_on_error=False, allow_abbrev=False)
    parser.add_argument("command", choices=["run"])
    parser.add_argument("-c", "--config", action="append", default=[])
    parser.add_argument("-C", "--config-directory", action="append", default=[])
    parser.add_argument("-D", "--directory")
    parser.add_argument("--disable-color", action="store_true")
    try:
        options, unknown = parser.parse_known_args(args[1:])
    except (argparse.ArgumentError, SystemExit) as error:
        raise InstallError("无法识别现有 sing-box 启动参数。") from error
    if unknown:
        raise InstallError("现有服务包含暂不支持的启动参数，请先整理现有服务。")
    base = Path(options.directory or cwd)
    if not base.is_absolute():
        base = cwd / base
    base = base.resolve()
    paths = [Path(path) if Path(path).is_absolute() else base / path for path in options.config]
    for directory in options.config_directory:
        directory = Path(directory)
        if not directory.is_absolute():
            directory = base / directory
        files = sorted(directory.glob("*.json"))
        paths.extend(files or [directory / "config.json"])
    if not paths:
        paths = [base / "config.json"]
    if len(paths) != 1:
        raise InstallError("检测到多文件/分片配置；请先合并为单个 JSON 文件再安装，原文件未修改。")
    return Path(args[0]), paths[0], base


def discover_service(runner: Runner, layout: Layout) -> Service:
    properties = (
        "LoadState,ActiveState,UnitFileState,MainPID,ControlGroup,User,Group,"
        "DynamicUser,RootDirectory,RootImage,WorkingDirectory,FragmentPath,DropInPaths,NeedDaemonReload"
    )
    result = runner.run(["systemctl", "show", SERVICE, f"--property={properties}"])
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    load_state = values.get("LoadState")
    if load_state == "not-found":
        if layout.unit.exists() or layout.unit.is_symlink():
            raise InstallError("服务文件已存在但 systemd 无法加载，请先检查服务文件。")
        return Service(False, layout.binary, layout.config, layout.root, layout.root)
    if load_state != "loaded":
        raise InstallError(f"现有服务状态为 {load_state}，请先解除屏蔽或修复服务。")
    if values.get("NeedDaemonReload") == "yes":
        raise InstallError("现有服务文件有尚未加载的变更，请先核对并运行 systemctl daemon-reload。")
    if values.get("UnitFileState") not in ("enabled", "enabled-runtime", "disabled"):
        raise InstallError("现有服务不是可正常 enable/disable 的常规服务，请先整理服务。")
    if values.get("ActiveState") not in ("active", "inactive", "failed"):
        raise InstallError("现有服务正在切换状态，请稍后重试。")
    if values.get("DynamicUser") == "yes" or values.get("RootDirectory") or values.get("RootImage"):
        raise InstallError("暂不支持 DynamicUser、RootDirectory 或 RootImage 服务。")
    cwd = Path(values.get("WorkingDirectory") or layout.root)
    if not cwd.is_absolute() or not cwd.is_dir():
        raise InstallError("无法识别现有服务的 WorkingDirectory。")
    text = runner.run(["systemctl", "cat", SERVICE]).stdout
    binary, config, base_dir = parse_exec_start(text, cwd)
    if not base_dir.is_dir():
        raise InstallError(f"现有服务工作目录不存在：{base_dir}")
    try:
        user = values.get("User") or "root"
        account = pwd.getpwuid(int(user)) if user.isdigit() else pwd.getpwnam(user)
        group = values.get("Group")
        gid = account.pw_gid
        if group:
            gid = int(group) if group.isdigit() else grp.getgrnam(group).gr_gid
    except KeyError as error:
        raise InstallError("现有服务的用户或组不存在。") from error
    files = shlex.split(values.get("DropInPaths", ""))
    if values.get("FragmentPath"):
        files.append(values["FragmentPath"])
    return Service(
        exists=True,
        binary=binary,
        config=config,
        cwd=cwd,
        base_dir=base_dir,
        active=values["ActiveState"] == "active",
        enabled=values["UnitFileState"],
        uid=account.pw_uid,
        gid=gid,
        main_pid=int(values.get("MainPID") or 0),
        control_group=values.get("ControlGroup", ""),
        files=[Path(path) for path in files],
    )


def process_belongs(pid: int, service: Service, proc: Path) -> bool:
    if not service.active or not pid:
        return False
    if pid == service.main_pid:
        return True
    if not service.control_group:
        return False
    try:
        groups = (proc / str(pid) / "cgroup").read_text().splitlines()
    except OSError:
        return False
    for line in groups:
        group = line.split(":", 2)[-1]
        if group == service.control_group or group.startswith(service.control_group + "/"):
            return True
    return False


def check_unmanaged_processes(service: Service, proc: Path) -> None:
    for item in proc.iterdir():
        if not item.name.isdigit():
            continue
        try:
            name = (item / "comm").read_text().strip()
        except OSError:
            continue
        if name == "sing-box" and not process_belongs(int(item.name), service, proc):
            raise InstallError(
                f"发现未由 {SERVICE} 管理的 sing-box（PID {item.name}），请先手动迁移或停止。"
            )


def check_port(
    runner: Runner, port: int, service: Service, proc: Path, *, required: bool = False
) -> bool:
    result = runner.run(["ss", "-H", "-lunp", f"sport = :{port}"])
    lines = result.stdout.strip().splitlines()
    if not lines:
        return not required
    for line in lines:
        pids = [int(pid) for pid in re.findall(r"pid=(\d+)", line)]
        if not pids or any(not process_belongs(pid, service, proc) for pid in pids):
            raise InstallError(f"UDP {port} 被当前 sing-box 服务以外的进程占用，原配置未覆盖。")
    return True


@dataclass
class Change:
    path: Path
    source: Path | None
    mode: int = 0o600
    uid: int = 0
    gid: int = 0


def atomic_copy(source: Path, target: Path, mode: int, uid: int, gid: int) -> None:
    descriptor, name = tempfile.mkstemp(prefix=".auto-proxy-", dir=target.parent)
    temp = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream, source.open("rb") as incoming:
            shutil.copyfileobj(incoming, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temp, uid, gid)
        os.chmod(temp, mode)
        os.replace(temp, target)
        descriptor = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temp.unlink(missing_ok=True)


class Transaction:
    def __init__(self, backup_root: Path, service: Service):
        self.service = service
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.backup = backup_root / f"{stamp}-{secrets.token_hex(4)}"
        self.records: dict[Path, dict] = {}
        self.applied: list[Change] = []
        self.created_dirs: list[Path] = []
        self.status = "prepared"
        self.extra: dict = {}

    def manifest(self) -> None:
        content = {
            "status": self.status,
            "service": {
                "existed": self.service.exists,
                "active": self.service.active,
                "enabled": self.service.enabled,
            },
            "files": list(self.records.values()),
            "created_directories": [str(path) for path in self.created_dirs],
            **self.extra,
        }
        path = self.backup / "manifest.json"
        path.write_bytes(json_bytes(content))
        path.chmod(0o600)

    def prepare(self, changes: list[Change], watched: list[Path]) -> None:
        self.backup.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.backup.parent.chmod(0o700)
        self.backup.mkdir(mode=0o700)
        for index, path in enumerate(dict.fromkeys([change.path for change in changes] + watched)):
            path = path.resolve()
            if path in self.records:
                continue
            record = {"path": str(path), "existed": path.exists()}
            if path.exists():
                info = path.stat()
                if not stat.S_ISREG(info.st_mode):
                    raise InstallError(f"目标不是普通文件：{path}")
                snapshot = f"{index:03d}.bak"
                shutil.copy2(path, self.backup / snapshot)
                (self.backup / snapshot).chmod(0o600)
                record.update(
                    snapshot=snapshot,
                    mode=stat.S_IMODE(info.st_mode),
                    uid=info.st_uid,
                    gid=info.st_gid,
                )
            self.records[path] = record
        self.manifest()

    def ensure_parent(self, path: Path) -> None:
        missing = []
        parent = path.parent
        while not parent.exists():
            missing.append(parent)
            parent = parent.parent
        for directory in reversed(missing):
            directory.mkdir(mode=0o755)
            directory.chmod(0o755)
            self.created_dirs.append(directory)

    def apply(self, changes: list[Change]) -> None:
        self.status = "applying"
        self.manifest()
        for change in changes:
            self.applied.append(change)
            self.ensure_parent(change.path)
            self.manifest()
            if change.source is None:
                change.path.unlink(missing_ok=True)
            else:
                atomic_copy(change.source, change.path, change.mode, change.uid, change.gid)

    def restore(self) -> list[str]:
        errors = []
        for change in reversed(self.applied):
            record = self.records[change.path]
            try:
                if record["existed"]:
                    atomic_copy(
                        self.backup / record["snapshot"],
                        change.path,
                        record["mode"],
                        record["uid"],
                        record["gid"],
                    )
                else:
                    change.path.unlink(missing_ok=True)
            except OSError as error:
                errors.append(f"恢复 {change.path} 失败：{error}")
        for directory in reversed(self.created_dirs):
            try:
                directory.rmdir()
            except OSError:
                pass  # Keep directories if the service created runtime files there.
        return errors


RELEASE_API = "https://api.github.com/repos/SagerNet/sing-box/releases/tags/"
RELEASE_DOWNLOAD = "https://github.com/SagerNet/sing-box/releases/download/"


def fetch(runner: Runner, url: str, destination: Path, *, metadata: bool = False) -> None:
    args = [
        "curl",
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--connect-timeout",
        "10",
        "--max-time",
        "180",
        "--retry",
        "3",
        "--retry-delay",
        "2",
        "--retry-all-errors",
        "--user-agent",
        "auto-proxy-installer",
        "--output",
        str(destination),
    ]
    if metadata:
        args.extend(["--header", "Accept: application/vnd.github+json"])
    runner.run(args + [url], timeout=780)


def binary_version(binary: Path, runner: Runner) -> str | None:
    if not binary.is_file() or not os.access(binary, os.X_OK):
        return None
    try:
        result = runner.run([str(binary), "version"], check=False, timeout=10)
    except InstallError:
        return None
    match = re.search(r"^sing-box version (\S+)", result.stdout, re.MULTILINE)
    return match[1] if result.returncode == 0 and match else None


def prepare_binary(runner: Runner, service: Service, architecture: str, stage: Path) -> Path:
    candidates = [service.binary]
    found = shutil.which("sing-box")
    if found:
        candidates.append(Path(found))
    for candidate in dict.fromkeys(candidates):
        if binary_version(candidate, runner) == SING_BOX_VERSION:
            say(f"复用已有 sing-box {SING_BOX_VERSION}：{candidate}")
            return candidate.resolve()
    say(f"下载并校验 sing-box {SING_BOX_VERSION} / {architecture}…")
    metadata = stage / "release.json"
    fetch(runner, RELEASE_API + "v" + SING_BOX_VERSION, metadata, metadata=True)
    try:
        release = json.loads(metadata.read_text())
        filename = f"sing-box-{SING_BOX_VERSION}-linux-{architecture}.tar.gz"
        matches = [asset for asset in release["assets"] if asset["name"] == filename]
        if release["tag_name"] != "v" + SING_BOX_VERSION or len(matches) != 1:
            raise ValueError("release/asset mismatch")
        digest = matches[0].get("digest", "")
        if not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest or ""):
            raise ValueError("missing SHA-256 digest")
    except (ValueError, KeyError, TypeError) as error:
        raise InstallError("官方发布信息缺少目标安装包或 SHA-256，已停止安装。") from error
    archive = stage / filename
    fetch(runner, f"{RELEASE_DOWNLOAD}v{SING_BOX_VERSION}/{filename}", archive)
    checksum = hashlib.sha256()
    with archive.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    if checksum.hexdigest() != digest.split(":", 1)[1].lower():
        raise InstallError("下载包 SHA-256 校验失败，原安装未修改。")
    binary = stage / "sing-box"
    try:
        with tarfile.open(archive, "r:gz") as package:
            members = [member for member in package if Path(member.name).name == "sing-box"]
            if (
                len(members) != 1
                or not members[0].isfile()
                or not 0 < members[0].size <= 300_000_000
            ):
                raise ValueError("invalid binary member")
            # Copy only the binary; archive paths and links are never extracted.
            incoming = package.extractfile(members[0])
            if incoming is None:
                raise ValueError("binary missing")
            with incoming, binary.open("wb") as output:
                shutil.copyfileobj(incoming, output)
    except (tarfile.TarError, ValueError) as error:
        raise InstallError("安装包格式不正确，原安装未修改。") from error
    binary.chmod(0o755)
    if binary_version(binary, runner) != SING_BOX_VERSION:
        raise InstallError("安装包程序版本与目标版本不一致。")
    return binary


def validate_credentials(runner: Runner, certificate: Path, key: Path, sni: str) -> None:
    if not certificate.is_file() or not key.is_file():
        raise InstallError("证书或私钥文件缺失。")
    extension = runner.run(
        [
            "openssl",
            "x509",
            "-in",
            str(certificate),
            "-noout",
            "-ext",
            "subjectAltName",
        ]
    ).stdout
    if not re.search(r"DNS:|IP Address:", extension):
        raise InstallError("证书缺少 SAN 名称，无法用于正常 TLS 名称校验。")
    try:
        ipaddress.ip_address(sni)
        flag = "-verify_ip"
    except ValueError:
        flag = "-verify_hostname"
    runner.run(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(certificate),
            "-partial_chain",
            "-purpose",
            "sslserver",
            flag,
            sni,
            str(certificate),
        ]
    )
    public_cert = runner.run(
        ["openssl", "x509", "-in", str(certificate), "-noout", "-pubkey"]
    ).stdout
    public_key = runner.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(key),
            "-passin",
            "pass:",
            "-pubout",
        ]
    ).stdout
    if public_cert.strip() != public_key.strip():
        raise InstallError("证书和私钥不匹配。")


def generate_credentials(runner: Runner, stage: Path, sni: str) -> tuple[Path, Path]:
    certificate, key = stage / "hy2.crt", stage / "hy2.key"
    try:
        ipaddress.ip_address(sni)
        san = f"IP:{sni}"
    except ValueError:
        san = f"DNS:{sni}"
    runner.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-days",
            "3650",
            "-subj",
            f"/CN={sni}",
            "-addext",
            f"subjectAltName={san}",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
        ]
    )
    certificate.chmod(0o600)
    key.chmod(0o600)
    validate_credentials(runner, certificate, key, sni)
    return certificate, key


def credential_path(value: str | None, base: Path) -> Path | None:
    if not value or not isinstance(value, str):
        return None
    path = Path(value)
    return (path if path.is_absolute() else base / path).resolve()


def managed_unit(binary: Path, config: Path) -> str:
    def quote(path: Path) -> str:
        return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'

    return (
        "[Unit]\nDescription=sing-box HY2 upstream\nAfter=network-online.target\n"
        "Wants=network-online.target\n\n[Service]\nType=exec\nUser=root\n"
        f"ExecStart={quote(binary)} run -c {quote(config)}\n"
        "Restart=on-failure\nRestartSec=2\nTimeoutStartSec=30\nTimeoutStopSec=30\n"
        "LimitNOFILE=1048576\n\n[Install]\nWantedBy=multi-user.target\n"
    )


BBR_FILE = "/etc/sysctl.d/99-zz-auto-proxy-bbr.conf"  # sorts after 99-sysctl.conf
BBR_SETTINGS = {"net.core.default_qdisc": "fq", "net.ipv4.tcp_congestion_control": "bbr"}
BBR_CONF = (
    "# Managed by auto_proxy bash.sh: kernel TCP BBR. HY2 runs over UDP and is unaffected.\n"
    "# Delete this file to undo after the next reboot.\n"
    + "".join(f"{key} = {value}\n" for key, value in BBR_SETTINGS.items())
)
# Read by systemd-sysctl at boot. Debian 13 no longer reads /etc/sysctl.conf unless a
# file here links to it, as 99-sysctl.conf still does on Debian 12 and Ubuntu.
SYSCTL_DIRS = (
    "/etc/sysctl.d",
    "/run/sysctl.d",
    "/usr/local/lib/sysctl.d",
    "/usr/lib/sysctl.d",
    "/lib/sysctl.d",
)
VENDOR_SYSCTL_DIRS = ("/usr/lib/sysctl.d", "/lib/sysctl.d")


def proc_sys(layout: Layout, key: str) -> Path:
    return layout.at("/proc/sys/" + key.replace(".", "/"))


def boot_sysctl(layout: Layout, skip: Path | None = None) -> dict[str, tuple[str, Path]]:
    """The value systemd-sysctl applies at boot for each BBR key, and the file setting it."""
    files: dict[str, Path] = {}
    for directory in SYSCTL_DIRS:
        folder = layout.at(directory)
        if folder.is_dir():
            for path in folder.glob("*.conf"):
                files.setdefault(path.name, path)  # /etc overrides /run, which overrides /usr
    found = {}
    for name in sorted(files):  # the latest name wins, whichever directory it is in
        if files[name] == skip:
            continue
        try:
            lines = files[name].read_text(errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line or line.startswith(("#", ";")) or "=" not in line:
                continue
            pattern, value = (part.strip() for part in line.split("=", 1))
            pattern = pattern.lstrip("-").replace("/", ".")
            for key in BBR_SETTINGS:
                if fnmatch.fnmatchcase(key, pattern):
                    found[key] = (value, files[name])
    return found


def detect_container(runner: Runner) -> str:
    try:
        result = runner.run(["systemd-detect-virt", "--container"], check=False)
    except InstallError:
        return ""
    name = result.stdout.strip()
    return name if result.returncode == 0 and name != "none" else ""


def bbr_supported(runner: Runner, available: list[str]) -> bool:
    if "bbr" in available:
        return True
    try:
        return runner.run(["modprobe", "-n", "-q", "tcp_bbr"], check=False).returncode == 0
    except InstallError:
        return False


class Installer:
    def __init__(
        self,
        runner: Runner | None = None,
        prompt: Prompt | None = None,
        layout: Layout | None = None,
        signals: SignalGuard | None = None,
    ):
        self.runner = runner or Runner()
        self.prompt = prompt or Prompt()
        self.layout = layout or Layout()
        self.signals = signals or SignalGuard()

    def command_check(self, binary: Path, config: Path, service: Service) -> None:
        self.runner.run(
            [
                str(binary),
                "check",
                "-c",
                str(config),
                "-D",
                str(service.base_dir),
                "--disable-color",
            ],
            cwd=service.cwd,
        )

    def address(self, default: str | None) -> str:
        if not default:
            try:
                result = self.runner.run(
                    [
                        "curl",
                        "-4",
                        "--fail",
                        "--silent",
                        "--show-error",
                        "--proto",
                        "=https",
                        "--connect-timeout",
                        "3",
                        "--max-time",
                        "8",
                        "https://api.ipify.org",
                    ],
                    timeout=10,
                )
                default = str(ipaddress.IPv4Address(result.stdout.strip()))
            except (InstallError, ValueError):
                say("无法自动探测公网 IPv4，请手动输入中转机使用的地址。")
        while True:
            try:
                return validate_name(self.prompt.ask("确认上游公网 IP 或域名", default or ""))
            except InstallError as error:
                say(error)

    def credentials(
        self,
        inbound: dict,
        service: Service,
        stage: Path,
        sni: str,
    ) -> tuple[dict, Path, Path, bool, list[Path]]:
        users = inbound.get("users", [])
        if not isinstance(users, list) or any(not isinstance(user, dict) for user in users):
            raise InstallError("旧 HY2 users 格式无法识别，原配置未修改。")
        if not users:
            users = [{"name": "HK-Relay"}]
            inbound["users"] = users
        choice = self.prompt.choose(
            "请选择需要复用或更新密码的 HY2 用户：",
            [str(user.get("name") or f"用户 {index + 1}") for index, user in enumerate(users)],
        )
        user = users[choice]
        tls = inbound.setdefault("tls", {})
        certificate = credential_path(tls.get("certificate_path"), service.base_dir)
        key = credential_path(tls.get("key_path"), service.base_dir)
        watched = [path for path in (certificate, key) if path is not None]
        valid = False
        if user.get("password") and isinstance(user["password"], str) and certificate and key:
            try:
                if any(ord(char) < 32 or ord(char) == 127 for char in user["password"]):
                    raise InstallError("旧密码包含控制字符，无法安全导出。")
                validate_credentials(self.runner, certificate, key, sni)
                valid = True
            except InstallError as error:
                say(f"旧凭据无法复用：{error}")
        elif certificate or key or user.get("password"):
            say("旧 HY2 密码、证书或私钥不完整，不能整套复用。")
        if valid and self.prompt.confirm("复用已有 HY2 密码和证书？"):
            tls.update(
                enabled=True, server_name=sni, certificate_path=str(certificate), key_path=str(key)
            )
            return user, certificate, key, True, watched
        if watched or user.get("password"):
            if len(users) > 1:
                say("更换此入站证书会影响该入站的所有用户；其他用户的密码会保留。")
            if not self.prompt.confirm("生成新密码和自签名证书？中转机需要同步更新。"):
                raise InstallError("已取消凭据更新。")
        certificate, key = generate_credentials(self.runner, stage, sni)
        user["password"] = secrets.token_hex(32)
        for tls_field in ("certificate", "key", "acme", "certificate_provider"):
            tls.pop(tls_field, None)
        tls.update(enabled=True, server_name=sni)
        return user, certificate, key, False, watched

    def runtime_service(self, service: Service) -> Service:
        result = self.runner.run(
            [
                "systemctl",
                "show",
                SERVICE,
                "--property=ActiveState,MainPID,ControlGroup",
            ]
        )
        values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        return replace(
            service,
            active=values.get("ActiveState") == "active",
            main_pid=int(values.get("MainPID") or 0),
            control_group=values.get("ControlGroup", ""),
        )

    def wait_ready(self, service: Service, port: int) -> None:
        stable = 0
        for _ in range(20):
            current = self.runtime_service(service)
            listening = current.active and check_port(
                self.runner,
                port,
                current,
                self.layout.at("/proc"),
                required=True,
            )
            stable = stable + 1 if listening else 0
            if stable == 3:
                say("本机检查通过：配置有效，服务运行中，HY2 UDP 端口由该服务监听。")
                return
            time.sleep(0.5)
        raise InstallError("服务未能持续运行并监听目标 UDP 端口。")

    def rollback(
        self,
        transaction: Transaction,
        service: Service,
        touched_service: bool,
        enabling_attempted: bool,
    ) -> list[str]:
        errors = []

        def attempt(args: list[str]) -> None:
            try:
                self.runner.run(["systemctl", *args])
            except InstallError as error:
                errors.append(str(error))

        if touched_service:
            attempt(["stop", SERVICE])
        if enabling_attempted and service.enabled != "enabled":
            attempt(["disable", SERVICE])
        errors.extend(transaction.restore())
        if touched_service:
            attempt(["daemon-reload"])
            if enabling_attempted:
                if service.enabled == "enabled":
                    attempt(["enable", SERVICE])
                elif service.enabled == "enabled-runtime":
                    attempt(["enable", "--runtime", SERVICE])
            if service.active:
                attempt(["restart", SERVICE])
                try:
                    if not self.runtime_service(service).active:
                        errors.append("原服务恢复后未处于运行状态。")
                except InstallError as error:
                    errors.append(str(error))
        transaction.status = "rollback-incomplete" if errors else "rolled-back"
        try:
            transaction.manifest()
        except OSError as error:
            errors.append(f"回滚状态记录失败：{error}")
        return errors

    def plan_bbr(self) -> bool:
        """Ask before deploying, so nothing after the deployment waits for the terminal."""
        try:
            current = {key: proc_sys(self.layout, key).read_text().strip() for key in BBR_SETTINGS}
            available = proc_sys(self.layout, "net.ipv4.tcp_available_congestion_control")
            choices = available.read_text().split()
        except OSError:
            say("读取不到内核网络参数，跳过系统 BBR。")
            return False
        boot = {key: value for key, (value, _) in boot_sysctl(self.layout).items()}
        if current == BBR_SETTINGS and boot == BBR_SETTINGS:
            say("系统 TCP BBR 已开启，保持不变。")
            return False
        container = detect_container(self.runner)
        if container:
            say(f"容器环境（{container}）的内核参数归宿主机管，跳过系统 BBR。")
            return False
        if not bbr_supported(self.runner, choices):
            say("当前内核没有 BBR 模块，跳过系统 BBR。")
            return False
        vendor = {self.layout.at(directory) for directory in VENDOR_SYSCTL_DIRS}
        conflicts = [
            f"  {path}：{key} = {value}"
            for key, (value, path) in boot_sysctl(self.layout, self.layout.at(BBR_FILE)).items()
            if value != BBR_SETTINGS[key] and path.parent not in vendor
        ]
        if conflicts:
            say("现有配置里设了别的值，开启后会被覆盖：\n" + "\n".join(conflicts))
        return self.prompt.confirm(
            "开启系统 TCP BBR？只影响本机 TCP，HY2 走 UDP 不受影响", not conflicts
        )

    def apply_bbr(self, transaction: Transaction, stage: Path) -> None:
        """Best effort: a BBR problem never rolls back the committed sing-box install."""
        if self.signals.stop_requested:
            say("收到中断信号，跳过系统 BBR。")
            return
        target = self.layout.at(BBR_FILE)
        existed = target.exists()
        previous: dict[str, str] = {}
        try:
            for key, value in BBR_SETTINGS.items():
                path = proc_sys(self.layout, key)
                previous[key] = path.read_text().strip()
                path.write_text(value + "\n")
                if path.read_text().strip() != value:
                    raise InstallError(f"{key} 写入后没有生效")
            source = stage / "bbr.conf"
            source.write_text(BBR_CONF)
            if not target.parent.is_dir():
                target.parent.mkdir(parents=True)
                target.parent.chmod(0o755)
            atomic_copy(source, target, 0o644, 0, 0)
        except (InstallError, OSError) as error:
            for key, value in previous.items():
                with contextlib.suppress(OSError):
                    proc_sys(self.layout, key).write_text(value + "\n")
            if not existed:
                with contextlib.suppress(OSError):
                    target.unlink(missing_ok=True)
            say(f"系统 BBR 没开成，已恢复原设置：{error}")
            return
        undo = f"rm {BBR_FILE} && sysctl -w " + " ".join(
            f"{key}={value}" for key, value in previous.items()
        )
        transaction.extra["bbr"] = {"file": str(target), "previous": previous, "undo": undo}
        with contextlib.suppress(OSError):
            transaction.manifest()
        say("系统 TCP BBR 已开启，新连接立即生效；fq 队列重启后才会用到现有网卡上。")
        say(f"撤销命令：{undo}")
        for key, (value, path) in boot_sysctl(self.layout).items():
            if value != BBR_SETTINGS[key]:
                say(f"注意：{path} 排在后面，重启后 {key} 会变成 {value}。")

    def install(self, options: argparse.Namespace, architecture: str) -> Path:
        service = discover_service(self.runner, self.layout)
        check_unmanaged_processes(service, self.layout.at("/proc"))
        if service.active and not service.config.is_file():
            raise InstallError("正在运行的服务配置文件缺失，无法安全保留现有配置。")
        config = load_config(service.config)
        legacy_files = [service.config.parent / name for name in ("keypair.txt", "uuid.txt")]
        cleanup = False
        if any(is_legacy(item) for item in config.get("inbounds", [])) or any(
            path.exists() for path in legacy_files
        ):
            cleanup = self.prompt.confirm(
                "检测到旧 VLESS/REALITY 或 keypair.txt、uuid.txt，清理这些内容？", False
            )
            if cleanup:
                config = remove_legacy(config)
        inbound, inbound_index = choose_inbound(config, self.prompt)
        default_port = options.port if options.port is not None else inbound.get("listen_port", 443)
        port = validate_port(self.prompt.ask("确认 HY2 UDP 端口", str(default_port)))
        inbound["listen_port"] = port
        sni = validate_name(
            options.sni or inbound.get("tls", {}).get("server_name") or "hy2.internal"
        )
        check_port(self.runner, port, service, self.layout.at("/proc"))
        address = self.address(options.address)
        with tempfile.TemporaryDirectory(prefix="auto-proxy-") as directory:
            stage = Path(directory)
            binary = prepare_binary(self.runner, service, architecture, stage)
            user, certificate, key, reuse, watched = self.credentials(inbound, service, stage, sni)
            bbr = self.plan_bbr()
            changes = []
            if not reuse:
                target_cert, target_key = (
                    service.config.parent / "hy2.crt",
                    service.config.parent / "hy2.key",
                )
                if (
                    target_cert.exists()
                    or target_key.exists()
                    or target_cert.is_symlink()
                    or target_key.is_symlink()
                ):
                    stem = "hy2-" + secrets.token_hex(6)
                    target_cert, target_key = (
                        service.config.parent / f"{stem}.crt",
                        service.config.parent / f"{stem}.key",
                    )
                inbound["tls"].update(certificate_path=str(target_cert), key_path=str(target_key))
                changes.extend(
                    [
                        Change(target_cert, certificate, uid=service.uid, gid=service.gid),
                        Change(target_key, key, uid=service.uid, gid=service.gid),
                    ]
                )
            if inbound_index is None:
                config.setdefault("inbounds", []).append(inbound)
            else:
                config["inbounds"][inbound_index] = inbound
            staged_config = copy.deepcopy(config)
            staged_inbound = staged_config["inbounds"][
                inbound_index if inbound_index is not None else -1
            ]
            staged_inbound["tls"].update(certificate_path=str(certificate), key_path=str(key))
            validation_file = stage / "validate.json"
            validation_file.write_bytes(json_bytes(staged_config))
            self.command_check(binary, validation_file, service)
            say("临时配置检查通过，准备备份并应用。")
            config_file = stage / "config.json"
            config_file.write_bytes(json_bytes(config))
            changes.append(Change(service.config, config_file, uid=service.uid, gid=service.gid))
            if binary.resolve() != service.binary.resolve():
                changes.insert(0, Change(service.binary, binary, 0o755))
            if not service.exists:
                unit = stage / SERVICE
                unit.write_text(managed_unit(service.binary, service.config))
                changes.append(Change(self.layout.unit, unit, 0o644))
            report = stage / "relay-info.md"
            report.write_text(relay_report(address, inbound, user, public_certificate(certificate)))
            changes.append(Change(self.layout.report, report))
            if cleanup:
                serialized = json.dumps(config)
                for path in legacy_files:
                    if path.exists():
                        if path.name in serialized:
                            raise InstallError(f"配置仍引用 {path.name}，请先保留旧文件。")
                        changes.append(Change(path, None))
            for change in changes:
                change.path = change.path.resolve()
            if len({change.path for change in changes}) != len(changes):
                raise InstallError("配置、证书或输出路径发生冲突，已停止安装。")
            transaction = Transaction(self.layout.at("/var/backups/auto-proxy"), service)
            transaction.prepare(changes, [service.config, service.binary, *service.files, *watched])
            touched_service = False
            enabling_attempted = False
            # From here on nothing waits for the terminal; signals wait for a checkpoint.
            with self.signals.deferred():
                try:
                    transaction.apply(changes)
                    self.command_check(service.binary, service.config, service)
                    self.signals.checkpoint()
                    touched_service = True
                    self.runner.run(["systemctl", "daemon-reload"])
                    self.runner.run(["systemctl", "restart", SERVICE])
                    self.wait_ready(service, port)
                    if service.enabled != "enabled":
                        enabling_attempted = True
                        self.runner.run(["systemctl", "enable", SERVICE])
                    enabled = self.runner.run(["systemctl", "is-enabled", SERVICE]).stdout.strip()
                    if enabled != "enabled":
                        raise InstallError("未能确认服务已设置为持久开机自启。")
                    self.signals.checkpoint()
                    transaction.status = "committed"
                    transaction.manifest()
                except BaseException as error:
                    say("安装未完成，正在恢复原文件和服务状态…", file=sys.stderr)
                    failures = self.rollback(
                        transaction, service, touched_service, enabling_attempted
                    )
                    if failures:
                        raise InstallError(
                            f"{error}\n回滚未完整完成，备份位于 {transaction.backup}\n"
                            + "\n".join(failures)
                        ) from error
                    raise InstallError(
                        f"{error}\n已回滚本次部署变更；备份位于 {transaction.backup}"
                    ) from error
                if bbr:
                    self.apply_bbr(transaction, stage)
                say(
                    f"\n安装完成，sing-box {SING_BOX_VERSION} 已设置开机自启。"
                    f"备份：{transaction.backup}"
                )
                say(f"对接文件：{self.layout.report}（0600）\n")
                say(report.read_text())
            return transaction.backup


def preflight(layout: Layout, runner: Runner) -> str:
    if os.geteuid() != 0:
        raise InstallError("请使用 sudo bash bash.sh 运行。")
    if platform.system() != "Linux":
        raise InstallError("仅支持 Linux Debian/Ubuntu。")
    release = layout.at("/etc/os-release").read_text()
    match = re.search(r'^ID=["\']?([^"\'\n]+)', release, re.MULTILINE)
    if not match or match[1] not in ("debian", "ubuntu"):
        raise InstallError("仅支持 Debian/Ubuntu。")
    architectures = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
    architecture = architectures.get(platform.machine())
    if not architecture:
        raise InstallError("仅支持 amd64/arm64。")
    if not layout.at("/run/systemd/system").is_dir():
        raise InstallError("需要正在运行的 systemd。")
    for dependency in ("curl", "openssl", "ss", "systemctl"):
        if not shutil.which(dependency):
            raise InstallError(f"缺少 {dependency}，请通过 bash.sh 安装依赖。")
    runner.run(["systemctl", "show", "--property=Version", "--value"])
    return architecture


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="bash.sh", description=f"交互部署 sing-box {SING_BOX_VERSION} HY2 上游代理"
    )
    parser.add_argument("--address", help="中转机连接的公网 IP 或域名，仍需交互确认")
    parser.add_argument("--port", type=int, help="HY2 UDP 端口；默认保留旧端口，新装使用 443")
    parser.add_argument("--sni", help="证书名称；默认保留旧名称，新装使用 hy2.internal")
    options = parser.parse_args(argv)
    signals = SignalGuard()
    try:
        if options.address:
            validate_name(options.address)
        if options.port is not None:
            validate_port(options.port)
        if options.sni:
            validate_name(options.sni)
        if not sys.stdin.isatty():
            raise InstallError("需要交互确认，请在终端中运行 bash.sh。")
        layout, runner = Layout(), Runner()
        architecture = preflight(layout, runner)
        lock_path = layout.at("/run/lock/auto-proxy.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise InstallError("已有安装进程正在运行，请稍后重试。") from error
            os.umask(0o077)
            signals.install()
            say(f"当前目标版本：sing-box {SING_BOX_VERSION}；架构：{architecture}")
            Installer(runner=runner, layout=layout, signals=signals).install(options, architecture)
    except (InstallError, OSError, ValueError) as error:
        say(f"安装失败：{error}", file=sys.stderr)
        return 1
    finally:
        signals.restore()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
AUTO_PROXY_PYTHON
