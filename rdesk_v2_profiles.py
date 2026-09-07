"""Separated role/mode profile storage for the rdesk V2 launcher."""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Union

from rdesk_v2_core import (
    DEFAULT_CONTROL_PORT,
    DEFAULT_RELAY_HOST,
    DEFAULT_SIGNAL_PORT,
    AppSettings,
    ClientSettings,
    HostSettings,
    config_path,
    load_settings,
)


MODE_MUTUAL = "mutual"
MODE_DIRECT = "direct"
MODE_RENDEZVOUS = "rendezvous"
CONNECTION_MODES = (MODE_MUTUAL, MODE_DIRECT, MODE_RENDEZVOUS)
MODE_LABELS = {
    MODE_MUTUAL: "双方地址互认",
    MODE_DIRECT: "控制端填写被控端",
    MODE_RENDEZVOUS: "密钥会合直连",
}
MODE_DESCRIPTIONS = {
    MODE_MUTUAL: "双方明确配置地址和端口；被控端可限制允许的控制端 IP。",
    MODE_DIRECT: "被控端只监听；控制端填写被控端 IPv4/IPv6、端口和密钥。",
    MODE_RENDEZVOUS: "双方只需相同房间与密钥；服务器只交换地址，媒体禁止 TURN。",
}

DEFAULT_RENDEZVOUS_HOST = DEFAULT_RELAY_HOST
DEFAULT_RENDEZVOUS_PORT = 45030


@dataclass
class ConnectionOptions:
    peer_host: str = "127.0.0.1"
    peer_signal_port: int = DEFAULT_SIGNAL_PORT
    peer_control_port: int = DEFAULT_CONTROL_PORT
    server_host: str = DEFAULT_RENDEZVOUS_HOST
    server_port: int = DEFAULT_RENDEZVOUS_PORT
    room: str = "default"
    local_udp_port: int = 0

    def validate(self, role: str, mode: str) -> None:
        if role not in ("host", "client"):
            raise ValueError("角色必须是 host 或 client")
        if mode not in CONNECTION_MODES:
            raise ValueError("未知连接方式")
        if mode in (MODE_MUTUAL, MODE_DIRECT) and role == "client":
            if not self.peer_host.strip():
                raise ValueError("被控端地址不能为空")
            _validate_port(self.peer_signal_port)
            _validate_port(self.peer_control_port)
        if mode == MODE_MUTUAL and role == "host" and not self.peer_host.strip():
            raise ValueError("双方地址互认模式需要填写允许的控制端 IP")
        if mode == MODE_RENDEZVOUS:
            if not self.server_host.strip():
                raise ValueError("会合服务器地址不能为空")
            _validate_port(self.server_port)
            if not self.room.strip():
                raise ValueError("会合房间名不能为空")
            if not 0 <= int(self.local_udp_port) <= 65535:
                raise ValueError("本地 UDP 端口必须是 0-65535")


RuntimeSettings = Union[HostSettings, ClientSettings]


@dataclass
class RoleProfile:
    role: str
    mode: str
    name: str
    connection: ConnectionOptions
    runtime: RuntimeSettings

    def validate(self) -> None:
        validate_profile_name(self.name)
        expected = HostSettings if self.role == "host" else ClientSettings
        if not isinstance(self.runtime, expected):
            raise ValueError("配置角色与运行参数不匹配")
        self.runtime.validate()
        self.connection.validate(self.role, self.mode)

    def effective_runtime(self) -> RuntimeSettings:
        """Return a copy with transport-specific values applied."""
        runtime = type(self.runtime)(**asdict(self.runtime))
        runtime.turn_server = ""
        runtime.native_interfaces_only = True
        if self.role == "host":
            runtime.allowed_peer = (
                self.connection.peer_host.strip() if self.mode == MODE_MUTUAL else ""
            )
        if self.role == "client" and self.mode in (MODE_MUTUAL, MODE_DIRECT):
            runtime.peer = self.connection.peer_host.strip()
            runtime.signal_port = int(self.connection.peer_signal_port)
            runtime.control_port = int(self.connection.peer_control_port)
        return runtime


def validate_profile_name(name: str) -> str:
    clean = name.strip()
    if not clean or not re.fullmatch(r"[A-Za-z0-9_-]+", clean):
        raise ValueError("配置版本名称只能包含字母、数字、- 和 _")
    return clean


def _validate_port(value: int) -> None:
    if not 1 <= int(value) <= 65535:
        raise ValueError("端口必须是 1-65535")


def _load_dataclass(cls, values):
    instance = cls()
    if not isinstance(values, dict):
        return instance
    allowed = {field.name for field in fields(instance)}
    for key, value in values.items():
        if key in allowed:
            setattr(instance, key, value)
    return instance


class ProfileRepository:
    """Store every role/mode profile in its own JSON file."""

    def __init__(self, root: Path | None = None):
        self.root = root or config_path().parent / "connections"

    def directory(self, role: str, mode: str) -> Path:
        if role not in ("host", "client") or mode not in CONNECTION_MODES:
            raise ValueError("无效的角色或连接方式")
        return self.root / role / mode

    def path(self, role: str, mode: str, name: str) -> Path:
        return self.directory(role, mode) / (validate_profile_name(name) + ".json")

    def names(self, role: str, mode: str):
        directory = self.directory(role, mode)
        names = ["default"]
        if directory.exists():
            names.extend(path.stem for path in directory.glob("*.json"))
        return sorted(set(names))

    def defaults(self, role: str, mode: str, name: str = "default") -> RoleProfile:
        legacy: AppSettings = load_settings()
        runtime = legacy.host if role == "host" else legacy.client
        connection = ConnectionOptions(
            peer_host=legacy.client.peer,
            peer_signal_port=legacy.client.signal_port,
            peer_control_port=legacy.client.control_port,
        )
        if role == "host" and mode == MODE_MUTUAL:
            connection.peer_host = "127.0.0.1"
        return RoleProfile(role, mode, name, connection, runtime)

    def load(self, role: str, mode: str, name: str) -> RoleProfile:
        path = self.path(role, mode, name)
        try:
            values = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return self.defaults(role, mode, name)
        runtime_cls = HostSettings if role == "host" else ClientSettings
        return RoleProfile(
            role=role,
            mode=mode,
            name=name,
            connection=_load_dataclass(ConnectionOptions, values.get("connection")),
            runtime=_load_dataclass(runtime_cls, values.get("runtime")),
        )

    def save(self, profile: RoleProfile) -> Path:
        profile.validate()
        path = self.path(profile.role, profile.mode, profile.name)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "role": profile.role,
            "mode": profile.mode,
            "name": profile.name,
            "connection": asdict(profile.connection),
            "runtime": asdict(profile.runtime),
        }
        temporary = path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        os.replace(temporary, path)
        if os.name != "nt":
            os.chmod(path, 0o600)
        return path
