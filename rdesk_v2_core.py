"""Transport, authentication and configuration helpers for rdesk WebRTC V2."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import ipaddress
import queue
import select
import socket
import struct
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


PROTOCOL_MAGIC = b"RDS2"
MAX_CONTROL_MESSAGE = 1_048_576
AUTH_HEADER_LIMIT = 32_768
DEFAULT_SIGNAL_PORT = 45000
DEFAULT_CONTROL_PORT = 45001
DEFAULT_INTERNAL_SIGNAL_PORT = 45002
DEFAULT_RELAY_HOST = ""


def derive_master_key(password: str) -> bytes:
    if len(password) < 6:
        raise ValueError("共享密钥至少需要 6 个字符")
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), b"rdesk-v2-control-v1", 220_000, 32
    )


def signalling_token(password: str) -> str:
    key = derive_master_key(password)
    return hmac.new(key, b"rdesk-v2-signalling", hashlib.sha256).hexdigest()


def parse_host_port(value: str, default_port: int = DEFAULT_SIGNAL_PORT) -> Tuple[str, int]:
    value = value.strip()
    if not value:
        raise ValueError("地址不能为空")
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0:
            raise ValueError("IPv6 地址缺少右方括号")
        host = value[1:closing]
        suffix = value[closing + 1 :]
        port = int(suffix[1:]) if suffix.startswith(":") else default_port
    elif value.count(":") > 1:
        # A raw IPv6 literal without brackets has no unambiguous port suffix.
        host, port = value, default_port
    elif value.count(":") == 0:
        host, port = value, default_port
    else:
        host, port_text = value.rsplit(":", 1)
        port = int(port_text)
    if not host or not (1 <= port <= 65535):
        raise ValueError("地址格式应为 IP:端口")
    return host, port


def websocket_url_host(value: str) -> str:
    """Return a host suitable for a WebSocket URI, including IPv6 brackets."""
    host = value.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return host
    if isinstance(address, ipaddress.IPv6Address):
        return "[{}]".format(host.replace("%", "%25"))
    return host


def create_tcp_listener(
    bind_host: str, port: int, backlog: int = 16, timeout: float = 0.5
) -> socket.socket:
    """Create an IPv4/IPv6 listener, using one dual-stack socket when possible.

    ``0.0.0.0`` is treated as the legacy spelling of an all-family wildcard so
    existing profiles gain IPv6 support without a migration. A specific IPv4
    or IPv6 address remains restricted to that address family.
    """
    host = bind_host.strip().strip("[]")
    wildcard = host in ("", "0.0.0.0", "::")
    attempts = []
    if wildcard:
        attempts = ((socket.AF_INET6, "::"), (socket.AF_INET, "0.0.0.0"))
    else:
        try:
            address = ipaddress.ip_address(host.split("%", 1)[0])
            family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
            attempts = ((family, host),)
        except ValueError:
            infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            attempts = tuple((item[0], item[4][0]) for item in infos)

    last_error = None
    seen = set()
    for family, address in attempts:
        marker = (family, address)
        if marker in seen:
            continue
        seen.add(marker)
        listener = socket.socket(family, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6 and wildcard:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            listener.bind((address, int(port)))
            listener.listen(backlog)
            listener.settimeout(timeout)
            return listener
        except OSError as exc:
            last_error = exc
            listener.close()
    if last_error is not None:
        raise last_error
    raise OSError("没有可用的 IPv4/IPv6 监听地址")


def happy_eyeballs_connect(
    host: str, port: int, timeout: float = 8.0, fallback_delay: float = 0.08
) -> socket.socket:
    """Race IPv6 and IPv4 TCP routes and return the first successful socket."""
    clean_host = host.strip().strip("[]")
    infos = socket.getaddrinfo(
        clean_host, int(port), socket.AF_UNSPEC, socket.SOCK_STREAM
    )
    unique = []
    seen = set()
    for family, socktype, proto, _canonname, sockaddr in infos:
        marker = (family, sockaddr)
        if marker not in seen:
            seen.add(marker)
            unique.append((family, socktype, proto, sockaddr))
    # RFC 8305-style family interleaving: prefer native IPv6, start IPv4 a
    # moment later, and never wait for a broken family to time out first.
    ipv6 = [item for item in unique if item[0] == socket.AF_INET6]
    ipv4 = [item for item in unique if item[0] == socket.AF_INET]
    other = [
        item for item in unique if item[0] not in (socket.AF_INET6, socket.AF_INET)
    ]
    unique = []
    while ipv6 or ipv4:
        if ipv6:
            unique.append(ipv6.pop(0))
        if ipv4:
            unique.append(ipv4.pop(0))
    unique.extend(other)
    if not unique:
        raise OSError("地址没有可用的 IPv4/IPv6 路由")

    results: "queue.Queue[tuple]" = queue.Queue()
    stop = threading.Event()
    sockets = []
    sockets_lock = threading.Lock()
    started = time.monotonic()

    def attempt(index, info) -> None:
        delay = min(index, 2) * max(0.0, fallback_delay)
        if stop.wait(delay):
            return
        family, socktype, proto, sockaddr = info
        candidate = socket.socket(family, socktype, proto)
        with sockets_lock:
            sockets.append(candidate)
        try:
            remaining = max(0.1, timeout - (time.monotonic() - started))
            candidate.settimeout(remaining)
            candidate.connect(sockaddr)
            if stop.is_set():
                candidate.close()
            else:
                results.put((candidate, None))
        except OSError as exc:
            candidate.close()
            results.put((None, exc))

    for index, info in enumerate(unique):
        threading.Thread(
            target=attempt,
            args=(index, info),
            name="rdesk-connect-{}".format(index),
            daemon=True,
        ).start()

    errors = []
    winner = None
    deadline = started + timeout
    while time.monotonic() < deadline and len(errors) < len(unique):
        try:
            candidate, error = results.get(
                timeout=max(0.01, deadline - time.monotonic())
            )
        except queue.Empty:
            break
        if candidate is not None:
            winner = candidate
            break
        errors.append(error)
    stop.set()
    with sockets_lock:
        for candidate in sockets:
            if candidate is not winner:
                try:
                    candidate.close()
                except OSError:
                    pass
    if winner is not None:
        winner.settimeout(None)
        return winner
    detail = str(errors[-1]) if errors else "连接超时"
    raise OSError("IPv6/IPv4 并行连接失败：{}".format(detail))


@dataclass
class HostSettings:
    bind_host: str = "::"
    allowed_peer: str = ""
    signal_port: int = DEFAULT_SIGNAL_PORT
    control_port: int = DEFAULT_CONTROL_PORT
    internal_signal_port: int = DEFAULT_INTERNAL_SIGNAL_PORT
    width: int = 1920
    height: int = 1080
    fps: int = 30
    monitor: int = 1
    video_backend: str = "auto"
    stun_server: str = "stun://stun.l.google.com:19302"
    turn_server: str = ""
    native_interfaces_only: bool = True
    password: str = ""

    def validate(self) -> None:
        _validate_port(self.signal_port)
        _validate_port(self.control_port)
        _validate_port(self.internal_signal_port)
        if len({self.signal_port, self.control_port, self.internal_signal_port}) != 3:
            raise ValueError("信令、控制和内部信令端口必须不同")
        if not 320 <= self.width <= 7680 or not 240 <= self.height <= 4320:
            raise ValueError("分辨率超出 320x240 到 7680x4320")
        if self.width % 2 or self.height % 2:
            raise ValueError("H.264 分辨率的宽和高必须为偶数")
        if not 1 <= self.fps <= 120:
            raise ValueError("FPS 必须是 1-120")
        if self.monitor < 1:
            raise ValueError("显示器编号必须从 1 开始")
        if self.video_backend not in ("auto", "gpu", "cpu"):
            raise ValueError("视频后端必须是 auto、gpu 或 cpu")
        derive_master_key(self.password)


@dataclass
class ClientSettings:
    peer: str = "127.0.0.1"
    signal_port: int = DEFAULT_SIGNAL_PORT
    control_port: int = DEFAULT_CONTROL_PORT
    password: str = ""
    clipboard: bool = True
    stun_server: str = "stun://stun.l.google.com:19302"
    turn_server: str = ""
    native_interfaces_only: bool = True
    latency_ms: int = 25

    def validate(self) -> None:
        if not self.peer.strip():
            raise ValueError("被控端地址不能为空")
        _validate_port(self.signal_port)
        _validate_port(self.control_port)
        if not 10 <= int(self.latency_ms) <= 200:
            raise ValueError("接收缓冲必须是 10-200 ms")
        derive_master_key(self.password)


@dataclass
class AppSettings:
    host: HostSettings
    client: ClientSettings

    @classmethod
    def defaults(cls) -> "AppSettings":
        return cls(HostSettings(), ClientSettings())


def _validate_port(value: int) -> None:
    if not 1 <= int(value) <= 65535:
        raise ValueError("端口必须是 1-65535")


def classify_peer_address(value: str) -> str:
    """Return a user-facing transport hint without pretending it is ICE truth."""
    host = value.strip().strip("[]")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "域名（最终路由以 ICE 候选对为准）"
    if address.is_loopback:
        return "本机回环"
    if isinstance(address, ipaddress.IPv4Address) and address in ipaddress.ip_network(
        "100.64.0.0/10"
    ):
        return "Tailscale/CGNAT 地址"
    if address.is_private or address.is_link_local:
        return "局域网地址"
    return "公网地址"


def peer_address_matches(observed: str, expected: str) -> bool:
    """Resolve an optional allow-list host and compare normalized IP addresses."""
    expected = expected.strip().strip("[]")
    if not expected:
        return True

    def normalized(value):
        address = ipaddress.ip_address(str(value).split("%", 1)[0])
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            return address.ipv4_mapped
        return address

    try:
        actual = normalized(observed)
    except ValueError:
        return False
    try:
        candidates = {
            normalized(info[4][0])
            for info in socket.getaddrinfo(expected, 0, socket.AF_UNSPEC, socket.SOCK_STREAM)
        }
    except (OSError, ValueError):
        return False
    return actual in candidates


def is_native_candidate_address(value: str) -> bool:
    """Return whether an address is suitable for native ICE gathering.

    Tailscale lives in 100.64.0.0/10.  Link-local, loopback and unspecified
    addresses cannot provide the wanted Internet P2P path either.  Real LAN
    IPv4 is retained because ICE/STUN needs it to derive a server-reflexive
    candidate, and global IPv6 is retained for the preferred direct route.
    """
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
    ):
        return False
    if isinstance(address, ipaddress.IPv4Address) and address in ipaddress.ip_network(
        "100.64.0.0/10"
    ):
        return False
    return True


def native_route_addresses() -> Tuple[str, ...]:
    """Discover the OS-selected native IPv4/IPv6 egress addresses.

    UDP ``connect`` selects a route without sending application data.  This is
    intentionally route based rather than enumerating adapters: it avoids
    feeding ICE addresses from Tailscale, Hyper-V, Docker and stale VPN NICs.
    """
    result = []
    targets = (
        # Discover/prefer global IPv6 first, while retaining IPv4 for NAT ICE.
        (socket.AF_INET6, ("2001:4860:4860::8888", 53, 0, 0)),
        (socket.AF_INET, ("8.8.8.8", 53)),
    )
    for family, target in targets:
        probe = None
        try:
            probe = socket.socket(family, socket.SOCK_DGRAM)
            probe.connect(target)
            value = str(probe.getsockname()[0])
            if is_native_candidate_address(value) and value not in result:
                result.append(value)
        except OSError:
            continue
        finally:
            if probe is not None:
                probe.close()
    return tuple(result)


def config_path() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return root / "rdesk-v2" / "config.json"


def load_settings(path: Optional[Path] = None) -> AppSettings:
    path = path or config_path()
    defaults = AppSettings.defaults()
    try:
        saved = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return defaults
    for section_name, target in (("host", defaults.host), ("client", defaults.client)):
        section = saved.get(section_name, {})
        if not isinstance(section, dict):
            continue
        for key in asdict(target):
            if key in section:
                setattr(target, key, section[key])
    return defaults


def save_settings(settings: AppSettings, path: Optional[Path] = None) -> Path:
    path = path or config_path()
    settings.host.validate()
    settings.client.validate()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(asdict(settings), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    os.replace(temporary, path)
    if os.name != "nt":
        os.chmod(path, 0o600)
    return path


def adaptive_video_fps(
    width: int,
    height: int,
    configured_fps: int,
    target_bps: int,
    bits_per_pixel_frame: float = 0.09,
) -> int:
    """Prefer fewer clean, current frames over a blurry delayed backlog.

    Desktop text and window edges need more bits per frame than camera video.
    Keeping the configured pixel dimensions while reducing the capture cadence
    gives H.264 enough bits for each frame and, importantly, prevents a slow
    network from accumulating seconds of obsolete motion.
    """
    pixels = max(1, int(width) * int(height))
    maximum = max(1, int(configured_fps))
    budget = max(1, int(target_bps))
    estimated = int(budget / (pixels * max(0.01, bits_per_pixel_frame)))
    # Five FPS made pointer/window motion look seconds behind and caused the
    # receiver-feedback loop to mistake its own throttling for congestion.
    # Keep an interactive cadence; if the path cannot carry this floor, the UI
    # should recommend a lower configured resolution instead of silently
    # turning 1080p into a blurry slideshow.
    return max(min(12, maximum), min(maximum, estimated))


def video_bitrate_limits(width: int, height: int, fps: int):
    """Return GCC min/start/max values suited to interactive desktop video."""
    pixels_per_second = max(1, int(width) * int(height) * int(fps))
    # Desktop text/edges need a materially higher floor than camera video.
    # For 1080p30 this gives about 3.7/7.5/22 Mbps. Going below the floor is
    # reported as insufficient bandwidth rather than producing unreadable
    # 0.5-1 Mbps 1080p output.
    minimum = max(1_000_000, min(6_000_000, int(pixels_per_second * 0.06)))
    start = max(minimum, min(14_000_000, int(pixels_per_second * 0.12)))
    maximum = max(start, min(30_000_000, int(pixels_per_second * 0.35)))
    return minimum, start, maximum


def recovery_gop_frames(fps: int) -> int:
    """Bound visible H.264 reference-frame damage to roughly one third second."""
    return max(1, int(fps) // 3)


COMMON_VIDEO_RESOLUTIONS = (
    (640, 360), (640, 480), (800, 600), (854, 480), (960, 540),
    (1024, 576), (1024, 768), (1280, 720), (1280, 800), (1280, 960),
    (1366, 768), (1440, 900), (1600, 900), (1600, 1200),
    (1680, 1050), (1920, 1080), (1920, 1200), (2048, 1152),
    (2048, 1536), (2560, 1440), (2560, 1600), (3440, 1440),
    (3840, 2160), (5120, 1440), (5120, 2160), (7680, 4320),
)


def fit_video_resolution(width: int, height: int, max_width: int, max_height: int):
    """Fit a resolution inside a display limit without changing its aspect."""
    width = max(1, int(width))
    height = max(1, int(height))
    max_width = max(1, int(max_width))
    max_height = max(1, int(max_height))
    if width <= max_width and height <= max_height:
        return max(2, width - width % 2), max(2, height - height % 2)
    if width * max_height > max_width * height:
        fitted_width = max_width
        fitted_height = max(1, max_width * height // width)
    else:
        fitted_height = max_height
        fitted_width = max(1, max_height * width // height)
    # H.264 4:2:0 encoders require even dimensions.
    fitted_width = max(2, fitted_width - fitted_width % 2)
    fitted_height = max(2, fitted_height - fitted_height % 2)
    return fitted_width, fitted_height


def available_video_resolutions(max_width: int, max_height: int):
    """Return useful standard modes plus the exact configured maximum."""
    max_width = max(1, int(max_width))
    max_height = max(1, int(max_height))
    modes = {
        (width, height)
        for width, height in COMMON_VIDEO_RESOLUTIONS
        if width <= max_width and height <= max_height
    }
    if max_width >= 320 and max_height >= 240:
        modes.add((max_width - max_width % 2, max_height - max_height % 2))
    return sorted(modes, key=lambda item: (item[0] * item[1], item[0], item[1]))


def format_video_resolution(width: int, height: int) -> str:
    labels = {
        (1280, 720): "720p",
        (1920, 1080): "1080p",
        (2560, 1440): "1440p",
        (3840, 2160): "4K",
    }
    size = (int(width), int(height))
    suffix = " · " + labels[size] if size in labels else ""
    return "{} × {}{}".format(size[0], size[1], suffix)


def parse_video_resolution(value: str):
    """Parse a UI resolution label without trusting its descriptive suffix."""
    import re

    match = re.match(r"^\s*(\d+)\s*[xX×]\s*(\d+)", str(value))
    if match is None:
        raise ValueError("分辨率格式应为 宽 × 高")
    return int(match.group(1)), int(match.group(2))


def validate_video_request(
    width: int,
    height: int,
    fps: int,
    max_width: int,
    max_height: int,
    max_fps: int,
):
    """Validate a controller request against immutable host capabilities."""
    width, height, fps = int(width), int(height), int(fps)
    if width < 320 or height < 240 or width % 2 or height % 2:
        raise ValueError("分辨率必须至少为 320x240，且宽高必须为偶数")
    if width > int(max_width) or height > int(max_height):
        raise ValueError(
            "请求 {}x{} 超过被控端上限 {}x{}".format(
                width, height, max_width, max_height
            )
        )
    if not 1 <= fps <= int(max_fps):
        raise ValueError("请求 FPS 必须在 1-{} 之间".format(max_fps))
    return width, height, fps


def host_raw_video_caps(video_backend: str, width: int, height: int, fps: int) -> str:
    """Return the mutable post-scale caps used by every host backend."""
    if video_backend.startswith("d3d11"):
        prefix, pixel_format = "video/x-raw(memory:D3D11Memory)", "NV12"
    elif video_backend == "cuda":
        prefix, pixel_format = "video/x-raw(memory:CUDAMemory)", "NV12"
    elif video_backend == "vaapi-hybrid":
        prefix, pixel_format = "video/x-raw(memory:VAMemory)", "NV12"
    elif video_backend == "cuda-hybrid":
        prefix, pixel_format = "video/x-raw", "NV12"
    else:
        prefix, pixel_format = "video/x-raw", "I420"
    return (
        "{},format={},width={},height={},pixel-aspect-ratio=1/1,framerate={}/1"
    ).format(prefix, pixel_format, int(width), int(height), int(fps))


def content_render_rectangle(
    widget_width: int,
    widget_height: int,
    frame_width: int,
    frame_height: int,
    pixel_aspect_num: int = 1,
    pixel_aspect_den: int = 1,
):
    """Return the exact integer rectangle used for aspect-fitted rendering."""
    widget_width = max(1, int(widget_width))
    widget_height = max(1, int(widget_height))
    frame_width = max(1, int(frame_width))
    frame_height = max(1, int(frame_height))
    pixel_aspect_num = max(1, int(pixel_aspect_num))
    pixel_aspect_den = max(1, int(pixel_aspect_den))
    # Match GstVideo's integer aspect-fit calculation.  Using floating-point
    # round() differs by one pixel for fractional results (for example a
    # 160x100 source inside 192x108 is 172 pixels wide in videoscale, not 173).
    # Integer division also avoids platform-dependent floating-point edges.
    source_ratio_num = frame_width * pixel_aspect_num
    source_ratio_den = frame_height * pixel_aspect_den
    if source_ratio_num * widget_height > widget_width * source_ratio_den:
        content_width = widget_width
        content_height = max(
            1,
            min(
                widget_height,
                widget_width * source_ratio_den // source_ratio_num,
            ),
        )
    else:
        content_height = widget_height
        content_width = max(
            1,
            min(
                widget_width,
                widget_height * source_ratio_num // source_ratio_den,
            ),
        )
    left = (widget_width - content_width) // 2
    top = (widget_height - content_height) // 2
    return left, top, content_width, content_height


def map_content_coordinates(
    x: int,
    y: int,
    widget_width: int,
    widget_height: int,
    frame_width: int,
    frame_height: int,
    pixel_aspect_num: int = 1,
    pixel_aspect_den: int = 1,
    source_width: Optional[int] = None,
    source_height: Optional[int] = None,
    source_pixel_aspect_num: int = 1,
    source_pixel_aspect_den: int = 1,
    source_letterboxed: bool = False,
):
    """Map an aspect-fitted video point to the host's 16-bit input space.

    ``frame_*`` describes the decoded/encoded frame displayed by the client.
    When the host scaler preserved the capture aspect ratio by adding borders,
    ``source_*`` describes the desktop pixels inside that frame.  Mapping both
    rectangles is essential: treating host-side borders as desktop pixels
    makes the centre correct while producing an error that grows towards each
    edge.
    """
    left, top, content_width, content_height = content_render_rectangle(
        widget_width,
        widget_height,
        frame_width,
        frame_height,
        pixel_aspect_num,
        pixel_aspect_den,
    )
    if not (left <= x < left + content_width and top <= y < top + content_height):
        return None

    # Convert from the controller widget to an exact decoded-frame pixel first.
    # Keeping the endpoints in pixel-centre space makes both outer edges map to
    # exactly 0 and 65535 at any client window size.
    frame_x = (x - left) * max(0, frame_width - 1) / max(1.0, content_width - 1.0)
    frame_y = (y - top) * max(0, frame_height - 1) / max(1.0, content_height - 1.0)

    inner_left = 0
    inner_top = 0
    inner_width = max(1, int(frame_width))
    inner_height = max(1, int(frame_height))
    if source_letterboxed and source_width and source_height:
        inner_left, inner_top, inner_width, inner_height = content_render_rectangle(
            frame_width,
            frame_height,
            source_width,
            source_height,
            source_pixel_aspect_num,
            source_pixel_aspect_den,
        )
        if not (
            inner_left <= frame_x <= inner_left + inner_width - 1
            and inner_top <= frame_y <= inner_top + inner_height - 1
        ):
            return None

    nx = round((frame_x - inner_left) * 65535 / max(1.0, inner_width - 1.0))
    ny = round((frame_y - inner_top) * 65535 / max(1.0, inner_height - 1.0))
    return max(0, min(65535, nx)), max(0, min(65535, ny))


def build_host_pipeline(
    settings: HostSettings, windows: bool, video_backend: str = "cpu"
) -> str:
    settings.validate()
    min_bitrate, start_bitrate, max_bitrate = video_bitrate_limits(
        settings.width, settings.height, settings.fps
    )
    if video_backend.startswith("d3d11"):
        # Capture, scale and colour conversion stay in D3D11 memory.  The
        # rswebrtc sink can hand this memory directly to nvd3d11h264enc or a
        # compatible Media Foundation encoder without a CPU read-back.
        if video_backend == "d3d11-mf":
            hardware_encoder = (
                "mfh264enc name=host_encoder low-latency=true rc-mode=cbr "
                "bitrate={bitrate} max-bitrate={max_bitrate} gop-size={gop} ! "
            )
        else:
            hardware_encoder = (
                "nvd3d11h264enc name=host_encoder preset=p4 tune=ultra-low-latency "
                "rc-mode=vbr bitrate={bitrate} max-bitrate={max_bitrate} "
                "gop-size={gop} bframes=0 zerolatency=true aud=true "
                "repeat-sequence-header=true ! "
            )
        capture = (
            "d3d11screencapturesrc name=capture monitor-index={} show-cursor=false ! "
            "video/x-raw(memory:D3D11Memory),framerate={fps}/1 ! "
            "queue max-size-buffers=1 max-size-bytes=0 max-size-time=0 leaky=downstream ! "
            "d3d11convert ! d3d11scale name=host_scale add-borders=true ! "
            "capsfilter name=host_caps caps=\"{host_caps}\" ! "
            "videorate name=adaptive_rate drop-only=true max-rate={fps} ! "
            "queue name=encode_queue max-size-buffers=1 max-size-bytes=0 max-size-time=0 leaky=downstream ! "
            + hardware_encoder
            + "h264parse config-interval=-1 ! video/x-h264,stream-format=byte-stream,alignment=au ! "
        ).format(
            max(0, settings.monitor - 1),
            fps=settings.fps,
            width=settings.width,
            height=settings.height,
            bitrate=max(1, start_bitrate // 1000),
            max_bitrate=max(1, max_bitrate // 1000),
            gop=recovery_gop_frames(settings.fps),
            host_caps=host_raw_video_caps(
                video_backend, settings.width, settings.height, settings.fps
            ),
        )
    elif video_backend == "cuda":
        capture = (
            "ximagesrc name=capture use-damage=false show-pointer=false ! "
            "video/x-raw,framerate={fps}/1 ! "
            "queue max-size-buffers=1 max-size-bytes=0 max-size-time=0 leaky=downstream ! "
            "cudaupload ! cudaconvert ! cudascale name=host_scale add-borders=true ! "
            "capsfilter name=host_caps caps=\"{host_caps}\" ! "
            "videorate name=adaptive_rate drop-only=true max-rate={fps} ! "
            "queue name=encode_queue max-size-buffers=1 max-size-bytes=0 max-size-time=0 leaky=downstream ! "
            "nvh264enc name=host_encoder preset=p4 tune=ultra-low-latency rc-mode=vbr "
            "bitrate={bitrate} max-bitrate={max_bitrate} gop-size={gop} bframes=0 "
            "zerolatency=true aud=true repeat-sequence-header=true ! "
            "h264parse config-interval=-1 ! video/x-h264,stream-format=byte-stream,alignment=au ! "
        ).format(
            fps=settings.fps,
            width=settings.width,
            height=settings.height,
            bitrate=max(1, start_bitrate // 1000),
            max_bitrate=max(1, max_bitrate // 1000),
            gop=recovery_gop_frames(settings.fps),
            host_caps=host_raw_video_caps(
                video_backend, settings.width, settings.height, settings.fps
            ),
        )
    elif video_backend == "cuda-hybrid":
        # X11 capture on Ubuntu 20.04 is system memory. Do the unavoidable
        # scale/convert once and let NVENC perform the final upload/encoding.
        # This is hybrid rather than falsely claiming zero-copy capture.
        capture = (
            "ximagesrc name=capture use-damage=false show-pointer=false ! "
            "video/x-raw,framerate={fps}/1 ! "
            "queue max-size-buffers=1 max-size-bytes=0 max-size-time=0 leaky=downstream ! "
            "videoscale name=host_scale method=0 add-borders=true ! videoconvert ! "
            "capsfilter name=host_caps caps=\"{host_caps}\" ! "
            "videorate name=adaptive_rate drop-only=true max-rate={fps} ! "
            "queue name=encode_queue max-size-buffers=1 max-size-bytes=0 max-size-time=0 leaky=downstream ! "
            "nvh264enc name=host_encoder preset=p4 tune=ultra-low-latency rc-mode=vbr "
            "bitrate={bitrate} max-bitrate={max_bitrate} gop-size={gop} bframes=0 "
            "zerolatency=true aud=true repeat-sequence-header=true ! "
            "h264parse config-interval=-1 ! video/x-h264,stream-format=byte-stream,alignment=au ! "
        ).format(
            fps=settings.fps,
            width=settings.width,
            height=settings.height,
            bitrate=max(1, start_bitrate // 1000),
            max_bitrate=max(1, max_bitrate // 1000),
            gop=recovery_gop_frames(settings.fps),
            host_caps=host_raw_video_caps(
                video_backend, settings.width, settings.height, settings.fps
            ),
        )
    elif video_backend == "vaapi-hybrid":
        capture = (
            "ximagesrc name=capture use-damage=false show-pointer=false ! "
            "video/x-raw,framerate={fps}/1 ! "
            "queue max-size-buffers=1 max-size-bytes=0 max-size-time=0 leaky=downstream ! "
            "vapostproc name=host_scale add-borders=true ! capsfilter name=host_caps caps=\"{host_caps}\" ! "
            "videorate name=adaptive_rate drop-only=true max-rate={fps} ! "
            "queue name=encode_queue max-size-buffers=1 max-size-bytes=0 max-size-time=0 leaky=downstream ! "
            "vah264enc name=host_encoder ! h264parse config-interval=-1 ! "
            "video/x-h264,stream-format=byte-stream,alignment=au ! "
        ).format(
            fps=settings.fps,
            host_caps=host_raw_video_caps(
                video_backend, settings.width, settings.height, settings.fps
            ),
        )
    elif windows:
        capture = (
            "d3d11screencapturesrc name=capture monitor-index={} show-cursor=false ! "
            "d3d11download ! "
        ).format(max(0, settings.monitor - 1))
    else:
        # XDamage can produce partial frames in Ubuntu 20.04 VMs. Full frames
        # are mandatory; WebRTC performs temporal compression afterwards.
        capture = "ximagesrc name=capture use-damage=false show-pointer=false ! "
    turn = ""
    if settings.turn_server.strip():
        turn = ' turn-servers=<"{}">'.format(settings.turn_server.strip())
    return (
        capture
        + (
            "video/x-raw,framerate={fps}/1 ! "
            "queue max-size-buffers=1 max-size-bytes=0 max-size-time=0 leaky=downstream ! "
            "videoscale name=host_scale method=0 add-borders=true ! videoconvert ! "
            "capsfilter name=host_caps caps=\"{host_caps}\" ! "
            "videorate name=adaptive_rate drop-only=true max-rate={fps} ! "
            "queue name=encode_queue max-size-buffers=1 max-size-bytes=0 max-size-time=0 leaky=downstream ! "
            if video_backend == "cpu"
            else ""
        )
        +
        "webrtcsink name=web run-signalling-server=true "
        "signalling-server-host=127.0.0.1 signalling-server-port={internal} "
        "video-caps=video/x-h264 congestion-control=gcc do-retransmission=true do-fec=true "
        # Preserve the configured resolution. Under congestion, reducing FPS
        # is preferable to silently turning a 1080p desktop into a blurry
        # low-resolution stream.
        "enable-mitigation-modes=downsampled min-bitrate={min_bitrate} "
        "start-bitrate={start_bitrate} max-bitrate={max_bitrate} "
        "stun-server={stun}{turn} enable-control-data-channel=true "
        "enable-data-channel-navigation=false "
        "meta=\"meta,name=rdesk-v2\""
    ).format(
        width=settings.width,
        height=settings.height,
        fps=settings.fps,
        internal=settings.internal_signal_port,
        min_bitrate=min_bitrate,
        start_bitrate=start_bitrate,
        max_bitrate=max_bitrate,
        stun=settings.stun_server,
        turn=turn,
        host_caps=host_raw_video_caps(
            video_backend, settings.width, settings.height, settings.fps
        ),
    )


def build_client_pipeline(settings: ClientSettings, windows: bool) -> str:
    settings.validate()
    token = signalling_token(settings.password)
    if windows:
        # Keep the decoded image in an explicit 8-bit SDR RGB format before it
        # reaches Direct3D. Letting the sink consume decoder-selected I420 can
        # create an HDR/alpha interpretation mismatch on some Windows/NVIDIA
        # combinations, producing a valid but almost completely black frame.
        render = (
            "videoconvert ! videoscale ! "
            "video/x-raw,format=BGRA,pixel-aspect-ratio=1/1 ! "
            "identity name=video_probe signal-handoffs=true silent=true ! "
            "d3d11videosink name=video_sink sync=false qos=true "
            "force-aspect-ratio=true enable-navigation-events=false "
            "display-format=b8g8r8a8-unorm"
        )
        # d3d12h264dec can occasionally expose one corrupted DXVA surface even
        # when the bitstream immediately decodes cleanly again.  That presents
        # as a single-frame full-screen stripe flash, not persistent reference
        # damage.  Software decode is still easily real-time at 1080p30/60 and
        # keeps Direct3D for the final low-cost presentation step.
        decoder = (
            "avdec_h264 name=client_decoder max-threads=2 direct-rendering=false "
            "discard-corrupted-frames=true output-corrupt=false"
        )
    else:
        render = (
            "videoconvert ! videoscale ! video/x-raw,pixel-aspect-ratio=1/1 ! "
            "identity name=video_probe "
            "signal-handoffs=true silent=true ! "
            "ximagesink name=video_sink sync=false qos=true "
            "force-aspect-ratio=true"
        )
        decoder = "decodebin"
    turn = ""
    if settings.turn_server.strip():
        turn = ' turn-servers=<"{}">'.format(settings.turn_server.strip())
    return (
        "webrtcsrc name=websrc signaller::uri=ws://{peer}:{port} "
        "signaller::headers=\"headers,authorization=Bearer-{token}\" "
        "connect-to-first-producer=true video-codecs=\"<H264>\" "
        "stun-server={stun}{turn} enable-control-data-channel=true "
        "enable-data-channel-navigation=false "
        "do-retransmission=true ! "
        "queue max-size-buffers=4 max-size-bytes=0 max-size-time=150000000 ! "
        "h264parse name=client_h264parse config-interval=-1 disable-passthrough=true ! "
        "video/x-h264,alignment=au ! {decoder} ! {render}"
    ).format(
        peer=websocket_url_host(settings.peer),
        port=settings.signal_port,
        token=token,
        render=render,
        decoder=decoder,
        stun=settings.stun_server,
        turn=turn,
    )


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    parts = bytearray()
    while len(parts) < size:
        chunk = sock.recv(size - len(parts))
        if not chunk:
            raise ConnectionError("连接已关闭")
        parts.extend(chunk)
    return bytes(parts)


class SecureChannel:
    """Length-prefixed ChaCha20-Poly1305 channel with monotonic nonces."""

    def __init__(self, sock: socket.socket, session_key: bytes, is_client: bool):
        self.sock = sock
        self.cipher = ChaCha20Poly1305(session_key)
        self.send_prefix = b"CLNT" if is_client else b"HOST"
        self.recv_prefix = b"HOST" if is_client else b"CLNT"
        self.send_counter = 0
        self.recv_counter = 0
        self.send_lock = threading.Lock()

    def send(self, value: Dict) -> None:
        plaintext = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        if len(plaintext) > MAX_CONTROL_MESSAGE:
            raise ValueError("控制消息过大")
        with self.send_lock:
            counter = self.send_counter
            self.send_counter += 1
            counter_bytes = struct.pack("!Q", counter)
            ciphertext = self.cipher.encrypt(
                self.send_prefix + counter_bytes, plaintext, counter_bytes
            )
            packet = counter_bytes + ciphertext
            self.sock.sendall(struct.pack("!I", len(packet)) + packet)

    def recv(self) -> Dict:
        length = struct.unpack("!I", _recv_exact(self.sock, 4))[0]
        if not 24 <= length <= MAX_CONTROL_MESSAGE + 24:
            raise ValueError("控制包长度非法")
        packet = _recv_exact(self.sock, length)
        counter_bytes, ciphertext = packet[:8], packet[8:]
        counter = struct.unpack("!Q", counter_bytes)[0]
        if counter != self.recv_counter:
            raise ValueError("控制包序号不连续")
        self.recv_counter += 1
        plaintext = self.cipher.decrypt(
            self.recv_prefix + counter_bytes, ciphertext, counter_bytes
        )
        value = json.loads(plaintext.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("控制消息必须是对象")
        return value

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


def client_handshake(sock: socket.socket, password: str) -> SecureChannel:
    greeting = _recv_exact(sock, 36)
    if greeting[:4] != PROTOCOL_MAGIC:
        raise ValueError("不是 rdesk V2 控制端口")
    challenge = greeting[4:]
    nonce = os.urandom(16)
    master = derive_master_key(password)
    proof = hmac.new(master, b"client" + challenge + nonce, hashlib.sha256).digest()
    sock.sendall(PROTOCOL_MAGIC + nonce + proof)
    expected = hmac.new(master, b"server" + challenge + nonce, hashlib.sha256).digest()
    if not hmac.compare_digest(_recv_exact(sock, 32), expected):
        raise PermissionError("被控端密钥校验失败")
    session_key = hmac.new(
        master, b"session" + challenge + nonce, hashlib.sha256
    ).digest()
    return SecureChannel(sock, session_key, is_client=True)


def server_handshake(sock: socket.socket, password: str) -> SecureChannel:
    challenge = os.urandom(32)
    sock.sendall(PROTOCOL_MAGIC + challenge)
    response = _recv_exact(sock, 52)
    if response[:4] != PROTOCOL_MAGIC:
        raise PermissionError("控制连接协议错误")
    nonce, proof = response[4:20], response[20:]
    master = derive_master_key(password)
    expected = hmac.new(master, b"client" + challenge + nonce, hashlib.sha256).digest()
    if not hmac.compare_digest(proof, expected):
        raise PermissionError("控制端共享密钥错误")
    sock.sendall(hmac.new(master, b"server" + challenge + nonce, hashlib.sha256).digest())
    session_key = hmac.new(
        master, b"session" + challenge + nonce, hashlib.sha256
    ).digest()
    return SecureChannel(sock, session_key, is_client=False)


class LatestMessageSender:
    """Reliable critical queue plus a one-element pointer mailbox."""

    def __init__(self, channel: SecureChannel):
        self.channel = channel
        self.critical: "queue.Queue[Optional[Dict]]" = queue.Queue(maxsize=2048)
        self.latest_pointer: Optional[Dict] = None
        self.pointer_lock = threading.Lock()
        self.running = threading.Event()
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.running.set()
        self.thread = threading.Thread(target=self._run, name="v2-control-send", daemon=True)
        self.thread.start()

    def send(self, message: Dict) -> None:
        if message.get("type") == "mouse_move":
            with self.pointer_lock:
                self.latest_pointer = message
            return
        self.critical.put_nowait(message)

    def _run(self) -> None:
        while self.running.is_set():
            try:
                critical = self.critical.get(timeout=0.008)
            except queue.Empty:
                critical = None
            try:
                if critical is not None:
                    self.channel.send(critical)
                with self.pointer_lock:
                    pointer, self.latest_pointer = self.latest_pointer, None
                if pointer is not None:
                    self.channel.send(pointer)
            except (OSError, ValueError, ConnectionError):
                self.running.clear()

    def close(self) -> None:
        self.running.clear()
        self.channel.close()
        thread = self.thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.0)
        self.thread = None


class AuthWebSocketProxy:
    """Small authenticated TCP proxy protecting the embedded signal server."""

    def __init__(
        self,
        bind: Tuple[str, int],
        upstream: Tuple[str, int],
        password: str,
        status: Callable[[str], None] = lambda _message: None,
        allowed_peer: str = "",
    ):
        self.bind = bind
        self.upstream = upstream
        self.expected = "bearer-" + signalling_token(password)
        self.status = status
        self.allowed_peer = allowed_peer
        self.running = threading.Event()
        self.listener: Optional[socket.socket] = None

    def start(self) -> None:
        listener = create_tcp_listener(self.bind[0], self.bind[1], backlog=16)
        self.listener = listener
        self.running.set()
        threading.Thread(target=self._accept_loop, name="v2-auth-proxy", daemon=True).start()

    def close(self) -> None:
        self.running.clear()
        if self.listener is not None:
            self.listener.close()

    def _accept_loop(self) -> None:
        assert self.listener is not None
        while self.running.is_set():
            try:
                client, address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not peer_address_matches(address[0], self.allowed_peer):
                self.status("已拒绝不在允许列表中的信令来源：{}".format(address[0]))
                client.close()
                continue
            threading.Thread(
                target=self._serve, args=(client, address), daemon=True
            ).start()

    def _serve(self, client: socket.socket, address) -> None:
        upstream = None
        try:
            request = bytearray()
            while b"\r\n\r\n" not in request:
                chunk = client.recv(4096)
                if not chunk:
                    return
                request.extend(chunk)
                if len(request) > AUTH_HEADER_LIMIT:
                    raise PermissionError("HTTP 头过大")
            header_text = bytes(request).split(b"\r\n\r\n", 1)[0].decode(
                "iso-8859-1", "replace"
            )
            headers = {}
            for line in header_text.split("\r\n")[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip().lower()
            if not hmac.compare_digest(headers.get("authorization", ""), self.expected):
                client.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                self.status("已拒绝未通过密钥认证的信令连接：{}".format(address[0]))
                return
            deadline = time.monotonic() + 4
            while upstream is None:
                try:
                    upstream = socket.create_connection(self.upstream, timeout=1)
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.1)
            upstream.settimeout(None)
            client.settimeout(None)
            upstream.sendall(request)
            self.status("信令认证成功：{}".format(address[0]))
            self._pipe(client, upstream)
        except (OSError, ValueError, PermissionError) as exc:
            self.status("信令代理连接结束：{}".format(exc))
        finally:
            client.close()
            if upstream is not None:
                upstream.close()

    def _pipe(self, left: socket.socket, right: socket.socket) -> None:
        sockets = (left, right)
        while self.running.is_set():
            readable, _, _ = select.select(sockets, (), (), 0.5)
            for source in readable:
                data = source.recv(65_536)
                if not data:
                    return
                (right if source is left else left).sendall(data)
