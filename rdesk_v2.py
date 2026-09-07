"""rdesk V2: authenticated WebRTC desktop streaming and remote control."""

from __future__ import annotations

import argparse
import json
import os
import queue
import socket
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from pathlib import Path
from tkinter import ttk
from typing import Dict, Optional

from rdesk_v2_platform import (
    CrossPlatformInputDriver,
    enable_windows_dpi_awareness,
    load_gstreamer,
    monitor_region,
)
from rdesk_v2_core import (
    AuthWebSocketProxy,
    ClientSettings,
    HostSettings,
    LatestMessageSender,
    SecureChannel,
    adaptive_video_fps,
    available_video_resolutions,
    build_client_pipeline,
    build_host_pipeline,
    classify_peer_address,
    client_handshake,
    content_render_rectangle,
    create_tcp_listener,
    fit_video_resolution,
    format_video_resolution,
    happy_eyeballs_connect,
    host_raw_video_caps,
    map_content_coordinates,
    native_route_addresses,
    peer_address_matches,
    parse_video_resolution,
    recovery_gop_frames,
    server_handshake,
    video_bitrate_limits,
    validate_video_request,
)
from rdesk_v2_launcher import Launcher


def _windows_client_size(window_handle: int):
    """Return the native client size used by the Win32 video overlay."""
    if not sys.platform.startswith("win") or not window_handle:
        return None
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.GetClientRect.argtypes = (
            wintypes.HWND,
            ctypes.POINTER(wintypes.RECT),
        )
        user32.GetClientRect.restype = wintypes.BOOL
        handle = wintypes.HWND(int(window_handle))
        rectangle = wintypes.RECT()
        if not user32.GetClientRect(handle, ctypes.byref(rectangle)):
            return None
        width = max(1, int(rectangle.right - rectangle.left))
        height = max(1, int(rectangle.bottom - rectangle.top))
        return width, height
    except Exception:
        return None


def _configure_native_ice(webrtcbin, addresses) -> str:
    """Describe the safe automatic ICE policy without borrowing ice-agent.

    GstWebRTCBin owns a GstWebRTCICE object whose PyGObject wrapper has caused
    the native object to be released on some Ubuntu/GStreamer combinations.
    Merely reading the ``ice-agent`` property was enough to leave webrtcbin
    with an invalid pointer and crash later in gst_webrtc_ice_add_stream.

    libnice already gathers IPv4 and IPv6 host candidates automatically.  Do
    not touch the owned ICE object here; TURN is independently disabled in the
    pipeline configuration, so automatic gathering cannot turn the rendezvous
    server into a media relay.
    """
    del webrtcbin  # Deliberately never access the owned ``ice-agent`` object.
    routes = tuple(str(address) for address in addresses if address)
    if routes:
        return (
            "ICE 自动并行收集 IPv4/IPv6 候选（检测到原生出口：{}）；"
            "TURN 已禁用"
        ).format(", ".join(routes))
    return "ICE 自动并行收集 IPv4/IPv6 候选；TURN 已禁用"


def _configure_h264_depayloader(element) -> list:
    """Apply loss recovery without GStreamer 1.28 header-cache aborts.

    GstRtpH264Depay aggregates RTP header extensions by default.  GStreamer
    1.28.6 can abort in GstRTPBaseDepayload when that cache is combined with a
    packet-loss/keyframe transition.  Header extensions have already served
    their WebRTC transport purpose before H.264 depayloading, so the decoder
    path does not need to copy/aggregate them into output access units.
    """
    configured = []
    disable_aggregation = getattr(
        element, "set_aggregate_hdrext_enabled", None
    )
    if callable(disable_aggregation):
        try:
            disable_aggregation(False)
            configured.append("header-extension-aggregation=off")
        except Exception:
            pass
    for name, value in (
        ("auto-header-extension", False),
        ("request-keyframe", True),
        # Drop damaged predictive access units after packet loss.  Header
        # extension aggregation is disabled above, so the affected 1.28 cache
        # transition is avoided while the next clean IDR replaces the few
        # green/corrupted frames that were previously allowed through.
        ("wait-for-keyframe", True),
    ):
        try:
            if element.find_property(name) is not None:
                element.set_property(name, value)
                configured.append("{}={}".format(name, str(value).lower()))
        except Exception:
            pass
    return configured


def _register_bundled_font() -> Optional[str]:
    """Register the bundled CJK font privately for this process."""
    font_path = Path(__file__).resolve().parent / "assets" / "fonts" / "NotoSansSC.ttf"
    if not font_path.is_file():
        return None
    try:
        import ctypes
        import ctypes.util

        if sys.platform.startswith("win"):
            gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
            gdi32.AddFontResourceExW.argtypes = (
                ctypes.c_wchar_p,
                ctypes.c_uint,
                ctypes.c_void_p,
            )
            gdi32.AddFontResourceExW.restype = ctypes.c_int
            if gdi32.AddFontResourceExW(str(font_path), 0x10, None) <= 0:
                return None
        elif sys.platform.startswith("linux"):
            library = ctypes.util.find_library("fontconfig") or "libfontconfig.so.1"
            fontconfig = ctypes.CDLL(library)
            fontconfig.FcConfigGetCurrent.restype = ctypes.c_void_p
            fontconfig.FcConfigAppFontAddFile.argtypes = (
                ctypes.c_void_p,
                ctypes.c_char_p,
            )
            fontconfig.FcConfigAppFontAddFile.restype = ctypes.c_int
            fontconfig.FcConfigBuildFonts.argtypes = (ctypes.c_void_p,)
            fontconfig.FcConfigBuildFonts.restype = ctypes.c_int
            config = fontconfig.FcConfigGetCurrent()
            if not config or not fontconfig.FcConfigAppFontAddFile(
                config, os.fsencode(font_path)
            ):
                return None
            fontconfig.FcConfigBuildFonts(config)
        elif sys.platform == "darwin":
            core_foundation = ctypes.CDLL(
                ctypes.util.find_library("CoreFoundation")
            )
            core_text = ctypes.CDLL(ctypes.util.find_library("CoreText"))
            core_foundation.CFURLCreateFromFileSystemRepresentation.restype = ctypes.c_void_p
            core_foundation.CFURLCreateFromFileSystemRepresentation.argtypes = (
                ctypes.c_void_p,
                ctypes.c_char_p,
                ctypes.c_long,
                ctypes.c_bool,
            )
            core_foundation.CFRelease.argtypes = (ctypes.c_void_p,)
            core_text.CTFontManagerRegisterFontsForURL.argtypes = (
                ctypes.c_void_p,
                ctypes.c_uint,
                ctypes.c_void_p,
            )
            core_text.CTFontManagerRegisterFontsForURL.restype = ctypes.c_bool
            encoded = os.fsencode(font_path)
            url = core_foundation.CFURLCreateFromFileSystemRepresentation(
                None, encoded, len(encoded), False
            )
            if not url:
                return None
            try:
                if not core_text.CTFontManagerRegisterFontsForURL(url, 1, None):
                    return None
            finally:
                core_foundation.CFRelease(url)
        else:
            return None
        return "Noto Sans SC"
    except Exception:
        return None


def configure_tk_ui(root: tk.Misc) -> None:
    """Apply readable cross-platform fonts, DPI and widget spacing."""
    try:
        current_scaling = float(root.tk.call("tk", "scaling"))
        minimum_scaling = 1.35 if sys.platform.startswith("linux") else 1.0
        root.tk.call("tk", "scaling", max(current_scaling, minimum_scaling))
    except (tk.TclError, ValueError, TypeError):
        pass

    bundled_family = _register_bundled_font()
    families = set(tkfont.families(root))
    preferred = (
        (bundled_family, "Microsoft YaHei UI", "Microsoft YaHei", "Segoe UI")
        if sys.platform.startswith("win")
        else (
            bundled_family,
            "Noto Sans SC",
            "Noto Sans CJK SC",
            "WenQuanYi Micro Hei",
            "Ubuntu",
            "DejaVu Sans",
        )
    )
    family = bundled_family or next(
        (name for name in preferred if name and name in families), None
    )
    base_size = 11 if sys.platform.startswith("linux") else 10
    for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkFixedFont"):
        try:
            font = tkfont.nametofont(name, root=root)
            font.configure(size=base_size)
            if family:
                font.configure(family=family)
        except tk.TclError:
            pass
    for name in ("TkHeadingFont", "TkCaptionFont"):
        try:
            font = tkfont.nametofont(name, root=root)
            font.configure(size=base_size + 1, weight="bold")
            if family:
                font.configure(family=family)
        except tk.TclError:
            pass

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    root.configure(background="#f4f7fb")
    style.configure("TFrame", background="#f4f7fb")
    style.configure("TLabel", background="#f4f7fb", foreground="#1e293b")
    style.configure("Hero.TFrame", background="#0f172a")
    style.configure(
        "HeroTitle.TLabel",
        background="#0f172a",
        foreground="#f8fafc",
        font=(family or "TkDefaultFont", base_size + 6, "bold"),
    )
    style.configure(
        "HeroSub.TLabel", background="#0f172a", foreground="#94a3b8"
    )
    style.configure(
        "Accent.TButton",
        padding=(16, 9),
        background="#2563eb",
        foreground="#ffffff",
        borderwidth=0,
    )
    style.map("Accent.TButton", background=[("active", "#1d4ed8")])
    style.configure("TButton", padding=(11, 7))
    style.configure("TEntry", padding=(6, 5))
    style.configure("TCombobox", padding=(6, 5))
    style.configure("TNotebook.Tab", padding=(16, 8))
    style.configure("TLabelframe", padding=8)
    style.configure("TLabelframe.Label", font=(family or "TkDefaultFont", base_size, "bold"))
    style.configure("Status.TLabel", padding=(12, 7), foreground="#334155")
    style.configure("Sidebar.TFrame", background="#e9eff8")
    style.configure(
        "SidebarTitle.TLabel",
        background="#e9eff8",
        foreground="#64748b",
        font=(family or "TkDefaultFont", base_size - 1, "bold"),
    )
    style.configure(
        "Role.TRadiobutton",
        background="#e9eff8",
        foreground="#0f172a",
        padding=(12, 10),
        font=(family or "TkDefaultFont", base_size + 1, "bold"),
    )
    style.map("Role.TRadiobutton", background=[("selected", "#dbeafe")])
    style.configure(
        "Mode.TRadiobutton",
        background="#e9eff8",
        foreground="#334155",
        padding=(12, 8),
    )
    style.map("Mode.TRadiobutton", background=[("selected", "#dbeafe")])
    style.configure("Card.TLabelframe", background="#ffffff", padding=14)
    style.configure("Card.TFrame", background="#ffffff")
    style.configure("Card.TCheckbutton", background="#ffffff", foreground="#334155")
    style.configure(
        "Card.TLabelframe.Label",
        background="#ffffff",
        foreground="#0f172a",
        font=(family or "TkDefaultFont", base_size + 1, "bold"),
    )
    style.configure("Card.TLabel", background="#ffffff", foreground="#334155")
    style.configure(
        "PageTitle.TLabel",
        foreground="#0f172a",
        font=(family or "TkDefaultFont", base_size + 4, "bold"),
    )
    style.configure("Hint.TLabel", foreground="#64748b")


def _load_gst_video():
    Gst = load_gstreamer()
    import gi

    gi.require_version("GstVideo", "1.0")
    gi.require_version("GstWebRTC", "1.0")
    # Importing GstRtp registers RTPBaseDepayload methods (including
    # set_aggregate_hdrext_enabled) on dynamically-created depayloaders.
    gi.require_version("GstRtp", "1.0")
    from gi.repository import GstRtp, GstVideo, GstWebRTC  # noqa: F401

    return Gst, GstVideo


def _select_video_backend(Gst, windows: bool, preference: str):
    """Choose the fastest usable path, while keeping a deterministic fallback."""

    def has(*names):
        return all(Gst.ElementFactory.find(name) is not None for name in names)

    def usable(name):
        element = Gst.ElementFactory.make(name)
        if element is None:
            return False
        try:
            result = element.set_state(Gst.State.READY)
            return result != Gst.StateChangeReturn.FAILURE
        finally:
            element.set_state(Gst.State.NULL)

    if preference == "cpu":
        return "cpu", "CPU 兼容模式"
    if windows and has("d3d11screencapturesrc", "d3d11convert", "d3d11scale"):
        if usable("nvd3d11h264enc"):
            return "d3d11-nv", "D3D11 GPU 零回读 + NVIDIA NVENC"
        if usable("mfh264enc"):
            return "d3d11-mf", "D3D11 GPU 零回读 + Media Foundation"
    if not windows and has("nvh264enc") and usable("nvh264enc"):
        if has("cudaupload", "cudaconvert", "cudascale"):
            return "cuda", "X11 采集 + CUDA 缩放/NVENC 混合通道"
        return "cuda-hybrid", "X11 CPU 采集/缩放 + NVENC GPU 编码"
    if not windows and has("vapostproc", "vah264enc") and usable("vah264enc"):
        return "vaapi-hybrid", "X11 采集 + VA-API GPU 处理/编码"
    if preference == "gpu":
        return "cpu", "未找到可用 GPU 管线，已自动回退 CPU"
    return "cpu", "未检测到可用 GPU 管线，使用 CPU"


class HostRuntime:
    def __init__(self, root: tk.Misc, settings: HostSettings, status):
        self.root = root
        self.settings = settings
        self.status = status
        self.Gst, self.GstVideo = _load_gst_video()
        self.pipeline = None
        self.proxy: Optional[AuthWebSocketProxy] = None
        self.listener: Optional[socket.socket] = None
        self.running = threading.Event()
        self.control_channel: Optional[SecureChannel] = None
        self.control_lock = threading.Lock()
        self.input = CrossPlatformInputDriver()
        self.gui_events: "queue.Queue[tuple]" = queue.Queue()
        self.last_clipboard = None
        self.consumer_pipelines = {}
        self.display_region = (0, 0, 1, 1)
        self.video_backend = "cpu"
        self.video_backend_text = "尚未检测"
        self.pointer_channels = {}
        self.pointer_channel_refs = []
        self.input_channels = {}
        self.input_channel_refs = []
        self.last_datachannel_pointer = 0.0
        self.pointer_datachannel_moves = 0
        self.pointer_channel_announced = False
        self.capture_caps_size = None
        self.capture_pixel_aspect = (1, 1)
        self.configured_max_width = settings.width
        self.configured_max_height = settings.height
        self.max_width = settings.width
        self.max_height = settings.height
        self.max_fps = settings.fps
        self.current_width = settings.width
        self.current_height = settings.height
        self.current_fps_limit = settings.fps
        self.input_lock = threading.Lock()
        self.explicit_encoder = None
        self.host_caps = None
        self.consumer_encoders = {}
        self.force_key_unit_count = 0
        self.web_sink = None
        self.adaptive_rate = None
        self.gcc_estimates = {}
        self.last_adaptive_bitrate = 0
        self.last_adaptive_fps = settings.fps
        self.last_adaptive_update = time.monotonic()
        self.configured_rtx_elements = set()
        self.configured_ice_elements = set()
        self.video_adaptation_lock = threading.Lock()
        self.client_bitrate_ceiling = None
        self.feedback_healthy_count = 0
        self.feedback_stale_count = 0
        self.control_peer_route = ""
        self.native_ice_addresses = native_route_addresses()
        self.native_ice_announced = False
        self.video_restart_attempt = 0
        self.video_restart_scheduled = False

    def start(self) -> None:
        self.settings.validate()
        left, top, width, height = monitor_region(self.root, self.settings.monitor)
        self.display_region = (left, top, width, height)
        self.input.set_region(left, top, width, height)
        self.max_width, self.max_height = fit_video_resolution(
            self.configured_max_width,
            self.configured_max_height,
            width,
            height,
        )
        self.max_fps = self.settings.fps
        self.current_width = self.max_width
        self.current_height = self.max_height
        self.current_fps_limit = self.max_fps
        self.video_backend, self.video_backend_text = _select_video_backend(
            self.Gst,
            windows=sys.platform.startswith("win"),
            preference=self.settings.video_backend,
        )
        try:
            self._start_video_pipeline(self.video_backend)
        except Exception as exc:
            if self.video_backend == "cpu":
                raise
            failed_backend = self.video_backend_text
            self.video_backend = "cpu"
            self.video_backend_text = "GPU 启动失败，自动回退 CPU：{}".format(exc)
            print(
                "{}；原后端 {}".format(self.video_backend_text, failed_backend),
                file=sys.stderr,
                flush=True,
            )
            self._start_video_pipeline("cpu")
        self.proxy = AuthWebSocketProxy(
            (self.settings.bind_host, self.settings.signal_port),
            ("127.0.0.1", self.settings.internal_signal_port),
            self.settings.password,
            lambda value: self.gui_events.put(("status", value)),
            allowed_peer=self.settings.allowed_peer,
        )
        # The embedded server starts asynchronously. The proxy can accept
        # immediately and will report a clear upstream error until it is ready.
        self.proxy.start()
        self._start_control_listener()
        self.running.set()
        self.status(
            "被控端运行中：信令 {}:{}，控制端口 {}，{}x{} @ {} FPS；{}".format(
                self.settings.bind_host,
                self.settings.signal_port,
                self.settings.control_port,
                self.current_width,
                self.current_height,
                self.current_fps_limit,
                self.video_backend_text,
            )
        )
        self.root.after(100, self._poll)
        self.root.after(500, self._clipboard_tick)
        self.root.after(250, self._display_geometry_tick)

    def _start_video_pipeline(self, backend: str) -> None:
        self.explicit_encoder = None
        self.adaptive_rate = None
        self.gcc_estimates.clear()
        self.last_adaptive_bitrate = 0
        pipeline_settings = HostSettings(**vars(self.settings))
        pipeline_settings.width = self.current_width
        pipeline_settings.height = self.current_height
        # Keep capture negotiation at the host FPS ceiling.  videorate applies
        # the controller's lower live cadence and can raise it again instantly.
        pipeline_settings.fps = self.max_fps
        description = build_host_pipeline(
            pipeline_settings,
            windows=sys.platform.startswith("win"),
            video_backend=backend,
        )
        pipeline = self.Gst.parse_launch(description)
        self.pipeline = pipeline
        self.capture_caps_size = None
        self.capture_pixel_aspect = (1, 1)
        self.host_caps = self.pipeline.get_by_name("host_caps")
        capture = self.pipeline.get_by_name("capture")
        if capture is not None:
            capture_pad = capture.get_static_pad("src")
            if capture_pad is not None:
                capture_pad.add_probe(
                    self.Gst.PadProbeType.EVENT_DOWNSTREAM,
                    self._capture_caps_probe,
                )
        web = self.pipeline.get_by_name("web")
        self.web_sink = web
        if web is not None:
            web.connect("encoder-setup", self._encoder_setup)
            web.connect("payloader-setup", self._payloader_setup)
            web.connect("consumer-pipeline-created", self._consumer_pipeline_created)
            web.connect("consumer-added", self._consumer_added)
        explicit_encoder = self.pipeline.get_by_name("host_encoder")
        self.adaptive_rate = self.pipeline.get_by_name("adaptive_rate")
        self.last_adaptive_fps = self.current_fps_limit
        if self.adaptive_rate is not None:
            self.adaptive_rate.set_property("max-rate", self.current_fps_limit)
        if explicit_encoder is not None:
            self.explicit_encoder = explicit_encoder
            factory = explicit_encoder.get_factory()
            name = factory.get_name() if factory is not None else explicit_encoder.get_name()
            if explicit_encoder.find_property("bitrate") is not None:
                _minimum, initial_bps, _maximum = video_bitrate_limits(
                    self.current_width,
                    self.current_height,
                    self.current_fps_limit,
                )
                explicit_encoder.set_property("bitrate", initial_bps // 1000)
            print("WebRTC 显式 GPU 编码器：{}".format(name), file=sys.stderr, flush=True)
        result = self.pipeline.set_state(self.Gst.State.PLAYING)
        if result == self.Gst.StateChangeReturn.FAILURE:
            self.pipeline.set_state(self.Gst.State.NULL)
            self.pipeline = None
            raise RuntimeError("WebRTC 被控端视频管线启动失败")
        state_result, _current, _pending = self.pipeline.get_state(
            2 * self.Gst.SECOND
        )
        error_message = self.pipeline.get_bus().pop_filtered(self.Gst.MessageType.ERROR)
        if state_result == self.Gst.StateChangeReturn.FAILURE or error_message is not None:
            detail = "未知错误"
            if error_message is not None:
                error, debug = error_message.parse_error()
                detail = "{} ({})".format(error, debug or "")
            self.pipeline.set_state(self.Gst.State.NULL)
            self.pipeline = None
            raise RuntimeError(detail)
        _minimum, start_bps, _maximum = video_bitrate_limits(
            self.current_width, self.current_height, self.current_fps_limit
        )
        self._apply_video_target(start_bps, "初始画质")

    def _host_info_message(self) -> Dict:
        left, top, input_width, input_height = self.display_region
        capture_width, capture_height = self.capture_caps_size or (
            input_width,
            input_height,
        )
        return {
            "type": "host_info",
            "width": self.current_width,
            "height": self.current_height,
            "fps": self.current_fps_limit,
            "max_width": self.max_width,
            "max_height": self.max_height,
            "max_fps": self.max_fps,
            "resolution_options": [
                {"width": width, "height": height}
                for width, height in available_video_resolutions(
                    self.max_width, self.max_height
                )
            ],
            "capture_left": left,
            "capture_top": top,
            "capture_width": capture_width,
            "capture_height": capture_height,
            "capture_pixel_aspect_num": self.capture_pixel_aspect[0],
            "capture_pixel_aspect_den": self.capture_pixel_aspect[1],
            # Every host backend is configured to preserve display aspect by
            # centring the captured desktop in the fixed-size encoded frame.
            "capture_scale_mode": "letterbox",
            "input_left": left,
            "input_top": top,
            "input_width": input_width,
            "input_height": input_height,
            "input_backend": self.input.input_backend_status(),
            "video_backend": self.video_backend_text,
            "pointer_transport": "归一化 DataChannel + 可靠备用通道",
        }

    def _capture_caps_probe(self, _pad, info):
        """Record video geometry without changing the OS input coordinate space."""
        event = info.get_event()
        if event is None or event.type != self.Gst.EventType.CAPS:
            return self.Gst.PadProbeReturn.OK
        try:
            caps = event.parse_caps()
            if caps is None or caps.get_size() < 1:
                return self.Gst.PadProbeReturn.OK
            structure = caps.get_structure(0)
            width = max(1, int(structure.get_value("width")))
            height = max(1, int(structure.get_value("height")))
            pixel_aspect = (1, 1)
            try:
                fraction = structure.get_fraction("pixel-aspect-ratio")
                if len(fraction) == 3 and fraction[0]:
                    pixel_aspect = (
                        max(1, int(fraction[1])),
                        max(1, int(fraction[2])),
                    )
                elif len(fraction) == 2:
                    pixel_aspect = (
                        max(1, int(fraction[0])),
                        max(1, int(fraction[1])),
                    )
            except Exception:
                try:
                    fraction = structure.get_value("pixel-aspect-ratio")
                    pixel_aspect = (
                        max(1, int(fraction.num)),
                        max(1, int(fraction.denom)),
                    )
                except Exception:
                    pass
            if (
                self.capture_caps_size != (width, height)
                or self.capture_pixel_aspect != pixel_aspect
            ):
                self.capture_caps_size = (width, height)
                self.capture_pixel_aspect = pixel_aspect
                self._send_control(self._host_info_message())
                self.gui_events.put(
                    (
                        "status",
                        "视频采集区域 {}x{}；输入桌面区域 ({}, {}) {}x{}".format(
                            width, height, *self.display_region
                        ),
                    )
                )
        except Exception as exc:
            self.gui_events.put(("status", "读取实际采集区域失败：{}".format(exc)))
        return self.Gst.PadProbeReturn.OK

    def _inject_pointer_move(self, x, y, datachannel=False) -> None:
        x = max(0, min(65535, int(x)))
        y = max(0, min(65535, int(y)))
        with self.input_lock:
            self.input.handle(
                json.dumps({"type": "mouse_move", "x": x, "y": y}).encode("utf-8")
            )
        if datachannel:
            self.last_datachannel_pointer = time.monotonic()
            self.pointer_datachannel_moves += 1
            if not self.pointer_channel_announced:
                self.pointer_channel_announced = True
                self._send_control({"type": "pointer_datachannel_ready"})
                self.gui_events.put(
                    ("status", "鼠标移动已切换到 WebRTC 无序/不可靠 DataChannel")
                )

    def _display_geometry_tick(self) -> None:
        if not self.running.is_set():
            return
        current = monitor_region(self.root, self.settings.monitor)
        if current != self.display_region:
            self.display_region = current
            self.input.set_region(*current)
            new_max = fit_video_resolution(
                self.configured_max_width,
                self.configured_max_height,
                current[2],
                current[3],
            )
            self.max_width, self.max_height = new_max
            fitted_current = fit_video_resolution(
                self.current_width,
                self.current_height,
                self.max_width,
                self.max_height,
            )
            if fitted_current != (self.current_width, self.current_height):
                self._apply_requested_video_config(
                    {
                        "width": fitted_current[0],
                        "height": fitted_current[1],
                        "fps": min(self.current_fps_limit, self.max_fps),
                    },
                    reason="显示器尺寸变化",
                )
            else:
                self._send_control(self._host_info_message())
            self.gui_events.put(
                (
                    "status",
                    "显示区域已更新：({}, {}) {}x{}".format(*current),
                )
            )
        self.root.after(250, self._display_geometry_tick)

    def _consumer_pipeline_created(self, _sink, consumer_id, pipeline) -> None:
        """Surface errors from webrtcsink's per-client child pipeline."""
        self.consumer_pipelines[str(consumer_id)] = pipeline
        pipeline.connect(
            "deep-element-added",
            self._consumer_element_added,
            str(consumer_id),
        )
        try:
            for element in pipeline.iterate_recurse():
                self._consumer_element_added(
                    pipeline, pipeline, element, str(consumer_id)
                )
        except Exception:
            pass
        bus = pipeline.get_bus()
        bus.set_sync_handler(self._consumer_bus_message, str(consumer_id))
        text = "WebRTC 已创建媒体管线：{}，正在生成 SDP".format(consumer_id)
        print(text, file=sys.stderr, flush=True)
        self.gui_events.put(("status", text))

    def _consumer_element_added(
        self, _pipeline, _owner, element, consumer_id
    ) -> None:
        factory = element.get_factory()
        factory_name = factory.get_name() if factory is not None else ""
        if factory_name == "webrtcbin" and self.settings.native_interfaces_only:
            # Announce the automatic dual-stack policy once per consumer.  Do
            # not read webrtcbin's ice-agent property here: on affected Linux
            # GStreamer/PyGObject builds that invalidates the owned ICE object
            # and causes a later gst_webrtc_ice_add_stream segmentation fault.
            marker = ("consumer", str(consumer_id))
            if marker not in self.configured_ice_elements:
                self.configured_ice_elements.add(marker)
                ice_text = _configure_native_ice(element, self.native_ice_addresses)
                print(ice_text, file=sys.stderr, flush=True)
                if not self.native_ice_announced:
                    self.native_ice_announced = True
                    self.gui_events.put(("status", ice_text))
        if factory_name == "rtprtxsend":
            marker = id(element)
            if marker in self.configured_rtx_elements:
                return
            self.configured_rtx_elements.add(marker)
            # The default cache is 100 packets with unlimited age. On a slow
            # path that can retransmit obsolete desktop frames long after the
            # mouse action has completed. Bound recovery to the interactive
            # latency budget; a fresh IDR repairs anything older.
            for name, value in (("max-size-time", 150), ("max-size-packets", 64)):
                if element.find_property(name) is not None:
                    element.set_property(name, value)
            return
        if factory_name != "rtpgccbwe":
            return
        element.connect(
            "notify::estimated-bitrate",
            self._gcc_bitrate_changed,
            consumer_id,
        )

    def _gcc_bitrate_changed(self, estimator, _spec, consumer_id) -> None:
        """Combine WebRTC GCC with receiver-observed playout feedback."""
        try:
            estimate = int(estimator.get_property("estimated-bitrate"))
        except Exception:
            return
        if estimate < 100_000:
            return
        self.gcc_estimates[str(consumer_id)] = estimate
        # One shared capture/encoder serves all viewers, so protect the slowest
        # active viewer. Keep headroom for RTP/FEC/DTLS overhead.
        target_bps = int(min(self.gcc_estimates.values()) * 0.85)
        quality_floor, _start, ceiling = video_bitrate_limits(
            self.current_width,
            self.current_height,
            self.current_fps_limit,
        )
        target_bps = max(quality_floor, min(ceiling, target_bps))
        if self.client_bitrate_ceiling is not None:
            target_bps = min(target_bps, self.client_bitrate_ceiling)
        self._apply_video_target(target_bps, "GCC")

    def _apply_video_target(self, target_bps: int, reason: str) -> None:
        """Apply one latency-first encoder/cadence target atomically."""
        encoder = self.explicit_encoder
        _minimum, _start, ceiling = video_bitrate_limits(
            self.current_width,
            self.current_height,
            self.current_fps_limit,
        )
        target_bps = max(_minimum, min(ceiling, int(target_bps)))
        target_kbps = max(1, target_bps // 1000)
        requested_fps = adaptive_video_fps(
            self.current_width,
            self.current_height,
            self.current_fps_limit,
            target_bps,
        )
        with self.video_adaptation_lock:
            # Recover cadence gradually to avoid oscillation, but reduce it
            # immediately when the receiver reports a playout collapse.
            previous_fps = self.last_adaptive_fps
            now = time.monotonic()
            if requested_fps > previous_fps:
                if now - self.last_adaptive_update >= 1.0:
                    requested_fps = min(requested_fps, previous_fps + 2)
                    self.last_adaptive_update = now
                else:
                    requested_fps = previous_fps
            elif requested_fps < previous_fps:
                self.last_adaptive_update = now
            if self.adaptive_rate is not None:
                try:
                    self.adaptive_rate.set_property("max-rate", requested_fps)
                    self.last_adaptive_fps = requested_fps
                except Exception:
                    pass
            if encoder is not None and encoder.find_property("bitrate") is not None:
                try:
                    encoder.set_property("bitrate", target_kbps)
                    if encoder.find_property("max-bitrate") is not None:
                        encoder.set_property(
                            "max-bitrate", max(target_kbps, int(target_kbps * 1.10))
                        )
                    gop = recovery_gop_frames(requested_fps)
                    for name in ("gop-size", "key-int-max"):
                        if encoder.find_property(name) is not None:
                            encoder.set_property(name, gop)
                except Exception:
                    pass
            # CPU encoders are owned by webrtcsink rather than exposed in the
            # top-level pipeline. Keep the feedback ceiling effective on both
            # the CPU and explicit GPU paths.
            if (
                self.web_sink is not None
                and self.web_sink.find_property("max-bitrate") is not None
            ):
                try:
                    self.web_sink.set_property("max-bitrate", target_bps)
                except Exception:
                    pass
            previous = self.last_adaptive_bitrate
            self.last_adaptive_bitrate = target_bps
        if (
            previous == 0
            or requested_fps != previous_fps
            or abs(target_bps - previous) >= max(400_000, previous // 6)
        ):
            message = "{}：{:.1f} Mbps，实时采样 {} FPS（保持 {}x{}）".format(
                reason,
                target_bps / 1_000_000,
                self.last_adaptive_fps,
                self.current_width,
                self.current_height,
            )
            self.gui_events.put(
                (
                    "status",
                    message,
                )
            )
            self._send_control(
                {
                    "type": "video_adaptation",
                    "bitrate_mbps": round(target_bps / 1_000_000, 1),
                    "fps": self.last_adaptive_fps,
                    "width": self.current_width,
                    "height": self.current_height,
                    "reason": reason,
                }
            )

    def _client_video_feedback(self, message: Dict) -> None:
        """Close the control loop when an overlay/VPN hides its own queue."""
        try:
            decoded_fps = max(0.0, float(message.get("decode_fps", 0)))
            frame_age_ms = max(0.0, float(message.get("frame_age_ms", 0)))
        except (TypeError, ValueError):
            return
        current_fps = max(1, self.last_adaptive_fps)
        _minimum, start, maximum = video_bitrate_limits(
            self.current_width, self.current_height, self.current_fps_limit
        )
        current_limit = self.client_bitrate_ceiling
        if current_limit is None:
            current_limit = self.last_adaptive_bitrate or start
        # Decoded FPS is an observation, not proof of congestion: it naturally
        # falls after we reduce the sender cadence.  Using it as a reduction
        # trigger created a positive feedback loop that drove 1080p down to
        # 0.4-0.7 Mbps and 5 FPS.  Only stale frame age may lower bitrate; FPS
        # remains useful for status and for deciding when recovery is healthy.
        severe = frame_age_ms >= 1500
        congested = frame_age_ms >= 650
        healthy = frame_age_ms < 250 and decoded_fps >= max(3, current_fps * 0.70)
        new_limit = current_limit
        if severe:
            self.feedback_stale_count += 1
            self.feedback_healthy_count = 0
            if self.feedback_stale_count >= 2:
                new_limit = max(_minimum, int(current_limit * 0.80))
        elif congested:
            self.feedback_stale_count += 1
            self.feedback_healthy_count = 0
            if self.feedback_stale_count >= 3:
                new_limit = max(_minimum, int(current_limit * 0.90))
        elif healthy:
            self.feedback_stale_count = 0
            self.feedback_healthy_count += 1
            if self.feedback_healthy_count >= 3:
                new_limit = min(maximum, int(current_limit * 1.15) + 250_000)
                self.feedback_healthy_count = 0
        else:
            self.feedback_stale_count = 0
            self.feedback_healthy_count = 0
        if new_limit != current_limit:
            self.client_bitrate_ceiling = new_limit
            reason = "接收端反馈 {:.1f} FPS/停帧 {:.0f} ms".format(
                decoded_fps, frame_age_ms
            )
            self._apply_video_target(new_limit, reason)

    def _force_video_keyframe(self) -> None:
        """Request an IDR with headers after loss or a live caps change."""
        with self.video_adaptation_lock:
            encoders = list(self.consumer_encoders.values())
        if self.explicit_encoder is not None and self.explicit_encoder not in encoders:
            encoders.append(self.explicit_encoder)
        self.force_key_unit_count += 1
        for encoder in encoders:
            try:
                pad = encoder.get_static_pad("src")
                if pad is None:
                    continue
                event = self.GstVideo.video_event_new_upstream_force_key_unit(
                    self.Gst.CLOCK_TIME_NONE,
                    True,
                    self.force_key_unit_count,
                )
                pad.send_event(event)
            except Exception:
                continue

    def _apply_requested_video_config(
        self, message: Dict, reason: str = "控制端画质请求"
    ) -> None:
        try:
            width, height, fps = validate_video_request(
                message.get("width"),
                message.get("height"),
                message.get("fps"),
                self.max_width,
                self.max_height,
                self.max_fps,
            )
            resolution_changed = (
                width != self.current_width or height != self.current_height
            )
            if resolution_changed:
                if self.host_caps is None:
                    raise RuntimeError("当前视频后端不支持实时分辨率切换")
                caps = self.Gst.Caps.from_string(
                    host_raw_video_caps(
                        self.video_backend,
                        width,
                        height,
                        self.max_fps,
                    )
                )
                self.host_caps.set_property("caps", caps)
            self.current_width = width
            self.current_height = height
            self.current_fps_limit = fps
            self.client_bitrate_ceiling = None
            _minimum, start_bps, _maximum = video_bitrate_limits(width, height, fps)
            self._apply_video_target(start_bps, reason)
            if resolution_changed:
                # Ask once immediately and once after renegotiation has reached
                # the encoder. Both events request SPS/PPS with the clean IDR.
                self._force_video_keyframe()
                timer = threading.Timer(0.15, self._force_video_keyframe)
                timer.daemon = True
                timer.start()
            applied = {
                "type": "video_config_applied",
                "width": width,
                "height": height,
                "fps": fps,
                "max_width": self.max_width,
                "max_height": self.max_height,
                "max_fps": self.max_fps,
            }
            self._send_control(applied)
            self._send_control(self._host_info_message())
            self.gui_events.put(
                (
                    "status",
                    "{}：已切换至 {}x{} @ {} FPS".format(
                        reason, width, height, fps
                    ),
                )
            )
        except Exception as exc:
            self._send_control(
                {"type": "video_config_rejected", "reason": str(exc)}
            )

    def _consumer_added(self, _sink, consumer_id, webrtcbin) -> None:
        text = "WebRTC 媒体会话已建立：{}".format(consumer_id)
        print(text, file=sys.stderr, flush=True)
        self.gui_events.put(("status", text))
        # ICE policy is announced from the per-consumer deep-element callback.
        # The owned ice-agent is intentionally never retrieved from Python.
        try:
            options = self.Gst.Structure.new_empty("config")
            options.set_value("ordered", False)
            options.set_value("max-retransmits", 0)
            channel = webrtcbin.emit(
                "create-data-channel", "rdesk-pointer-v1", options
            )
            channel.connect("on-message-string", self._pointer_channel_message)
            channel.connect("on-close", self._pointer_channel_closed)
            self.pointer_channels[str(consumer_id)] = channel
            self.pointer_channel_refs.append(channel)
        except Exception as exc:
            self.gui_events.put(
                ("status", "无法创建鼠标 DataChannel，将用可靠回退：{}".format(exc))
            )
        try:
            options = self.Gst.Structure.new_empty("config")
            options.set_value("ordered", True)
            channel = webrtcbin.emit(
                "create-data-channel", "rdesk-input-v1", options
            )
            channel.connect("on-message-string", self._input_channel_message)
            channel.connect("on-close", self._input_channel_closed)
            self.input_channels[str(consumer_id)] = channel
            self.input_channel_refs.append(channel)
        except Exception as exc:
            self.gui_events.put(
                ("status", "无法创建可靠输入 DataChannel，将用控制通道：{}".format(exc))
            )
        for property_name in ("ice-connection-state", "connection-state"):
            if webrtcbin.find_property(property_name) is not None:
                webrtcbin.connect(
                    "notify::" + property_name,
                    self._webrtc_state_changed,
                    str(consumer_id),
                    property_name,
                )

    def _pointer_channel_message(self, _channel, text) -> None:
        try:
            value = json.loads(text)
            if value.get("type") == "pointer":
                self._inject_pointer_move(value["x"], value["y"], datachannel=True)
        except (ValueError, KeyError, TypeError):
            return

    def _pointer_channel_closed(self, channel) -> None:
        self.pointer_channel_refs = [item for item in self.pointer_channel_refs if item is not channel]
        self.gui_events.put(("status", "WebRTC 鼠标 DataChannel 已关闭，自动回退到可靠通道"))

    def _input_channel_message(self, _channel, text) -> None:
        try:
            message = json.loads(text)
        except (ValueError, TypeError):
            return
        if message.get("type") not in {
            "key_down",
            "key_up",
            "mouse_button",
            "mouse_wheel",
            "release_all",
        }:
            return
        self._handle_input_message(message)

    def _input_channel_closed(self, channel) -> None:
        self.input_channel_refs = [
            item for item in self.input_channel_refs if item is not channel
        ]
        self.gui_events.put(
            ("status", "WebRTC 可靠输入 DataChannel 已关闭，自动回退控制通道")
        )

    def _webrtc_state_changed(
        self, webrtcbin, _property_spec, consumer_id, property_name
    ) -> None:
        try:
            value = webrtcbin.get_property(property_name)
            nick = getattr(value, "value_nick", str(value))
        except Exception as exc:
            nick = "读取失败：{}".format(exc)
        text = "WebRTC {} {}={}".format(consumer_id, property_name, nick)
        print(text, file=sys.stderr, flush=True)
        self.gui_events.put(("status", text))

    def _consumer_bus_message(self, _bus, message, consumer_id):
        if message.type == self.Gst.MessageType.ERROR:
            error, debug = message.parse_error()
            text = "WebRTC 子管线错误 [{}]：{} ({})".format(
                consumer_id, error, debug or ""
            )
            print(text, file=sys.stderr, flush=True)
            self.gui_events.put(("status", text))
        elif message.type == self.Gst.MessageType.WARNING:
            warning, debug = message.parse_warning()
            text = "WebRTC 子管线警告 [{}]：{} ({})".format(
                consumer_id, warning, debug or ""
            )
            print(text, file=sys.stderr, flush=True)
            self.gui_events.put(("status", text))
        return self.Gst.BusSyncReply.PASS

    def _encoder_setup(self, _sink, _consumer_id, _stream_name, encoder):
        # Properties differ between NVENC, Media Foundation, VAAPI and x264.
        # Set only universally safe low-latency knobs that exist on the chosen
        # encoder; rswebrtc remains responsible for bitrate/GCC.
        factory = encoder.get_factory()
        encoder_name = factory.get_name() if factory is not None else encoder.get_name()
        candidates = {
            "bframes": 0,
            "b-frames": 0,
            "rc-lookahead": 0,
            "sync-lookahead": 0,
            # x264 uses enum/flag properties for its actual real-time mode.
            # Without these it may buffer a long time on a CPU-limited VM
            # before webrtcsink receives the first access unit and creates SDP.
            "speed-preset": "ultrafast",
            "tune": "zerolatency",
            "sliced-threads": True,
            "zerolatency": True,
            "zero-reorder-delay": True,
            "repeat-sequence-header": True,
            "aud": True,
            # Recover from an unrecoverable reference frame within about one
            # third second. Retransmission/FEC should normally avoid this,
            # but remote desktop motion is especially sensitive to ghosting.
            "key-int-max": recovery_gop_frames(self.current_fps_limit),
            "gop-size": recovery_gop_frames(self.current_fps_limit),
            "min-force-key-unit-interval": 0,
        }
        if encoder_name in ("nvh264enc", "nvd3d11h264enc"):
            candidates.update(
                {
                    "preset": "p4",
                    "tune": "ultra-low-latency",
                    "rc-mode": "vbr",
                    "spatial-aq": True,
                }
            )
        applied = []
        for name, value in candidates.items():
            if encoder.find_property(name) is not None:
                try:
                    encoder.set_property(name, value)
                except (TypeError, ValueError):
                    # PyGObject does not directly coerce strings into every
                    # GStreamer enum/flags type (notably x264enc tune/preset).
                    try:
                        text = str(value).lower() if isinstance(value, bool) else str(value)
                        self.Gst.util_set_object_arg(encoder, name, text)
                    except Exception:
                        pass
                try:
                    applied.append("{}={}".format(name, encoder.get_property(name)))
                except Exception:
                    pass
        text = "WebRTC 实际编码器：{}；{}".format(
            encoder_name, ", ".join(applied) or "未应用低延迟参数"
        )
        print(text, file=sys.stderr, flush=True)
        self.gui_events.put(("status", text))
        with self.video_adaptation_lock:
            self.consumer_encoders[str(_consumer_id)] = encoder
        return True

    def _payloader_setup(self, _sink, _consumer_id, _stream_name, payloader):
        # NATs and Internet paths may expose an MTU near 1280. GStreamer's RTP
        # payloaders can otherwise be fragmented; losing one fragment drops
        # the complete H.264 RTP packet and creates black blocks/ghosting.
        if payloader.find_property("mtu") is not None:
            payloader.set_property("mtu", 1120)
        # Repeat SPS/PPS with every IDR so a new receiver, or one recovering
        # after loss, can decode the next key frame independently.
        if payloader.find_property("config-interval") is not None:
            payloader.set_property("config-interval", -1)
        factory = payloader.get_factory()
        name = factory.get_name() if factory is not None else payloader.get_name()
        text = "WebRTC RTP 打包器：{}，MTU 1120（兼容 IPv6 最小链路 MTU）".format(name)
        print(text, file=sys.stderr, flush=True)
        self.gui_events.put(("status", text))
        return True

    def _start_control_listener(self) -> None:
        listener = create_tcp_listener(
            self.settings.bind_host, self.settings.control_port, backlog=4
        )
        self.listener = listener
        threading.Thread(
            target=self._control_accept_loop, name="v2-control-listen", daemon=True
        ).start()

    def _control_accept_loop(self) -> None:
        assert self.listener is not None
        while self.running.is_set() or self.pipeline is not None:
            try:
                sock, address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not peer_address_matches(address[0], self.settings.allowed_peer):
                sock.close()
                self.gui_events.put(
                    ("status", "已拒绝不在允许列表中的控制来源：{}".format(address[0]))
                )
                continue
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(8)
            try:
                channel = server_handshake(sock, self.settings.password)
                sock.settimeout(None)
            except Exception as exc:
                sock.close()
                self.gui_events.put(("status", "控制认证失败：{}".format(exc)))
                continue
            with self.control_lock:
                previous, self.control_channel = self.control_channel, channel
            if previous is not None:
                previous.close()
            self.input.reset_session()
            self.pointer_channel_announced = False
            self.control_peer_route = classify_peer_address(address[0])
            channel.send(self._host_info_message())
            self.gui_events.put(
                (
                    "status",
                    "控制认证成功：{}（{}）".format(
                        address[0], classify_peer_address(address[0])
                    ),
                )
            )
            threading.Thread(
                target=self._control_receive_loop,
                args=(channel,),
                name="v2-control-recv",
                daemon=True,
            ).start()

    def _control_receive_loop(self, channel: SecureChannel) -> None:
        try:
            while self.pipeline is not None:
                message = channel.recv()
                if message.get("type") == "clipboard":
                    self.gui_events.put(("clipboard", str(message.get("text", ""))))
                elif message.get("type") == "ping":
                    channel.send({"type": "pong", "time": message.get("time")})
                elif message.get("type") == "video_feedback":
                    self._client_video_feedback(message)
                elif message.get("type") == "video_config":
                    self._apply_requested_video_config(message)
                elif message.get("type") == "reset_input_session":
                    self.input.reset_session()
                elif message.get("type") == "mouse_move":
                    # This is a deliberately low-frequency reliable fallback.
                    # Never let an old TCP position pull the pointer backwards
                    # while the unordered WebRTC channel is healthy.
                    if time.monotonic() - self.last_datachannel_pointer >= 0.5:
                        self._inject_pointer_move(message.get("x", 0), message.get("y", 0))
                else:
                    self._handle_input_message(message)
        except Exception as exc:
            self.gui_events.put(("status", "控制连接已断开：{}".format(exc)))
        finally:
            self.input.release_all()
            with self.control_lock:
                if self.control_channel is channel:
                    self.control_channel = None
            channel.close()

    def _handle_input_message(self, message: Dict) -> None:
        if message.get("type") == "mouse_button" and "x" in message and "y" in message:
            # Click carries its own position so a discarded pointer move can
            # never make the action land on an old pixel.
            self._inject_pointer_move(message["x"], message["y"])
        with self.input_lock:
            self.input.handle(
                json.dumps(message, ensure_ascii=False).encode("utf-8")
            )

    def _send_control(self, message: Dict) -> None:
        with self.control_lock:
            channel = self.control_channel
        if channel is not None:
            try:
                channel.send(message)
            except Exception:
                pass

    def _clipboard_tick(self) -> None:
        if not self.running.is_set():
            return
        try:
            text = self.root.clipboard_get()
        except tk.TclError:
            text = None
        if text is not None and text != self.last_clipboard:
            self.last_clipboard = text
            self._send_control({"type": "clipboard", "text": text[:1_000_000]})
        self.root.after(500, self._clipboard_tick)

    def _poll(self) -> None:
        while True:
            try:
                kind, value = self.gui_events.get_nowait()
            except queue.Empty:
                break
            if kind == "status":
                self.status(value)
            elif kind == "clipboard":
                self.last_clipboard = value
                try:
                    self.root.clipboard_clear()
                    self.root.clipboard_append(value)
                except tk.TclError:
                    pass
        if not self.running.is_set():
            return
        if self.pipeline is None:
            self.root.after(100, self._poll)
            return
        bus = self.pipeline.get_bus()
        message = bus.pop_filtered(self.Gst.MessageType.ERROR | self.Gst.MessageType.EOS)
        if message is not None:
            if message.type == self.Gst.MessageType.ERROR:
                error, debug = message.parse_error()
                detail = "{} ({})".format(error, debug or "")
            else:
                detail = "视频管线已停止"
            self._schedule_video_restart(detail)
            self.root.after(100, self._poll)
            return
        self.root.after(100, self._poll)

    def _schedule_video_restart(self, detail: str) -> None:
        """Keep the host available when a network/media failure kills WebRTC."""
        if not self.running.is_set():
            return
        self._stop_video_pipeline()
        if self.video_restart_scheduled:
            return
        self.video_restart_attempt += 1
        delay = min(10, 2 ** min(self.video_restart_attempt - 1, 3))
        self.video_restart_scheduled = True
        self.status(
            "被控端视频暂时中断：{}；{} 秒后自动重建，监听与会合保持运行".format(
                detail, delay
            )
        )
        self.root.after(delay * 1000, self._restart_video_pipeline)

    def _restart_video_pipeline(self) -> None:
        self.video_restart_scheduled = False
        if not self.running.is_set() or self.pipeline is not None:
            return
        try:
            # Recreate webrtcsink and its local signalling server. This clears
            # stale ICE/DTLS state after an interface/public-address change,
            # while the host's externally reachable listeners stay alive.
            self.native_ice_addresses = native_route_addresses()
            self.native_ice_announced = False
            self._start_video_pipeline(self.video_backend)
        except Exception as exc:
            self._schedule_video_restart(str(exc))
            return
        self.video_restart_attempt = 0
        self.status("被控端视频服务已恢复，正在等待控制端重新连接")
        self._send_control(self._host_info_message())

    def _stop_video_pipeline(self) -> None:
        """Tear down only media state; keep host TCP/proxy listeners alive."""
        pipeline, self.pipeline = self.pipeline, None
        for consumer_pipeline in self.consumer_pipelines.values():
            try:
                consumer_pipeline.get_bus().set_sync_handler(None)
            except Exception:
                pass
            try:
                consumer_pipeline.set_state(self.Gst.State.NULL)
                consumer_pipeline.get_state(2 * self.Gst.SECOND)
            except Exception:
                pass
        self.consumer_pipelines.clear()
        self.explicit_encoder = None
        self.host_caps = None
        with self.video_adaptation_lock:
            self.consumer_encoders.clear()
        self.web_sink = None
        self.adaptive_rate = None
        self.gcc_estimates.clear()
        self.configured_rtx_elements.clear()
        self.configured_ice_elements.clear()
        self.client_bitrate_ceiling = None
        self.feedback_healthy_count = 0
        self.feedback_stale_count = 0
        for pointer_channel in self.pointer_channel_refs:
            try:
                pointer_channel.emit("close")
            except Exception:
                pass
        self.pointer_channels.clear()
        self.pointer_channel_refs.clear()
        for input_channel in self.input_channel_refs:
            try:
                input_channel.emit("close")
            except Exception:
                pass
        self.input_channels.clear()
        self.input_channel_refs.clear()
        if pipeline is not None:
            try:
                pipeline.set_state(self.Gst.State.NULL)
                pipeline.get_state(3 * self.Gst.SECOND)
            except Exception:
                pass

    def stop(self) -> None:
        self.running.clear()
        self.video_restart_scheduled = False
        if self.proxy is not None:
            self.proxy.close()
            self.proxy = None
        if self.listener is not None:
            self.listener.close()
            self.listener = None
        with self.control_lock:
            channel, self.control_channel = self.control_channel, None
        if channel is not None:
            channel.close()
        self.input.release_all()
        self._stop_video_pipeline()


class ClientRuntime:
    def __init__(self, window: tk.Toplevel, settings: ClientSettings):
        self.window = window
        self.settings = settings
        self.Gst, self.GstVideo = _load_gst_video()
        self.pipeline = None
        self.channel: Optional[SecureChannel] = None
        self.sender: Optional[LatestMessageSender] = None
        self.events: "queue.Queue[tuple]" = queue.Queue()
        self.host_width = 16
        self.host_height = 9
        self.host_pixel_aspect_num = 1
        self.host_pixel_aspect_den = 1
        self.host_capture_width = 16
        self.host_capture_height = 9
        self.host_capture_pixel_aspect_num = 1
        self.host_capture_pixel_aspect_den = 1
        self.host_capture_letterboxed = False
        self.host_max_width = 16
        self.host_max_height = 9
        self.host_max_fps = 1
        self.video_render_rect = (0, 0, 1, 1)
        self.forward_input = True
        self.last_clipboard = None
        self.key_ids = set()
        self.video_frames = 0
        self.video_ready = False
        self.video_started_at = 0.0
        self.video_handle = 0
        self.video_sink = None
        self.video_probe = None
        self.video_caps_reported = False
        self.video_caps_text = ""
        self.recovery_elements = set()
        self.host_info_text = "控制通道已认证"
        self.pointer_channel = None
        self.pointer_channel_ready = False
        self.pointer_datachannel_confirmed = False
        self.pointer_sequence = 0
        self.pending_pointer = None
        self.pointer_flush_scheduled = False
        self.last_pointer_fallback = 0.0
        self.input_channel = None
        self.input_channel_ready = False
        self.input_sequence = 0
        self.peer_route = classify_peer_address(self.settings.peer)
        self.client_webrtcbin = None
        self.last_ice_stats_request = 0.0
        self.last_ice_route = ""
        self.network_stats_text = ""
        self.decode_fps_text = ""
        self.adaptation_text = ""
        self.fps_window_started = time.monotonic()
        self.fps_window_frames = 0
        self.actual_decode_fps = 0.0
        self.last_video_frame_at = 0.0
        self.last_video_feedback = 0.0
        self.expected_sender_fps = 0
        self.last_inbound_bytes = None
        self.last_packet_totals = None
        self.native_ice_addresses = native_route_addresses()
        self.native_ice_announced = False
        self.ice_configuration_attempted = False
        self.media_restart_pending = False
        self.media_restart_attempts = 0
        self.control_connecting = False
        self.control_connect_lock = threading.Lock()
        self.clipboard_started = False
        self.closing = False
        self.closed = False
        self.bus = None
        self.bus_sync_handler_id = None
        self.pipeline_handler_id = None
        self.probe_handler_id = None
        self._build_window()

    def _build_window(self) -> None:
        self.window.title("rdesk V2 - 控制端")
        self.window.geometry("1280x760")
        toolbar = ttk.Frame(self.window, padding=(8, 5))
        toolbar.pack(fill="x")
        self.status_var = tk.StringVar(value="正在连接…")
        status_label = ttk.Label(toolbar, textvariable=self.status_var)
        quality = ttk.Frame(toolbar)
        quality.pack(side="right", padx=(10, 0))
        self.quality_resolution_var = tk.StringVar(value="等待能力信息")
        self.quality_resolution_box = ttk.Combobox(
            quality,
            textvariable=self.quality_resolution_var,
            state="disabled",
            width=21,
        )
        self.quality_resolution_box.pack(side="left", padx=(0, 5))
        self.quality_fps_var = tk.StringVar(value="-")
        self.quality_fps_box = ttk.Combobox(
            quality,
            textvariable=self.quality_fps_var,
            state="disabled",
            width=4,
        )
        self.quality_fps_box.pack(side="left")
        ttk.Label(quality, text="FPS").pack(side="left", padx=(3, 5))
        self.quality_apply_button = ttk.Button(
            quality,
            text="应用画质",
            command=self._request_video_config,
            state="disabled",
        )
        self.quality_apply_button.pack(side="left", padx=(0, 8))
        self.input_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            quality,
            text="转发鼠标键盘（F12）",
            variable=self.input_var,
            command=lambda: setattr(self, "forward_input", self.input_var.get()),
        ).pack(side="right")
        status_label.pack(side="left", fill="x", expand=True)
        self.video = tk.Frame(self.window, background="black", takefocus=True)
        self.video.pack(fill="both", expand=True)
        for sequence, callback in (
            ("<Motion>", self._mouse_move),
            ("<ButtonPress>", self._mouse_button_down),
            ("<ButtonRelease>", self._mouse_button_up),
            ("<MouseWheel>", self._mouse_wheel),
            ("<KeyPress>", self._key_down),
            ("<KeyRelease>", self._key_up),
            ("<FocusOut>", self._release_all),
        ):
            self.video.bind(sequence, callback)
        self.video.bind("<Button-4>", lambda event: self._linux_wheel(1))
        self.video.bind("<Button-5>", lambda event: self._linux_wheel(-1))
        self.video.bind("<Configure>", self._video_resized, add="+")
        self.window.protocol("WM_DELETE_WINDOW", self.close)

    def _update_quality_controls(self, info: Dict) -> None:
        self.host_max_width = max(1, int(info.get("max_width", info.get("width", 16))))
        self.host_max_height = max(1, int(info.get("max_height", info.get("height", 9))))
        self.host_max_fps = max(1, int(info.get("max_fps", info.get("fps", 1))))
        modes = []
        for item in info.get("resolution_options", ()):
            try:
                width, height = int(item["width"]), int(item["height"])
                validate_video_request(
                    width,
                    height,
                    1,
                    self.host_max_width,
                    self.host_max_height,
                    self.host_max_fps,
                )
                modes.append((width, height))
            except (KeyError, TypeError, ValueError):
                continue
        if not modes:
            modes = available_video_resolutions(
                self.host_max_width, self.host_max_height
            )
        current = (
            max(1, int(info.get("width", self.host_max_width))),
            max(1, int(info.get("height", self.host_max_height))),
        )
        if current not in modes:
            modes.append(current)
        modes = sorted(set(modes), key=lambda item: (item[0] * item[1], item))
        self.quality_resolution_box.configure(
            values=[format_video_resolution(*item) for item in modes],
            state="readonly",
        )
        self.quality_resolution_var.set(format_video_resolution(*current))
        common_fps = {
            10, 15, 20, 24, 25, 30, 45, 50, 60, 90, 120, self.host_max_fps
        }
        fps_values = sorted(value for value in common_fps if value <= self.host_max_fps)
        current_fps = max(1, int(info.get("fps", self.host_max_fps)))
        if current_fps not in fps_values:
            fps_values.append(current_fps)
            fps_values.sort()
        self.quality_fps_box.configure(
            values=[str(value) for value in fps_values], state="readonly"
        )
        self.quality_fps_var.set(str(current_fps))
        self.quality_apply_button.configure(state="normal")

    def _request_video_config(self) -> None:
        try:
            width, height = parse_video_resolution(
                self.quality_resolution_var.get()
            )
            width, height, fps = validate_video_request(
                width,
                height,
                int(self.quality_fps_var.get()),
                self.host_max_width,
                self.host_max_height,
                self.host_max_fps,
            )
        except (TypeError, ValueError) as exc:
            self.status_var.set("画质设置无效：{}".format(exc))
            return
        self._send(
            {"type": "video_config", "width": width, "height": height, "fps": fps}
        )
        self.status_var.set(
            "已请求切换至 {}x{} @ {} FPS，等待被控端确认…".format(
                width, height, fps
            )
        )

    def _set_composed_status(self, extra: str = "") -> None:
        parts = [self.host_info_text]
        if self.video_ready:
            parts.append("实际视频 " + (self.video_caps_text or "首帧已显示"))
        else:
            parts.append("正在等待视频首帧")
        if self.decode_fps_text:
            parts.append(self.decode_fps_text)
        if self.adaptation_text:
            parts.append(self.adaptation_text)
        if self.last_ice_route:
            parts.append("媒体路由 " + self.last_ice_route)
        if self.network_stats_text:
            parts.append(self.network_stats_text)
        if extra:
            parts.append(extra)
        self.status_var.set("；".join(parts))

    def start(self) -> None:
        self.settings.validate()
        self.status_var.set("正在后台建立控制连接…")
        self.window.after(100, self._poll)
        self._start_control_connect()

    def _start_control_connect(self) -> None:
        with self.control_connect_lock:
            if self.closing or self.control_connecting:
                return
            self.control_connecting = True
        threading.Thread(
            target=self._control_connect_worker,
            name="v2-client-connect",
            daemon=True,
        ).start()

    def _control_connect_worker(self) -> None:
        attempt = 0
        while not self.closing:
            attempt += 1
            sock = None
            try:
                self.events.put(
                    ("connect_status", "正在认证控制通道（第 {} 次）…".format(attempt))
                )
                sock = happy_eyeballs_connect(
                    self.settings.peer, self.settings.control_port, timeout=5
                )
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.settimeout(5)
                connected_peer = str(sock.getpeername()[0])
                channel = client_handshake(sock, self.settings.password)
                sock.settimeout(None)
                if self.closing:
                    channel.close()
                    return
                self.peer_route = classify_peer_address(connected_peer)
                self.channel = channel
                self.input_sequence = 0
                sender = LatestMessageSender(channel)
                self.sender = sender
                sender.start()
                if self.closing:
                    if self.sender is sender:
                        self.sender = None
                    if self.channel is channel:
                        self.channel = None
                    sender.close()
                    return
                with self.control_connect_lock:
                    self.control_connecting = False
                self.events.put(("control_ready", connected_peer))
                threading.Thread(
                    target=self._receive_loop,
                    args=(channel,),
                    name="v2-client-recv",
                    daemon=True,
                ).start()
                return
            except Exception as exc:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
                if self.closing:
                    return
                delay = min(3.0, 0.25 * (2 ** min(4, attempt - 1)))
                self.events.put(
                    (
                        "connect_status",
                        "控制握手失败：{}；{:.1f} 秒后自动重试".format(exc, delay),
                    )
                )
                time.sleep(delay)
        with self.control_connect_lock:
            self.control_connecting = False

    def _start_media_pipeline(self, connected_peer: str) -> None:
        self.window.update_idletasks()
        # Use the route that won the control-channel IPv6/IPv4 race so the
        # WebSocket layer does not stall on the losing address family again.
        media_settings = ClientSettings(**vars(self.settings))
        media_settings.peer = connected_peer
        description = build_client_pipeline(
            media_settings, windows=sys.platform.startswith("win")
        )
        self.pipeline = self.Gst.parse_launch(description)
        # The depayloader and decoder are created dynamically after SDP/caps
        # negotiation. Configure them as soon as they appear, before damaged
        # reference frames can be displayed for a whole GOP.
        self.pipeline_handler_id = self.pipeline.connect(
            "deep-element-added", self._media_element_added
        )
        sink = self.pipeline.get_by_name("video_sink")
        if sink is None:
            raise RuntimeError("没有找到视频显示组件")
        self.video_sink = sink
        probe = self.pipeline.get_by_name("video_probe")
        if probe is None:
            raise RuntimeError("没有找到视频首帧检测组件")
        self.probe_handler_id = probe.connect("handoff", self._video_handoff)
        self.video_probe = probe
        bus = self.pipeline.get_bus()
        self.bus = bus
        bus.enable_sync_message_emission()
        self.bus_sync_handler_id = bus.connect(
            "sync-message::element", self._prepare_video_overlay
        )
        self.video_handle = self.video.winfo_id()
        self.GstVideo.VideoOverlay.set_window_handle(sink, self.video_handle)
        self._update_video_render_rectangle()
        result = self.pipeline.set_state(self.Gst.State.PLAYING)
        if result == self.Gst.StateChangeReturn.FAILURE:
            raise RuntimeError("WebRTC 控制端视频管线启动失败")
        self.video_started_at = time.monotonic()
        self.status_var.set(
            "控制通道已认证（{}），正在协商 WebRTC/ICE…".format(
                self.peer_route,
            )
        )
        if not self.clipboard_started:
            self.clipboard_started = True
            self.window.after(500, self._clipboard_tick)
        self.video.focus_set()

    def _media_element_added(self, _pipeline, _owner, element) -> None:
        factory = element.get_factory()
        factory_name = factory.get_name() if factory is not None else ""
        configured = []

        if factory_name == "webrtcbin":
            self.client_webrtcbin = element
            if (
                self.settings.native_interfaces_only
                and not self.ice_configuration_attempted
            ):
                self.ice_configuration_attempted = True
                ice_text = _configure_native_ice(element, self.native_ice_addresses)
                print(ice_text, file=sys.stderr, flush=True)
                if not self.native_ice_announced:
                    self.native_ice_announced = True
                    self.events.put(("ice_route", ice_text))
            element.connect("on-data-channel", self._on_data_channel)
            for property_name in ("ice-connection-state", "connection-state"):
                if element.find_property(property_name) is not None:
                    element.connect(
                        "notify::" + property_name,
                        self._client_webrtc_state_changed,
                        property_name,
                    )

        if factory_name in ("webrtcbin", "rtpbin", "rtpjitterbuffer"):
            if element.find_property("latency") is not None:
                latency = self.settings.latency_ms
                if factory_name == "rtpjitterbuffer":
                    latency = max(40, latency)
                element.set_property("latency", latency)
                configured.append("latency={}ms".format(latency))
            for name, value in (
                ("drop-on-latency", True),
                ("do-lost", True),
            ):
                if element.find_property(name) is not None:
                    element.set_property(name, value)
                    configured.append(name)

        if factory_name == "rtph264depay":
            configured.extend(_configure_h264_depayloader(element))

        if factory_name.endswith("h264dec") or factory_name in (
            "avdec_h264",
            "openh264dec",
        ):
            for name, value in (
                ("discard-corrupted-frames", True),
                ("automatic-request-sync-points", True),
                ("min-force-key-unit-interval", 0),
                ("output-corrupt", False),
            ):
                if element.find_property(name) is not None:
                    element.set_property(name, value)
                    configured.append(name)

        if configured and factory_name not in self.recovery_elements:
            self.recovery_elements.add(factory_name)
            text = "视频丢包恢复已启用：{} ({})".format(
                factory_name, ", ".join(configured)
            )
            print(text, file=sys.stderr, flush=True)
            self.events.put(("media_recovery", text))

    def _on_data_channel(self, _webrtcbin, channel) -> None:
        try:
            label = channel.get_property("label")
        except Exception:
            return
        if label == "rdesk-pointer-v1":
            self.pointer_channel = channel
            opened = self._pointer_channel_opened
            closed = self._pointer_channel_closed
        elif label == "rdesk-input-v1":
            self.input_channel = channel
            opened = self._input_channel_opened
            closed = self._input_channel_closed
        else:
            return
        channel.connect("on-open", opened)
        channel.connect("on-close", closed)
        try:
            state = channel.get_property("ready-state")
            if getattr(state, "value_nick", "") == "open":
                opened(channel)
        except Exception:
            pass

    def _pointer_channel_opened(self, _channel) -> None:
        self.pointer_channel_ready = True
        self.events.put(
            (
                "pointer_transport",
                "WebRTC 无序/不可靠 DataChannel 已打开，等待被控端确认",
            )
        )

    def _pointer_channel_closed(self, _channel) -> None:
        self.pointer_channel_ready = False
        self.pointer_datachannel_confirmed = False
        self.pointer_channel = None
        self.events.put(("pointer_transport", "鼠标 DataChannel 断开，已回退可靠通道"))

    def _input_channel_opened(self, _channel) -> None:
        self.input_channel_ready = True
        self.events.put(
            ("input_transport", "键盘与点击已切换到 WebRTC 有序可靠 DataChannel")
        )

    def _input_channel_closed(self, _channel) -> None:
        self.input_channel_ready = False
        self.input_channel = None
        self.events.put(
            ("input_transport", "可靠输入 DataChannel 断开，已回退控制通道")
        )

    def _client_webrtc_state_changed(self, webrtcbin, _spec, property_name) -> None:
        try:
            state = webrtcbin.get_property(property_name)
            state_text = getattr(state, "value_nick", str(state))
        except Exception as exc:
            state_text = "error:{}".format(exc)
        self.events.put(
            (
                "ice_state",
                "WebRTC {}={}（地址类型：{}）".format(
                    property_name, state_text, self.peer_route
                ),
            )
        )

    def _request_ice_stats(self) -> None:
        webrtcbin = self.client_webrtcbin
        if webrtcbin is None:
            return
        try:
            promise = self.Gst.Promise.new_with_change_func(
                self._ice_stats_ready, None
            )
            webrtcbin.emit("get-stats", None, promise)
        except Exception:
            pass

    def _ice_stats_ready(self, promise, _user_data=None) -> None:
        try:
            reply = promise.get_reply()
            if reply is None:
                return
            structures = {}

            def visit(structure):
                for index in range(structure.n_fields()):
                    name = structure.nth_field_name(index)
                    value = structure.get_value(name)
                    if isinstance(value, self.Gst.Structure):
                        structures[name] = value
                        stats_id = value.get_value("id") if value.has_field("id") else None
                        if stats_id:
                            structures[str(stats_id)] = value
                        visit(value)

            visit(reply)
            selected = None
            inbound_video = None
            seen = set()
            for structure in structures.values():
                marker = id(structure)
                if marker in seen:
                    continue
                seen.add(marker)
                stats_type = str(structure.get_value("type")) if structure.has_field("type") else ""
                structure_name = structure.get_name()
                state = str(structure.get_value("state")) if structure.has_field("state") else ""
                nominated = bool(structure.get_value("nominated")) if structure.has_field("nominated") else False
                chosen = bool(structure.get_value("selected")) if structure.has_field("selected") else False
                if "candidate-pair" in stats_type and state == "succeeded" and (nominated or chosen):
                    selected = structure
                if "inbound-rtp" in stats_type or "inbound-rtp" in structure_name:
                    media = ""
                    for field in ("kind", "media-type", "media-kind"):
                        if structure.has_field(field):
                            media = str(structure.get_value(field)).lower()
                            break
                    if not media or "video" in media:
                        inbound_video = structure
            if selected is None:
                return
            local_id = str(selected.get_value("local-candidate-id"))
            remote_id = str(selected.get_value("remote-candidate-id"))
            candidates = [structures.get(local_id), structures.get(remote_id)]
            types = {
                str(item.get_value("candidate-type"))
                for item in candidates
                if item is not None and item.has_field("candidate-type")
            }
            addresses = []
            for item in candidates:
                if item is None:
                    continue
                for field in ("address", "ip", "candidate-address"):
                    if item.has_field(field):
                        address = str(item.get_value(field))
                        if address and address not in addresses:
                            addresses.append(address)
                        break
            if "relay" in types:
                route = "TURN 中继"
            elif any(":" in address for address in addresses):
                route = "原生 IPv6 P2P 直连"
            elif "srflx" in types or "prflx" in types:
                route = "公网 IPv4 NAT P2P 直连"
            elif "host" in types:
                route = "ICE host-host 直连"
            else:
                route = "ICE 直连（候选类型 {}）".format(
                    ",".join(sorted(types)) or "unknown"
                )
            if addresses:
                route += " [{}]".format(" ↔ ".join(addresses))
            if route != self.last_ice_route:
                self.last_ice_route = route
                self.events.put(("ice_route", route))

            def number(structure, *fields):
                if structure is None:
                    return None
                for field in fields:
                    if structure.has_field(field):
                        try:
                            return float(structure.get_value(field))
                        except (TypeError, ValueError):
                            pass
                return None

            parts = []
            rtt = number(selected, "current-round-trip-time", "round-trip-time")
            if rtt is not None:
                rtt_ms = rtt * 1000 if rtt <= 10 else rtt
                parts.append("RTT {:.0f} ms".format(rtt_ms))
            available = number(
                selected,
                "available-incoming-bitrate",
                "available-outgoing-bitrate",
            )
            if available is not None and available > 0:
                parts.append("ICE 可用 {:.1f} Mbps".format(available / 1_000_000))

            now = time.monotonic()
            received_bytes = number(inbound_video, "bytes-received")
            if received_bytes is not None:
                if self.last_inbound_bytes is not None:
                    previous_bytes, previous_time = self.last_inbound_bytes
                    elapsed = max(0.001, now - previous_time)
                    rate = max(0.0, received_bytes - previous_bytes) * 8 / elapsed
                    parts.append("接收 {:.1f} Mbps".format(rate / 1_000_000))
                self.last_inbound_bytes = (received_bytes, now)

            received = number(inbound_video, "packets-received")
            lost = number(inbound_video, "packets-lost")
            if received is not None and lost is not None:
                if self.last_packet_totals is not None:
                    old_received, old_lost = self.last_packet_totals
                    received_delta = max(0.0, received - old_received)
                    lost_delta = max(0.0, lost - old_lost)
                    total_delta = received_delta + lost_delta
                    if total_delta:
                        parts.append("丢包 {:.1f}%".format(100 * lost_delta / total_delta))
                self.last_packet_totals = (received, lost)
            jitter = number(inbound_video, "jitter")
            if jitter is not None:
                jitter_ms = jitter * 1000 if jitter <= 10 else jitter
                parts.append("抖动 {:.0f} ms".format(jitter_ms))
            if parts:
                self.events.put(("network_stats", " / ".join(parts)))
        except Exception:
            # Stats differ slightly across GStreamer releases. Connection and
            # input must keep working even when a vendor omits optional fields.
            return

    def _video_resized(self, event) -> None:
        """Keep rendering and pointer mapping on one identical rectangle."""
        if (
            self.closing
            or self.video_sink is None
            or event.width <= 1
            or event.height <= 1
        ):
            return
        self._update_video_render_rectangle(event.width, event.height)
        try:
            self.GstVideo.VideoOverlay.expose(self.video_sink)
        except Exception:
            pass

    def _update_video_render_rectangle(self, width=None, height=None) -> None:
        native = _windows_client_size(
            getattr(self, "video_handle", 0)
        )
        if native is not None:
            width, height = native
        else:
            width = self.video.winfo_width() if width is None else int(width)
            height = self.video.winfo_height() if height is None else int(height)
        if width <= 1 or height <= 1:
            return
        rectangle = content_render_rectangle(
            width,
            height,
            self.host_width,
            self.host_height,
            self.host_pixel_aspect_num,
            self.host_pixel_aspect_den,
        )
        self.video_render_rect = rectangle
        if self.video_sink is not None:
            # Do not let the native sink independently choose a subtly
            # different aspect-fit rectangle.  Even a small width difference
            # compresses pointer coordinates around the centre: the remote
            # pointer lands right of the local pointer on the left half and
            # left of it on the right half, with error growing at the edges.
            # Supplying the exact same native-pixel rectangle used below for
            # input mapping keeps presentation and pointer geometry identical.
            try:
                self.GstVideo.VideoOverlay.set_render_rectangle(
                    self.video_sink, *rectangle
                )
            except Exception as exc:
                self.events.put(("video_overlay_error", str(exc)))

    def _prepare_video_overlay(self, _bus, message) -> None:
        """Bind native sinks when they request a window during state change."""
        if self.closing or not self.video_handle:
            return
        try:
            is_prepare = self.GstVideo.is_video_overlay_prepare_window_handle_message(
                message
            )
        except (AttributeError, TypeError):
            is_prepare = message.get_structure() is not None and (
                message.get_structure().get_name() == "prepare-window-handle"
            )
        if not is_prepare:
            return
        try:
            self.GstVideo.VideoOverlay.set_window_handle(
                message.src, self.video_handle
            )
        except Exception as exc:
            self.events.put(("video_overlay_error", str(exc)))

    def _video_handoff(self, identity, *_args) -> None:
        if self.closing:
            return
        self.video_frames += 1
        self.fps_window_frames += 1
        now = time.monotonic()
        self.last_video_frame_at = now
        self.media_restart_attempts = 0
        elapsed = now - self.fps_window_started
        if elapsed >= 1.0:
            actual_fps = self.fps_window_frames / elapsed
            self.actual_decode_fps = actual_fps
            self.fps_window_frames = 0
            self.fps_window_started = now
            self.events.put(("video_rate", actual_fps))
        try:
            caps = identity.get_static_pad("sink").get_current_caps()
            caps_text = caps.to_string() if caps is not None else "unknown"
            if caps is not None and caps.get_size() > 0:
                structure = caps.get_structure(0)
                width = int(structure.get_value("width"))
                height = int(structure.get_value("height"))
                pixel_format = structure.get_value("format")
                pixel_aspect_num, pixel_aspect_den = 1, 1
                try:
                    ok, par_num, par_den = structure.get_fraction("pixel-aspect-ratio")
                    if ok and par_num > 0 and par_den > 0:
                        pixel_aspect_num, pixel_aspect_den = int(par_num), int(par_den)
                except Exception:
                    pass
                caps_summary = "{}x{} {} PAR {}/{}".format(
                    width, height, pixel_format, pixel_aspect_num, pixel_aspect_den
                )
                caps_key = (
                    width,
                    height,
                    str(pixel_format),
                    pixel_aspect_num,
                    pixel_aspect_den,
                )
            else:
                caps_summary = caps_text
                caps_key = (caps_text,)
        except Exception as exc:
            caps_text = "读取失败：{}".format(exc)
            caps_summary = caps_text
            caps_key = (caps_text,)
        if caps_key != getattr(self, "last_video_caps_key", None):
            self.last_video_caps_key = caps_key
            self.video_caps_reported = True
            print("客户端视频 caps: {}".format(caps_text), file=sys.stderr, flush=True)
            self.events.put(
                (
                    "video_caps",
                    {
                        "summary": caps_summary,
                        "width": width if len(caps_key) == 5 else None,
                        "height": height if len(caps_key) == 5 else None,
                        "pixel_aspect_num": pixel_aspect_num if len(caps_key) == 5 else 1,
                        "pixel_aspect_den": pixel_aspect_den if len(caps_key) == 5 else 1,
                    },
                )
            )
        if not self.video_ready:
            self.video_ready = True
            self.events.put(("video_ready", {}))

    def _receive_loop(self, channel: SecureChannel) -> None:
        try:
            while self.pipeline is not None or self.sender is not None:
                value = channel.recv()
                self.events.put((value.get("type", "message"), value))
        except Exception as exc:
            self.events.put(("control_error", channel, str(exc)))

    def _schedule_media_restart(self, detail: str) -> None:
        if self.closing or self.pipeline is None or self.media_restart_pending:
            return
        self.media_restart_pending = True
        self.media_restart_attempts += 1
        delay = min(8.0, 1.0 * (2 ** min(3, self.media_restart_attempts - 1)))
        self.status_var.set(
            "信令连接中断，{:.0f} 秒后自动重连（{}）".format(delay, detail)
        )
        self.window.after(int(delay * 1000), self._restart_media_pipeline)

    def _restart_media_pipeline(self) -> None:
        if self.closing or self.pipeline is None:
            self.media_restart_pending = False
            return
        pipeline = self.pipeline
        try:
            pipeline.set_state(self.Gst.State.NULL)
            pipeline.get_state(2 * self.Gst.SECOND)
            bus = pipeline.get_bus()
            while bus.pop_filtered(self.Gst.MessageType.ERROR | self.Gst.MessageType.EOS):
                pass
            self.video_ready = False
            self.video_started_at = 0.0
            self.client_webrtcbin = None
            self.ice_configuration_attempted = False
            self.pointer_channel = None
            self.pointer_channel_ready = False
            self.pointer_datachannel_confirmed = False
            self.input_channel = None
            self.input_channel_ready = False
            self.input_sequence = 0
            self.recovery_elements.clear()
            self._send({"type": "reset_input_session"})
            self.GstVideo.VideoOverlay.set_window_handle(
                self.video_sink, self.video_handle
            )
            result = pipeline.set_state(self.Gst.State.PLAYING)
            if result == self.Gst.StateChangeReturn.FAILURE:
                raise RuntimeError("WebRTC 管线重新启动失败")
            self.video_started_at = time.monotonic()
            self.media_restart_pending = False
            self.status_var.set("正在重新建立 WebRTC/ICE 媒体会话…")
        except Exception as exc:
            self.media_restart_pending = False
            self._schedule_media_restart(str(exc))

    def _content_coordinates(self, x: int, y: int):
        # Tk gives the event position and widget dimensions in the same
        # coordinate space.  The shared helper reverses both aspect fits: the
        # controller's native video rectangle and the host scaler's inner
        # capture rectangle.  Either omitted transform creates an error that
        # grows symmetrically away from the centre.
        widget_width = max(1, int(self.video.winfo_width()))
        widget_height = max(1, int(self.video.winfo_height()))
        return map_content_coordinates(
            x,
            y,
            widget_width,
            widget_height,
            self.host_width,
            self.host_height,
            self.host_pixel_aspect_num,
            self.host_pixel_aspect_den,
            getattr(self, "host_capture_width", self.host_width),
            getattr(self, "host_capture_height", self.host_height),
            getattr(self, "host_capture_pixel_aspect_num", 1),
            getattr(self, "host_capture_pixel_aspect_den", 1),
            getattr(self, "host_capture_letterboxed", False),
        )

    def _send(self, value: Dict) -> None:
        if self.sender is not None:
            try:
                self.sender.send(value)
            except queue.Full:
                self.status_var.set("控制消息队列已满")

    def _send_input(self, value: Dict) -> None:
        self.input_sequence += 1
        value = dict(value)
        value["order"] = self.input_sequence
        channel = self.input_channel
        if channel is not None and self.input_channel_ready:
            try:
                buffered = (
                    int(channel.get_property("buffered-amount"))
                    if channel.find_property("buffered-amount") is not None
                    else 0
                )
                if buffered <= 262_144:
                    result = channel.send_string_full(
                        json.dumps(value, ensure_ascii=False, separators=(",", ":"))
                    )
                    if result is not False:
                        return
            except Exception:
                self.input_channel_ready = False
        self._send(value)

    def _mouse_move(self, event) -> None:
        if not self.forward_input:
            return
        point = self._content_coordinates(event.x, event.y)
        if point is not None:
            # Tk can emit multiple motion events per millisecond. Only the
            # latest coordinate is useful; flushing at 125 Hz prevents stale
            # positions from accumulating in SCTP while remaining responsive.
            self.pending_pointer = point
            if not self.pointer_flush_scheduled:
                self.pointer_flush_scheduled = True
                self.window.after(8, self._flush_pointer_move)

    def _flush_pointer_move(self) -> None:
        self.pointer_flush_scheduled = False
        point, self.pending_pointer = self.pending_pointer, None
        if point is None or self.closing or not self.forward_input:
            return
        self.pointer_sequence += 1
        sent_datachannel = False
        channel = self.pointer_channel
        if channel is not None and self.pointer_channel_ready:
            try:
                buffered = (
                    int(channel.get_property("buffered-amount"))
                    if channel.find_property("buffered-amount") is not None
                    else 0
                )
                if buffered <= 16_384:
                    channel.send_string_full(
                        json.dumps(
                            {
                                "type": "pointer",
                                "x": point[0],
                                "y": point[1],
                                "seq": self.pointer_sequence,
                            },
                            separators=(",", ":"),
                        )
                    )
                    sent_datachannel = True
            except Exception:
                self.pointer_channel_ready = False
        now = time.monotonic()
        fallback_interval = 1.0 if sent_datachannel else 0.05
        if now - self.last_pointer_fallback >= fallback_interval:
            self.last_pointer_fallback = now
            self._send(
                {
                    "type": "mouse_move",
                    "x": point[0],
                    "y": point[1],
                    "seq": self.pointer_sequence,
                }
            )
        if self.pending_pointer is not None and not self.pointer_flush_scheduled:
            self.pointer_flush_scheduled = True
            self.window.after(8, self._flush_pointer_move)

    @staticmethod
    def _button_name(number: int) -> Optional[str]:
        return {1: "left", 2: "middle", 3: "right"}.get(number)

    def _mouse_button_down(self, event) -> None:
        self.video.focus_set()
        if not self.forward_input:
            return
        button = self._button_name(event.num)
        if button:
            point = self._content_coordinates(event.x, event.y)
            value = {"type": "mouse_button", "button": button, "down": True}
            if point is not None:
                value.update({"x": point[0], "y": point[1]})
            self._send_input(value)

    def _mouse_button_up(self, event) -> None:
        if not self.forward_input:
            return
        button = self._button_name(event.num)
        if button:
            point = self._content_coordinates(event.x, event.y)
            value = {"type": "mouse_button", "button": button, "down": False}
            if point is not None:
                value.update({"x": point[0], "y": point[1]})
            self._send_input(value)

    def _mouse_wheel(self, event) -> None:
        if self.forward_input:
            self._send_input(
                {"type": "mouse_wheel", "dx": 0, "dy": int(event.delta / 120)}
            )

    def _linux_wheel(self, direction: int):
        if self.forward_input:
            self._send_input({"type": "mouse_wheel", "dx": 0, "dy": direction})
        return "break"

    def _key_down(self, event):
        if event.keysym == "F12":
            self.forward_input = not self.forward_input
            self.input_var.set(self.forward_input)
            if not self.forward_input:
                self._release_all()
            return "break"
        if not self.forward_input:
            return None
        key_id = "key:{}".format(event.keycode)
        if key_id in self.key_ids:
            return "break"
        self.key_ids.add(key_id)
        self._send_input(
            {
                "type": "key_down",
                "id": key_id,
                "keysym": event.keysym,
                "char": event.char,
            }
        )
        return "break"

    def _key_up(self, event):
        key_id = "key:{}".format(event.keycode)
        self.key_ids.discard(key_id)
        if self.forward_input:
            self._send_input(
                {
                    "type": "key_up",
                    "id": key_id,
                    "keysym": event.keysym,
                    "char": event.char,
                }
            )
        return "break"

    def _release_all(self, _event=None) -> None:
        self.key_ids.clear()
        self._send_input({"type": "release_all"})

    def _clipboard_tick(self) -> None:
        if self.closing or self.pipeline is None:
            return
        if self.settings.clipboard:
            try:
                text = self.window.clipboard_get()
            except tk.TclError:
                text = None
            if text is not None and text != self.last_clipboard:
                self.last_clipboard = text
                self._send({"type": "clipboard", "text": text[:1_000_000]})
        self.window.after(500, self._clipboard_tick)

    def _poll(self) -> None:
        if self.closing:
            return
        while True:
            try:
                current_event = self.events.get_nowait()
            except queue.Empty:
                break
            kind = current_event[0]
            value = current_event[1] if len(current_event) > 1 else None
            if kind == "control_ready":
                try:
                    if self.pipeline is None:
                        self._start_media_pipeline(str(value))
                    else:
                        self.status_var.set("控制通道已重新认证，媒体连接保持中")
                except Exception as exc:
                    self.status_var.set("视频管线启动失败：{}".format(exc))
            elif kind == "connect_status":
                self.status_var.set(str(value))
            elif kind == "control_error":
                failed_channel = value
                detail = current_event[2]
                if self.channel is failed_channel:
                    sender, self.sender = self.sender, None
                    self.channel = None
                    if sender is not None:
                        sender.close()
                    self.status_var.set(
                        "控制连接断开：{}；正在后台重连".format(detail)
                    )
                    self._start_control_connect()
            elif kind == "host_info":
                announced_width = max(1, int(value.get("width", 16)))
                announced_height = max(1, int(value.get("height", 9)))
                if not self.video_ready:
                    self.host_width = announced_width
                    self.host_height = announced_height
                    self.host_pixel_aspect_num = 1
                    self.host_pixel_aspect_den = 1
                    self._update_video_render_rectangle()
                self._update_quality_controls(value)
                self.host_info_text = "已认证；远端 {}x{} @ {} FPS；输入 {}".format(
                    announced_width,
                    announced_height,
                    value.get("fps", "?"),
                    value.get("input_backend", "?"),
                )
                self.host_info_text += "；视频 {}".format(
                    value.get("video_backend", "unknown")
                )
                capture_width = max(
                    1, int(value.get("capture_width", self.host_width))
                )
                capture_height = max(
                    1, int(value.get("capture_height", self.host_height))
                )
                self.host_capture_width = capture_width
                self.host_capture_height = capture_height
                self.host_capture_pixel_aspect_num = max(
                    1, int(value.get("capture_pixel_aspect_num", 1))
                )
                self.host_capture_pixel_aspect_den = max(
                    1, int(value.get("capture_pixel_aspect_den", 1))
                )
                self.host_capture_letterboxed = (
                    value.get("capture_scale_mode") == "letterbox"
                )
                input_width = max(1, int(value.get("input_width", capture_width)))
                input_height = max(1, int(value.get("input_height", capture_height)))
                self.host_info_text += "；采集 {}x{} / 输入桌面 {}x{}".format(
                    capture_width, capture_height, input_width, input_height
                )
                self._set_composed_status()
            elif kind == "video_config_applied":
                self.quality_resolution_var.set(
                    format_video_resolution(value.get("width"), value.get("height"))
                )
                self.quality_fps_var.set(str(value.get("fps")))
                self.adaptation_text = "画质已确认 {}x{} @ {} FPS（上限 {}x{} @ {}）".format(
                    value.get("width"),
                    value.get("height"),
                    value.get("fps"),
                    value.get("max_width", self.host_max_width),
                    value.get("max_height", self.host_max_height),
                    value.get("max_fps", self.host_max_fps),
                )
                self._set_composed_status()
            elif kind == "video_config_rejected":
                self._set_composed_status(
                    "被控端拒绝画质设置：{}".format(value.get("reason", "未知原因"))
                )
            elif kind == "video_ready":
                self._set_composed_status()
            elif kind == "video_caps":
                summary = str(value.get("summary", "unknown"))
                actual_width = value.get("width")
                actual_height = value.get("height")
                if actual_width and actual_height:
                    # Use the actual decoded aspect ratio for letterbox and
                    # pointer mapping. This also handles live renegotiation.
                    self.host_width = max(1, int(actual_width))
                    self.host_height = max(1, int(actual_height))
                    self.host_pixel_aspect_num = max(
                        1, int(value.get("pixel_aspect_num", 1))
                    )
                    self.host_pixel_aspect_den = max(
                        1, int(value.get("pixel_aspect_den", 1))
                    )
                    self._update_video_render_rectangle()
                self.video_caps_text = summary
                self._set_composed_status()
            elif kind == "video_rate":
                self.decode_fps_text = "当前解码 {:.1f} FPS".format(float(value))
                self._set_composed_status()
            elif kind == "video_adaptation":
                try:
                    self.expected_sender_fps = max(1, int(value.get("fps", 0)))
                except (TypeError, ValueError):
                    self.expected_sender_fps = 0
                self.adaptation_text = "发送端 {:.1f} Mbps / {} FPS / {}x{}".format(
                    float(value.get("bitrate_mbps", 0)),
                    value.get("fps", "?"),
                    value.get("width", "?"),
                    value.get("height", "?"),
                )
                self._set_composed_status()
            elif kind == "video_overlay_error":
                self.status_var.set("视频窗口绑定失败：{}".format(value))
            elif kind == "media_recovery":
                self.status_var.set(str(value))
            elif kind == "pointer_datachannel_ready":
                self.pointer_datachannel_confirmed = True
                self.status_var.set(
                    self.host_info_text
                    + "；鼠标 WebRTC 无序/不可靠 DataChannel 已验证"
                )
            elif kind == "pointer_transport":
                self.status_var.set(str(value))
            elif kind == "input_transport":
                self.status_var.set(str(value))
            elif kind == "ice_state":
                self.status_var.set(str(value))
            elif kind == "ice_route":
                self.last_ice_route = str(value)
                self._set_composed_status()
            elif kind == "network_stats":
                self.network_stats_text = str(value)
                self._set_composed_status()
            elif kind == "clipboard" and self.settings.clipboard:
                text = str(value.get("text", ""))
                self.last_clipboard = text
                try:
                    self.window.clipboard_clear()
                    self.window.clipboard_append(text)
                except tk.TclError:
                    pass
            elif kind == "error":
                self.status_var.set("控制连接断开：{}".format(value))
        if self.pipeline is None:
            self.window.after(100, self._poll)
            return
        bus = self.pipeline.get_bus()
        message = bus.pop_filtered(self.Gst.MessageType.ERROR | self.Gst.MessageType.EOS)
        if message is not None:
            if message.type == self.Gst.MessageType.ERROR:
                error, debug = message.parse_error()
                detail = "{} ({})".format(error, debug or "")
                self._schedule_media_restart(detail)
            else:
                self._schedule_media_restart("视频连接已停止")
            self.window.after(100, self._poll)
            return
        if (
            not self.video_ready
            and self.video_started_at
            and time.monotonic() - self.video_started_at >= 12
        ):
            self.status_var.set(
                self.host_info_text
                + "；12 秒未收到视频帧（WebRTC/ICE 媒体未连通）"
            )
            # Only emit the timeout status once.
            self.video_started_at = 0.0
        now = time.monotonic()
        if self.video_ready and now - self.last_video_feedback >= 1.0:
            self.last_video_feedback = now
            frame_age_ms = (
                max(0.0, now - self.last_video_frame_at) * 1000
                if self.last_video_frame_at
                else 9999.0
            )
            self._send(
                {
                    "type": "video_feedback",
                    "decode_fps": round(self.actual_decode_fps, 2),
                    "frame_age_ms": round(frame_age_ms),
                    "expected_fps": self.expected_sender_fps,
                }
            )
        if now - self.last_ice_stats_request >= 3.0:
            self.last_ice_stats_request = now
            self._request_ice_stats()
        self.window.after(100, self._poll)

    def close(self) -> None:
        if self.closed or self.closing:
            return
        self.closing = True
        try:
            self._release_all()
        except Exception:
            pass
        pipeline, self.pipeline = self.pipeline, None
        if self.sender is not None:
            self.sender.close()
            self.sender = None
        self.channel = None
        channels = (self.pointer_channel, self.input_channel)
        self.pointer_channel = None
        self.input_channel = None
        self.input_channel_ready = False
        for channel in channels:
            if channel is None:
                continue
            try:
                channel.emit("close")
            except Exception:
                pass
        # Stop every Python callback before releasing the Win32 HWND.  Without
        # this ordering d3d11videosink may prepare/expose a swapchain against a
        # Tk window that has already been destroyed, which manifests as a
        # native read from 0xFFFFFFFFFFFFFFFF rather than a Python traceback.
        if self.video_probe is not None and self.probe_handler_id is not None:
            try:
                self.video_probe.disconnect(self.probe_handler_id)
            except Exception:
                pass
        self.probe_handler_id = None
        self.video_probe = None
        if pipeline is not None and self.pipeline_handler_id is not None:
            try:
                pipeline.disconnect(self.pipeline_handler_id)
            except Exception:
                pass
        self.pipeline_handler_id = None
        if self.bus is not None:
            if self.bus_sync_handler_id is not None:
                try:
                    self.bus.disconnect(self.bus_sync_handler_id)
                except Exception:
                    pass
            try:
                self.bus.disable_sync_message_emission()
            except Exception:
                pass
        self.bus_sync_handler_id = None
        self.bus = None
        if self.video_sink is not None:
            try:
                self.GstVideo.VideoOverlay.set_window_handle(self.video_sink, 0)
            except Exception:
                pass
        self.video_handle = 0
        if pipeline is not None:
            try:
                pipeline.set_state(self.Gst.State.NULL)
                pipeline.get_state(3 * self.Gst.SECOND)
            except Exception:
                pass
        self.client_webrtcbin = None
        self.ice_configuration_attempted = False
        self.video_sink = None
        self.pointer_channel = None
        self.pointer_channel_ready = False
        self.closed = True
        try:
            if self.window.winfo_exists():
                self.window.destroy()
        except tk.TclError:
            pass


def doctor() -> int:
    Gst, _ = _load_gst_video()
    required = [
        "webrtcsink",
        "webrtcsrc",
        "webrtcbin",
        "nicesrc",
        "nicesink",
        "dtlssrtpenc",
        "srtpenc",
        "srtpdec",
        "sctpenc",
        "sctpdec",
        "rtpgccbwe",
        "rtprtxsend",
        "rtprtxreceive",
        "rtpulpfecenc",
        "rtpulpfecdec",
        "rtph264pay",
        "rtph264depay",
        "h264parse",
        "decodebin",
        "videoconvert",
    ]
    required.extend(
        ["d3d11screencapturesrc", "d3d11videosink"]
        if sys.platform.startswith("win")
        else ["ximagesrc", "ximagesink"]
    )
    missing = [name for name in required if Gst.ElementFactory.find(name) is None]
    encoders = [
        "nvd3d11h264enc",
        "mfh264enc",
        "nvh264enc",
        "vah264enc",
        "vaapih264enc",
        "x264enc",
        "openh264enc",
    ]
    decoders = ["d3d11h264dec", "avdec_h264", "openh264dec"]
    available = [name for name in encoders if Gst.ElementFactory.find(name) is not None]
    available_decoders = [
        name for name in decoders if Gst.ElementFactory.find(name) is not None
    ]
    print(Gst.version_string())
    print("required:", ", ".join(required))
    print("H.264 encoders:", ", ".join(available) or "none")
    print("H.264 decoders:", ", ".join(available_decoders) or "none")
    backend, backend_text = _select_video_backend(
        Gst, sys.platform.startswith("win"), "auto"
    )
    print("selected video backend:", backend, "-", backend_text)
    pointer_stack = ["webrtcbin", "sctpenc", "sctpdec", "dtlssrtpenc"]
    print(
        "pointer DataChannel stack:",
        "OK"
        if all(Gst.ElementFactory.find(name) is not None for name in pointer_stack)
        else "missing components",
    )
    native_addresses = native_route_addresses()
    print("native ICE routes:", ", ".join(native_addresses) or "none")
    print(
        "native IPv6:",
        "OK" if any(":" in address for address in native_addresses) else "unavailable",
    )
    print(
        "native IPv4:",
        "OK" if any("." in address for address in native_addresses) else "unavailable",
    )
    try:
        listener = create_tcp_listener("::", 0)
        dual_stack = (
            listener.family == socket.AF_INET6
            and listener.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 0
        )
        listener.close()
        print("signalling/control dual-stack listener:", "OK" if dual_stack else "IPv4 fallback")
    except OSError as exc:
        print("signalling/control listener: unavailable -", exc)
    if missing or not available or not available_decoders:
        absent = list(missing)
        if not available:
            absent.append("H.264 encoder")
        if not available_decoders:
            absent.append("H.264 decoder")
        print("missing:", ", ".join(absent))
        return 1
    print("doctor: OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="rdesk V2 WebRTC remote desktop")
    parser.add_argument("mode", nargs="?", choices=("gui", "host", "client", "doctor"), default="gui")
    args = parser.parse_args()
    if args.mode == "doctor":
        return doctor()
    enable_windows_dpi_awareness()
    root = tk.Tk()
    configure_tk_ui(root)
    Launcher(
        root,
        HostRuntime,
        ClientRuntime,
        auto_role=args.mode if args.mode in ("host", "client") else None,
    )
    root.mainloop()
    if sys.platform.startswith("win"):
        # PyGObject/GStreamer plug-ins occasionally finalize in an invalid DLL
        # order during CPython shutdown on Windows, after every rdesk pipeline
        # and HWND has already been synchronously released.  Avoid that second
        # native teardown pass; configuration and sockets are closed above.
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        finally:
            os._exit(0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
