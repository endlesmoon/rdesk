"""Tk launcher for role/mode-isolated rdesk V2 profiles."""

from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from dataclasses import asdict
from tkinter import messagebox, ttk

from rdesk_v2_platform import monitor_region
from rdesk_v2_core import (
    available_video_resolutions,
    fit_video_resolution,
    format_video_resolution,
    parse_video_resolution,
)
from rdesk_v2_profiles import (
    CONNECTION_MODES,
    MODE_DESCRIPTIONS,
    MODE_DIRECT,
    MODE_LABELS,
    MODE_MUTUAL,
    MODE_RENDEZVOUS,
    ConnectionOptions,
    ProfileRepository,
    RoleProfile,
)
from rdesk_v2_tunnel import CONTROL_STREAM, SIGNAL_STREAM, ReliableP2PTunnel


class Launcher:
    """Role-first launcher with independent profiles for every connection mode."""

    def __init__(self, root: tk.Tk, host_runtime_cls, client_runtime_cls, auto_role=None):
        self.root = root
        self.host_runtime_cls = host_runtime_cls
        self.client_runtime_cls = client_runtime_cls
        self.root.title("rdesk V2 · 远程控制中心")
        self.root.geometry("1120x790")
        self.root.minsize(960, 700)
        self.repository = ProfileRepository()
        self.role_var = tk.StringVar(value=auto_role or "host")
        self.mode_var = tk.StringVar(value=MODE_DIRECT)
        self.profile_name = tk.StringVar(value="default")
        self.selected_names = {}
        self.drafts = {}
        self.current_profile = None
        self.bindings = []
        self.field_vars = {}
        self.host_resolution_box = None
        self.host_runtime = None
        self.host_tunnel = None
        self.host_generation = 0
        self.client_windows = []
        self.task_events = queue.Queue()
        self._build()
        self._switch_context(capture=False)
        self.root.after(100, self._poll_tasks)
        if auto_role:
            action = self.start_host if auto_role == "host" else self.start_client
            self.root.after(250, action)

    def _build(self) -> None:
        header = ttk.Frame(self.root, padding=(24, 18, 24, 17), style="Hero.TFrame")
        header.pack(fill="x")
        title = ttk.Frame(header, style="Hero.TFrame")
        title.pack(side="left")
        ttk.Label(title, text="rdesk V2", style="HeroTitle.TLabel").pack(anchor="w")
        ttk.Label(
            title,
            text="原生双栈 P2P · 端到端加密 · 低延迟高清远控",
            style="HeroSub.TLabel",
        ).pack(anchor="w", pady=(3, 0))
        ttk.Label(
            header,
            text="TURN 默认禁用",
            style="HeroSub.TLabel",
        ).pack(side="right")

        body = ttk.Frame(self.root)
        body.pack(fill="both", expand=True)
        sidebar = ttk.Frame(body, width=250, padding=(16, 20), style="Sidebar.TFrame")
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        ttk.Label(sidebar, text="当前角色", style="SidebarTitle.TLabel").pack(
            fill="x", pady=(0, 8)
        )
        for value, text in (("host", "被控端"), ("client", "控制端")):
            ttk.Radiobutton(
                sidebar,
                text=text,
                value=value,
                variable=self.role_var,
                command=self._switch_context,
                style="Role.TRadiobutton",
            ).pack(fill="x", pady=2)

        ttk.Separator(sidebar).pack(fill="x", pady=18)
        ttk.Label(sidebar, text="连接方式", style="SidebarTitle.TLabel").pack(
            fill="x", pady=(0, 8)
        )
        for mode in CONNECTION_MODES:
            ttk.Radiobutton(
                sidebar,
                text=MODE_LABELS[mode],
                value=mode,
                variable=self.mode_var,
                command=self._switch_context,
                style="Mode.TRadiobutton",
            ).pack(fill="x", pady=2)
        self.mode_hint = ttk.Label(
            sidebar,
            text="",
            style="SidebarTitle.TLabel",
            wraplength=205,
            justify="left",
        )
        self.mode_hint.pack(fill="x", pady=(18, 0))

        content = ttk.Frame(body, padding=(22, 18, 22, 14))
        content.pack(side="left", fill="both", expand=True)
        toolbar = ttk.Frame(content)
        toolbar.pack(fill="x", pady=(0, 12))
        ttk.Label(toolbar, text="配置版本", style="Hint.TLabel").pack(side="left")
        self.profile_box = ttk.Combobox(
            toolbar,
            textvariable=self.profile_name,
            width=20,
        )
        self.profile_box.pack(side="left", padx=(8, 7))
        self.profile_box.bind("<<ComboboxSelected>>", lambda _event: self.load_profile())
        ttk.Button(toolbar, text="加载", command=self.load_profile).pack(side="left")
        ttk.Button(toolbar, text="保存 / 另存", command=self.save_profile).pack(
            side="left", padx=6
        )
        ttk.Label(
            toolbar,
            text="同名版本会按角色和连接方式分别保存",
            style="Hint.TLabel",
        ).pack(side="right")

        self.page_title = tk.StringVar()
        ttk.Label(content, textvariable=self.page_title, style="PageTitle.TLabel").pack(
            fill="x"
        )
        self.page_subtitle = tk.StringVar()
        ttk.Label(
            content,
            textvariable=self.page_subtitle,
            style="Hint.TLabel",
            wraplength=760,
        ).pack(fill="x", pady=(4, 14))
        self.form_area = ttk.Frame(content)
        self.form_area.pack(fill="both", expand=True)

        footer = ttk.Frame(self.root, padding=(18, 10, 18, 14))
        footer.pack(fill="x")
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(
            footer,
            textvariable=self.status_var,
            style="Status.TLabel",
            wraplength=690,
        ).pack(side="left", fill="x", expand=True)
        self.stop_button = ttk.Button(footer, text="停止被控端", command=self.stop_host)
        self.start_button = ttk.Button(
            footer, text="启动", command=self._start_selected, style="Accent.TButton"
        )
        self.start_button.pack(side="right")
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def _start_selected(self):
        return self.start_host() if self.role_var.get() == "host" else self.start_client()

    def _switch_context(self, capture=True) -> None:
        if capture:
            self._capture_draft()
        role, mode = self.role_var.get(), self.mode_var.get()
        key = (role, mode)
        name = self.selected_names.get(key, "default")
        names = self.repository.names(role, mode)
        if name not in names:
            name = "default"
        self.profile_name.set(name)
        self.profile_box.configure(values=names)
        self.current_profile = self.drafts.get(
            (role, mode, name), self.repository.load(role, mode, name)
        )
        self._rebuild_form()
        self._update_actions()

    def _capture_draft(self) -> None:
        if self.current_profile is None or not self.bindings:
            return
        try:
            profile = self._read_profile(validate=False)
        except (TypeError, ValueError, tk.TclError):
            return
        key = (profile.role, profile.mode, profile.name)
        self.drafts[key] = profile
        self.selected_names[(profile.role, profile.mode)] = profile.name

    def _update_actions(self) -> None:
        role = self.role_var.get()
        mode = self.mode_var.get()
        role_text = "被控端" if role == "host" else "控制端"
        self.page_title.set("{} · {}".format(role_text, MODE_LABELS[mode]))
        self.page_subtitle.set(MODE_DESCRIPTIONS[mode])
        self.mode_hint.configure(text=MODE_DESCRIPTIONS[mode])
        self.start_button.configure(text="启动{}".format(role_text))
        if role == "host":
            self.stop_button.pack(side="right", padx=(0, 8))
        else:
            self.stop_button.pack_forget()

    def _rebuild_form(self) -> None:
        for child in self.form_area.winfo_children():
            child.destroy()
        self.bindings = []
        self.field_vars = {}
        profile = self.current_profile
        connection = ttk.LabelFrame(
            self.form_area, text="连接与身份认证", style="Card.TLabelframe"
        )
        performance = ttk.LabelFrame(
            self.form_area, text="画面与媒体", style="Card.TLabelframe"
        )
        connection.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        performance.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        self.form_area.columnconfigure(0, weight=1, uniform="cards")
        self.form_area.columnconfigure(1, weight=1, uniform="cards")
        self.form_area.rowconfigure(0, weight=1)

        row = 0
        if profile.role == "host":
            runtime = profile.runtime
            try:
                _left, _top, display_width, display_height = monitor_region(
                    self.root, int(runtime.monitor)
                )
            except (TypeError, ValueError, tk.TclError):
                display_width = self.root.winfo_screenwidth()
                display_height = self.root.winfo_screenheight()
            runtime.width, runtime.height = fit_video_resolution(
                runtime.width,
                runtime.height,
                display_width,
                display_height,
            )
            row = self._entry(connection, row, runtime, "bind_host", "本机监听地址")
            row = self._entry(connection, row, runtime, "signal_port", "信令端口", int)
            row = self._entry(connection, row, runtime, "control_port", "控制端口", int)
            row = self._entry(
                connection, row, runtime, "internal_signal_port", "内部信令端口", int
            )
            if profile.mode == MODE_MUTUAL:
                row = self._entry(
                    connection,
                    row,
                    profile.connection,
                    "peer_host",
                    "允许的控制端 IP",
                )
            elif profile.mode == MODE_RENDEZVOUS:
                row = self._rendezvous_fields(connection, row, profile.connection)
            else:
                self._hint(
                    connection,
                    row,
                    "被控端无需填写控制端地址，启动后监听 IPv4/IPv6；控制端负责发起连接。",
                )
                row += 1
            row = self._entry(connection, row, runtime, "password", "共享密钥（可见）")

            media_row = 0
            media_row = self._resolution_entry(
                performance,
                media_row,
                runtime,
                display_width,
                display_height,
            )
            media_row = self._entry(
                performance,
                media_row,
                runtime,
                "fps",
                "允许控制端使用的最高 FPS",
                int,
                choices=tuple(
                    str(value)
                    for value in sorted(
                        {10, 15, 20, 24, 25, 30, 45, 50, 60, 90, 120, int(runtime.fps)}
                    )
                    if 1 <= value <= 120
                ),
            )
            media_row = self._entry(performance, media_row, runtime, "monitor", "显示器编号", int)
            media_row = self._entry(
                performance,
                media_row,
                runtime,
                "video_backend",
                "视频后端",
                choices=("auto", "gpu", "cpu"),
            )
            media_row = self._entry(performance, media_row, runtime, "stun_server", "STUN")
            quality = ttk.Frame(performance, style="Card.TFrame")
            quality.grid(row=media_row, column=0, columnspan=2, sticky="ew", pady=(14, 5))
            presets = (
                ("流畅 720p", 1280, 720, 30),
                ("均衡 1080p", 1920, 1080, 30),
                ("清晰 1080p60", 1920, 1080, 60),
            )
            for label, width, height, fps in presets:
                if width > display_width or height > display_height:
                    continue
                ttk.Button(
                    quality,
                    text=label,
                    command=lambda w=width, h=height, f=fps: self._set_quality(w, h, f),
                ).pack(side="left", padx=(0, 5))
            self._hint(
                performance,
                media_row + 1,
                "这里设置被控端硬上限；连接后控制端可在此范围内实时切换。当前系统最大 {}x{}。".format(
                    display_width, display_height
                ),
            )
        else:
            runtime = profile.runtime
            if profile.mode in (MODE_MUTUAL, MODE_DIRECT):
                row = self._entry(
                    connection, row, profile.connection, "peer_host", "被控端 IP / 域名"
                )
                row = self._entry(
                    connection,
                    row,
                    profile.connection,
                    "peer_signal_port",
                    "被控端信令端口",
                    int,
                )
                row = self._entry(
                    connection,
                    row,
                    profile.connection,
                    "peer_control_port",
                    "被控端控制端口",
                    int,
                )
            else:
                row = self._rendezvous_fields(connection, row, profile.connection)
            row = self._entry(connection, row, runtime, "password", "共享密钥（可见）")

            media_row = 0
            media_row = self._entry(performance, media_row, runtime, "stun_server", "STUN")
            media_row = self._entry(
                performance, media_row, runtime, "latency_ms", "接收缓冲（ms）", int
            )
            media_row = self._check(
                performance, media_row, runtime, "clipboard", "同步文本剪贴板"
            )
            self._hint(
                performance,
                media_row,
                "25 ms 适合稳定直连；弱网可设 40-60 ms。ICE 并行检查 IPv6 与 IPv4。",
            )

    def _rendezvous_fields(self, parent, row, options):
        row = self._entry(parent, row, options, "server_host", "会合服务器 IP / 域名")
        row = self._entry(parent, row, options, "server_port", "会合服务器 UDP 端口", int)
        row = self._entry(parent, row, options, "room", "会合房间名")
        return self._entry(
            parent, row, options, "local_udp_port", "本地 UDP 端口（0 自动）", int
        )

    def _entry(
        self,
        parent,
        row,
        target,
        attribute,
        label,
        converter=str,
        choices=None,
    ):
        ttk.Label(parent, text=label, style="Card.TLabel").grid(
            row=row, column=0, sticky="w", padx=(0, 12), pady=6
        )
        variable = tk.StringVar(value=str(getattr(target, attribute)))
        if choices:
            widget = ttk.Combobox(
                parent,
                textvariable=variable,
                values=choices,
                state="readonly",
                width=28,
            )
        else:
            widget = ttk.Entry(parent, textvariable=variable, width=30)
        widget.grid(row=row, column=1, sticky="ew", pady=6)
        parent.columnconfigure(1, weight=1)
        self.bindings.append((target, attribute, variable, converter))
        self.field_vars[attribute] = variable
        if attribute == "monitor":
            variable.trace_add(
                "write",
                lambda *_args, monitor_var=variable: self.root.after_idle(
                    lambda: self._refresh_host_resolution_options(monitor_var)
                ),
            )
        return row + 1

    def _resolution_entry(
        self, parent, row, target, max_width: int, max_height: int
    ):
        ttk.Label(parent, text="允许控制端使用的最大分辨率", style="Card.TLabel").grid(
            row=row, column=0, sticky="w", padx=(0, 12), pady=6
        )
        modes = available_video_resolutions(max_width, max_height)
        current = (int(target.width), int(target.height))
        if current not in modes:
            modes.append(current)
            modes.sort(key=lambda item: (item[0] * item[1], item))
        variable = tk.StringVar(value=format_video_resolution(*current))
        widget = ttk.Combobox(
            parent,
            textvariable=variable,
            values=[format_video_resolution(*item) for item in modes],
            state="readonly",
            width=28,
        )
        widget.grid(row=row, column=1, sticky="ew", pady=6)
        self.host_resolution_box = widget
        parent.columnconfigure(1, weight=1)
        self.bindings.append(
            (target, "width", variable, lambda value: parse_video_resolution(value)[0])
        )
        self.bindings.append(
            (target, "height", variable, lambda value: parse_video_resolution(value)[1])
        )
        self.field_vars["resolution"] = variable
        return row + 1

    def _refresh_host_resolution_options(self, monitor_var) -> None:
        box = self.host_resolution_box
        resolution_var = self.field_vars.get("resolution")
        if box is None or resolution_var is None or not box.winfo_exists():
            return
        try:
            _left, _top, max_width, max_height = monitor_region(
                self.root, int(monitor_var.get())
            )
            width, height = parse_video_resolution(resolution_var.get())
        except (TypeError, ValueError, tk.TclError):
            return
        width, height = fit_video_resolution(width, height, max_width, max_height)
        modes = available_video_resolutions(max_width, max_height)
        current = (width, height)
        if current not in modes:
            modes.append(current)
            modes.sort(key=lambda item: (item[0] * item[1], item))
        box.configure(values=[format_video_resolution(*item) for item in modes])
        resolution_var.set(format_video_resolution(*current))

    def _check(self, parent, row, target, attribute, label):
        variable = tk.BooleanVar(value=bool(getattr(target, attribute)))
        ttk.Checkbutton(
            parent, text=label, variable=variable, style="Card.TCheckbutton"
        ).grid(
            row=row, column=0, columnspan=2, sticky="w", pady=(10, 4)
        )
        self.bindings.append((target, attribute, variable, bool))
        self.field_vars[attribute] = variable
        return row + 1

    @staticmethod
    def _hint(parent, row, text):
        ttk.Label(
            parent,
            text=text,
            style="Card.TLabel",
            foreground="#64748b",
            wraplength=360,
            justify="left",
        ).grid(row=row, column=0, columnspan=2, sticky="w", pady=(10, 2))

    def _read_profile(self, validate=True) -> RoleProfile:
        current = self.current_profile
        # Clone declared dataclass fields only.  UI bindings deliberately keep
        # pointing at the form objects that existed when the page was built;
        # after the first Start, object identity changes and must not be used
        # to decide whether a field belongs to runtime or connection options.
        runtime = type(current.runtime)(**asdict(current.runtime))
        options = ConnectionOptions(**asdict(current.connection))
        for original, attribute, variable, converter in self.bindings:
            target = options if isinstance(original, ConnectionOptions) else runtime
            raw = variable.get()
            value = converter(raw) if converter is not bool else bool(raw)
            if converter is str:
                value = value.strip() if attribute != "password" else value
            setattr(target, attribute, value)
        profile = RoleProfile(
            current.role,
            current.mode,
            self.profile_name.get().strip(),
            options,
            runtime,
        )
        if validate:
            profile.validate()
        return profile

    def _set_quality(self, width, height, fps):
        resolution = self.field_vars.get("resolution")
        if resolution is not None:
            resolution.set(format_video_resolution(width, height))
        fps_variable = self.field_vars.get("fps")
        if fps_variable is not None:
            fps_variable.set(str(fps))
        self.status_var.set("画面预设：{}x{} @ {} FPS".format(width, height, fps))

    def save_profile(self) -> None:
        try:
            profile = self._read_profile()
            path = self.repository.save(profile)
            self.current_profile = profile
            key = (profile.role, profile.mode, profile.name)
            self.drafts[key] = profile
            self.selected_names[(profile.role, profile.mode)] = profile.name
            self.profile_box.configure(values=self.repository.names(profile.role, profile.mode))
            self.status_var.set("独立配置已保存：{}".format(path))
        except Exception as exc:
            messagebox.showerror("保存失败", str(exc), parent=self.root)

    def load_profile(self) -> None:
        try:
            role, mode = self.role_var.get(), self.mode_var.get()
            name = self.profile_name.get().strip()
            self.current_profile = self.repository.load(role, mode, name)
            self.selected_names[(role, mode)] = name
            self.drafts.pop((role, mode, name), None)
            self._rebuild_form()
            self.status_var.set("已加载 {} / {} / {}".format(role, MODE_LABELS[mode], name))
        except Exception as exc:
            messagebox.showerror("加载失败", str(exc), parent=self.root)

    def _save_current_for_start(self) -> RoleProfile:
        profile = self._read_profile()
        self.repository.save(profile)
        self.current_profile = profile
        return profile

    def start_host(self) -> None:
        if self.host_runtime is not None:
            self.status_var.set("被控端已经运行")
            return
        try:
            profile = self._save_current_for_start()
            if profile.role != "host":
                raise ValueError("请先切换到被控端")
            settings = profile.effective_runtime()
            runtime = self.host_runtime_cls(self.root, settings, self.status_var.set)
            runtime.start()
            self.host_runtime = runtime
            self.host_generation += 1
            if profile.mode == MODE_RENDEZVOUS:
                generation = self.host_generation
                self.status_var.set("被控端已启动，正在向会合服务器注册…")
                threading.Thread(
                    target=self._prepare_rendezvous_host,
                    args=(profile, settings, generation),
                    name="v2-rendezvous-host",
                    daemon=True,
                ).start()
            elif profile.mode == MODE_MUTUAL:
                self.status_var.set(
                    "被控端运行中；仅接受密钥认证，预期控制端 {}".format(
                        profile.connection.peer_host
                    )
                )
        except Exception as exc:
            if "runtime" in locals():
                runtime.stop()
            messagebox.showerror("启动被控端失败", str(exc), parent=self.root)

    def _prepare_rendezvous_host(self, profile, settings, generation):
        import p2p_secrect as secure
        from p2p_server import establish_peer

        options = profile.connection
        key = secure.derive_key(settings.password)
        while generation == self.host_generation:
            bridge = None
            try:
                session, _family, sockets, counters = establish_peer(
                    "host",
                    (options.server_host, options.server_port),
                    key,
                    room_name=options.room,
                    port=options.local_udp_port,
                    timeout=60,
                )
                bridge = ReliableP2PTunnel(
                    session,
                    sockets,
                    "host",
                    targets={
                        SIGNAL_STREAM: ("127.0.0.1", settings.signal_port),
                        CONTROL_STREAM: ("127.0.0.1", settings.control_port),
                    },
                    status=lambda text: self.task_events.put(("status", text)),
                )
                if generation != self.host_generation:
                    bridge.close(notify_peer=False)
                    return
                bridge.start()
                self.task_events.put(("host_bridge", generation, bridge, counters))
                while (
                    generation == self.host_generation
                    and not bridge.wait_disconnected(0.5)
                ):
                    pass
                reason = bridge.disconnect_reason or "当前控制会话已结束"
                bridge.close(notify_peer=False)
                if generation != self.host_generation:
                    return
                self.task_events.put(
                    ("host_bridge_lost", generation, bridge, reason)
                )
            except Exception as exc:
                if bridge is not None:
                    bridge.close(notify_peer=False)
                if generation != self.host_generation:
                    return
                self.task_events.put(
                    (
                        "host_waiting_retry",
                        generation,
                        "会合等待暂时中断：{}；2 秒后继续等待".format(exc),
                    )
                )
                time.sleep(2.0)

    def stop_host(self) -> None:
        self.host_generation += 1
        if self.host_tunnel is not None:
            self.host_tunnel.close()
            self.host_tunnel = None
        if self.host_runtime is not None:
            self.host_runtime.stop()
            self.host_runtime = None
            self.status_var.set("被控端已停止")

    def start_client(self) -> None:
        try:
            profile = self._save_current_for_start()
            if profile.role != "client":
                raise ValueError("请先切换到控制端")
            settings = profile.effective_runtime()
            if profile.mode == MODE_RENDEZVOUS:
                self.status_var.set("控制端正在向会合服务器注册并建立 P2P…")
                threading.Thread(
                    target=self._prepare_rendezvous_client,
                    args=(profile, settings),
                    name="v2-rendezvous-client",
                    daemon=True,
                ).start()
            else:
                self._launch_client(settings, None)
        except Exception as exc:
            messagebox.showerror("启动控制端失败", str(exc), parent=self.root)

    def _prepare_rendezvous_client(self, profile, settings):
        bridge = None
        try:
            import p2p_secrect as secure
            from p2p_server import establish_peer

            options = profile.connection
            session, _family, sockets, counters = establish_peer(
                "client",
                (options.server_host, options.server_port),
                secure.derive_key(settings.password),
                room_name=options.room,
                port=options.local_udp_port,
                timeout=60,
            )
            bridge = ReliableP2PTunnel(
                session,
                sockets,
                "client",
                status=lambda text: self.task_events.put(("status", text)),
            )
            signal_port = bridge.add_local_listener(SIGNAL_STREAM)
            control_port = bridge.add_local_listener(CONTROL_STREAM)
            bridge.start()
            settings.peer = "127.0.0.1"
            settings.signal_port = signal_port
            settings.control_port = control_port
            self.task_events.put(("client_ready", settings, bridge, counters))
        except Exception as exc:
            if bridge is not None:
                bridge.close()
            self.task_events.put(("client_error", str(exc)))

    def _launch_client(self, settings, bridge):
        window = tk.Toplevel(self.root)
        runtime = None
        try:
            runtime = self.client_runtime_cls(window, settings)
            runtime.start()
            record = [runtime, bridge]
            self.client_windows.append(record)

            def close_client():
                try:
                    runtime.close()
                finally:
                    if bridge is not None:
                        bridge.close()
                    if record in self.client_windows:
                        self.client_windows.remove(record)

            window.protocol("WM_DELETE_WINDOW", close_client)
            self.status_var.set("控制端已启动")
        except Exception:
            if runtime is not None:
                runtime.close()
            elif window.winfo_exists():
                window.destroy()
            if bridge is not None:
                bridge.close()
            raise

    def _poll_tasks(self):
        try:
            while True:
                event = self.task_events.get_nowait()
                kind = event[0]
                if kind == "status":
                    self.status_var.set(event[1])
                elif kind == "host_bridge":
                    _kind, generation, bridge, counters = event
                    if generation != self.host_generation or self.host_runtime is None:
                        bridge.close()
                    else:
                        if self.host_tunnel is not None:
                            self.host_tunnel.close()
                        self.host_tunnel = bridge
                        self.status_var.set(
                            "会合 P2P 已认证；信令/控制走加密直连隧道，画面走 WebRTC ICE；{}".format(
                                counters
                            )
                        )
                elif kind == "host_error":
                    _kind, generation, detail = event
                    if generation == self.host_generation:
                        self.status_var.set("会合连接失败：{}".format(detail))
                elif kind == "host_bridge_lost":
                    _kind, generation, bridge, reason = event
                    if generation == self.host_generation:
                        if self.host_tunnel is bridge:
                            self.host_tunnel = None
                        self.status_var.set("{}；被控端正在重新注册等待".format(reason))
                elif kind == "host_waiting_retry":
                    _kind, generation, detail = event
                    if generation == self.host_generation:
                        self.status_var.set(detail)
                elif kind == "client_ready":
                    _kind, settings, bridge, _counters = event
                    try:
                        self._launch_client(settings, bridge)
                    except Exception as exc:
                        messagebox.showerror("启动控制端失败", str(exc), parent=self.root)
                elif kind == "client_error":
                    messagebox.showerror("会合连接失败", event[1], parent=self.root)
        except queue.Empty:
            pass
        if self.root.winfo_exists():
            self.root.after(100, self._poll_tasks)

    def close(self) -> None:
        self.stop_host()
        for runtime, bridge in list(self.client_windows):
            try:
                runtime.close()
            except tk.TclError:
                pass
            if bridge is not None:
                bridge.close()
        self.client_windows.clear()
        self.root.destroy()
