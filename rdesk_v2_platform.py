"""Minimal OS integration used by rdesk V2."""

import json
import os
import sys
import threading
import time
from typing import Dict, Tuple


def decode_json(payload: bytes) -> Dict:
    if len(payload) > 64 * 1024:
        raise ValueError("message too large")
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("invalid message")
    return value


def enable_windows_dpi_awareness():
    if not sys.platform.startswith("win"):
        return
    try:
        import ctypes

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        # Python/Tk or an executable manifest may already have selected a
        # process DPI mode.  SetProcessDpiAwareness() returns an HRESULT (it
        # does not raise through ctypes), so the old try/except silently
        # treated E_ACCESSDENIED as success.  A per-thread PMv2 context still
        # gives the Tk window and all coordinate APIs created below one
        # physical-pixel coordinate space.
        try:
            set_process_context = user32.SetProcessDpiAwarenessContext
            set_process_context.argtypes = (ctypes.c_void_p,)
            set_process_context.restype = ctypes.c_bool
            set_process_context(ctypes.c_void_p(-4))  # PER_MONITOR_AWARE_V2
        except Exception:
            try:
                shcore = ctypes.WinDLL("shcore", use_last_error=True)
                shcore.SetProcessDpiAwareness.argtypes = (ctypes.c_int,)
                shcore.SetProcessDpiAwareness.restype = ctypes.c_long
                shcore.SetProcessDpiAwareness(2)  # PROCESS_PER_MONITOR_DPI_AWARE
            except Exception:
                user32.SetProcessDPIAware()
        try:
            set_thread_context = user32.SetThreadDpiAwarenessContext
            set_thread_context.argtypes = (ctypes.c_void_p,)
            set_thread_context.restype = ctypes.c_void_p
            set_thread_context(ctypes.c_void_p(-4))  # PER_MONITOR_AWARE_V2
        except Exception:
            pass
    except Exception:
        pass


def windows_monitor_info(monitor_index: int):
    """Return (HMONITOR, left, top, width, height) for one Windows monitor."""
    if sys.platform.startswith("win"):
        try:
            import ctypes
            from ctypes import wintypes

            regions = []
            callback_type = ctypes.WINFUNCTYPE(
                ctypes.c_int,
                wintypes.HMONITOR,
                wintypes.HDC,
                ctypes.POINTER(wintypes.RECT),
                wintypes.LPARAM,
            )

            def collect(_monitor, _dc, rectangle, _data):
                rect = rectangle.contents
                handle = ctypes.cast(_monitor, ctypes.c_void_p).value or 0
                regions.append(
                    (handle, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top)
                )
                return 1

            callback = callback_type(collect)
            ctypes.windll.user32.EnumDisplayMonitors(0, 0, callback, 0)
            if regions:
                return regions[max(0, min(len(regions) - 1, monitor_index - 1))]
        except Exception:
            pass
    return None


def monitor_region(root, monitor_index: int) -> Tuple[int, int, int, int]:
    """Return the selected monitor's desktop coordinates where available."""
    monitor = windows_monitor_info(monitor_index)
    if monitor is not None:
        return monitor[1:]
    return 0, 0, root.winfo_screenwidth(), root.winfo_screenheight()


class CrossPlatformInputDriver:
    """Inject input with Win32 SendInput on Windows or pynput on X11."""

    SPECIAL_KEYS = {
        "Return": "enter",
        "KP_Enter": "enter",
        "BackSpace": "backspace",
        "Tab": "tab",
        "Escape": "esc",
        "Delete": "delete",
        "Insert": "insert",
        "Home": "home",
        "End": "end",
        "Prior": "page_up",
        "Next": "page_down",
        "Left": "left",
        "Right": "right",
        "Up": "up",
        "Down": "down",
        "Shift_L": "shift_l",
        "Shift_R": "shift_r",
        "Control_L": "ctrl_l",
        "Control_R": "ctrl_r",
        "Alt_L": "alt_l",
        "Alt_R": "alt_r",
        "Super_L": "cmd_l",
        "Super_R": "cmd_r",
        "Caps_Lock": "caps_lock",
        "Num_Lock": "num_lock",
        "Print": "print_screen",
        "Pause": "pause",
        "space": "space",
    }

    # Tk reports the logical keysym, while Ctrl+C may put the control byte
    # ``\x03`` in event.char. Map the keysym back to the physical base key so
    # modifier combinations remain Ctrl+<letter> instead of a control glyph.
    PRINTABLE_KEYSYMS = {
        "minus": "-",
        "equal": "=",
        "bracketleft": "[",
        "bracketright": "]",
        "backslash": "\\",
        "semicolon": ";",
        "apostrophe": "'",
        "grave": "`",
        "comma": ",",
        "period": ".",
        "slash": "/",
        "exclam": "1",
        "at": "2",
        "numbersign": "3",
        "dollar": "4",
        "percent": "5",
        "asciicircum": "6",
        "ampersand": "7",
        "asterisk": "8",
        "parenleft": "9",
        "parenright": "0",
        "underscore": "-",
        "plus": "=",
        "braceleft": "[",
        "braceright": "]",
        "bar": "\\",
        "colon": ";",
        "quotedbl": "'",
        "asciitilde": "`",
        "less": ",",
        "greater": ".",
        "question": "/",
    }

    def __init__(self):
        self.is_windows = sys.platform.startswith("win")
        if self.is_windows:
            self._initialize_windows_input()
        else:
            from pynput.keyboard import Controller as KeyboardController
            from pynput.keyboard import Key, KeyCode
            from pynput.mouse import Button, Controller as MouseController

            self.keyboard = KeyboardController()
            self.mouse = MouseController()
            self.Key = Key
            self.KeyCode = KeyCode
            self.Button = Button
        self.region = {"left": 0, "top": 0, "width": 1, "height": 1}
        self.pressed = {}
        self.next_order = 1
        self.ordered_events = {}
        self.lock = threading.Lock()

    def _initialize_windows_input(self):
        import ctypes
        from ctypes import wintypes

        ulong_ptr = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong

        class MouseInput(ctypes.Structure):
            _fields_ = (
                ("dx", wintypes.LONG),
                ("dy", wintypes.LONG),
                ("mouseData", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD),
                ("dwExtraInfo", ulong_ptr),
            )

        class KeyboardInput(ctypes.Structure):
            _fields_ = (
                ("wVk", wintypes.WORD),
                ("wScan", wintypes.WORD),
                ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD),
                ("dwExtraInfo", ulong_ptr),
            )

        class HardwareInput(ctypes.Structure):
            _fields_ = (
                ("uMsg", wintypes.DWORD),
                ("wParamL", wintypes.WORD),
                ("wParamH", wintypes.WORD),
            )

        class InputUnion(ctypes.Union):
            _fields_ = (("mi", MouseInput), ("ki", KeyboardInput), ("hi", HardwareInput))

        class Input(ctypes.Structure):
            _anonymous_ = ("data",)
            _fields_ = (("type", wintypes.DWORD), ("data", InputUnion))

        self.ctypes = ctypes
        self.wintypes = wintypes
        self.MouseInput = MouseInput
        self.KeyboardInput = KeyboardInput
        self.Input = Input
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.user32.SendInput.argtypes = (wintypes.UINT, ctypes.POINTER(Input), ctypes.c_int)
        self.user32.SendInput.restype = wintypes.UINT
        self.user32.OpenInputDesktop.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        self.user32.OpenInputDesktop.restype = wintypes.HANDLE
        self.user32.GetThreadDesktop.argtypes = (wintypes.DWORD,)
        self.user32.GetThreadDesktop.restype = wintypes.HANDLE
        self.user32.SetThreadDesktop.argtypes = (wintypes.HANDLE,)
        self.user32.SetThreadDesktop.restype = wintypes.BOOL
        self.user32.GetCursorPos.argtypes = (ctypes.POINTER(wintypes.POINT),)
        self.user32.GetCursorPos.restype = wintypes.BOOL
        self.user32.SetCursorPos.argtypes = (ctypes.c_int, ctypes.c_int)
        self.user32.SetCursorPos.restype = wintypes.BOOL
        self.get_physical_cursor_pos = getattr(
            self.user32, "GetPhysicalCursorPos", self.user32.GetCursorPos
        )
        self.get_physical_cursor_pos.argtypes = (
            ctypes.POINTER(wintypes.POINT),
        )
        self.get_physical_cursor_pos.restype = wintypes.BOOL
        self.set_physical_cursor_pos = getattr(
            self.user32, "SetPhysicalCursorPos", self.user32.SetCursorPos
        )
        self.set_physical_cursor_pos.argtypes = (ctypes.c_int, ctypes.c_int)
        self.set_physical_cursor_pos.restype = wintypes.BOOL
        self.user32.GetUserObjectInformationW.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        )
        self.user32.GetUserObjectInformationW.restype = wintypes.BOOL
        self.kernel32.GetCurrentThreadId.restype = wintypes.DWORD
        self.input_desktop_threads = {}
        self.last_desktop_name = "unknown"
        self.last_mouse_target = None
        self.last_mouse_actual = None

    WINDOWS_SPECIAL_KEYS = {
        "Return": 0x0D,
        "KP_Enter": 0x0D,
        "BackSpace": 0x08,
        "Tab": 0x09,
        "Escape": 0x1B,
        "Delete": 0x2E,
        "Insert": 0x2D,
        "Home": 0x24,
        "End": 0x23,
        "Prior": 0x21,
        "Next": 0x22,
        "Left": 0x25,
        "Up": 0x26,
        "Right": 0x27,
        "Down": 0x28,
        "Shift_L": 0xA0,
        "Shift_R": 0xA1,
        "Control_L": 0xA2,
        "Control_R": 0xA3,
        "Alt_L": 0xA4,
        "Alt_R": 0xA5,
        "Super_L": 0x5B,
        "Super_R": 0x5C,
        "Caps_Lock": 0x14,
        "Num_Lock": 0x90,
        "Print": 0x2C,
        "Pause": 0x13,
        "space": 0x20,
    }

    WINDOWS_PRINTABLE_KEYS = {
        "minus": 0xBD,
        "underscore": 0xBD,
        "equal": 0xBB,
        "plus": 0xBB,
        "bracketleft": 0xDB,
        "braceleft": 0xDB,
        "bracketright": 0xDD,
        "braceright": 0xDD,
        "backslash": 0xDC,
        "bar": 0xDC,
        "semicolon": 0xBA,
        "colon": 0xBA,
        "apostrophe": 0xDE,
        "quotedbl": 0xDE,
        "grave": 0xC0,
        "asciitilde": 0xC0,
        "comma": 0xBC,
        "less": 0xBC,
        "period": 0xBE,
        "greater": 0xBE,
        "slash": 0xBF,
        "question": 0xBF,
        "exclam": ord("1"),
        "at": ord("2"),
        "numbersign": ord("3"),
        "dollar": ord("4"),
        "percent": ord("5"),
        "asciicircum": ord("6"),
        "ampersand": ord("7"),
        "asterisk": ord("8"),
        "parenleft": ord("9"),
        "parenright": ord("0"),
    }

    def set_region(self, left: int, top: int, width: int, height: int):
        with self.lock:
            self.region = {
                "left": left,
                "top": top,
                "width": max(1, width),
                "height": max(1, height),
            }

    def _send_windows_input(self, native_input):
        self._ensure_windows_input_desktop()
        sent = self.user32.SendInput(1, self.ctypes.byref(native_input), self.ctypes.sizeof(self.Input))
        if sent != 1:
            error_code = self.ctypes.get_last_error()
            raise OSError(
                error_code,
                "Windows SendInput 失败；请确保 rdesk 运行在当前交互桌面，并与目标程序权限级别相同",
            )

    def _windows_desktop_name(self, desktop_handle) -> str:
        if not desktop_handle:
            return "unavailable"
        needed = self.wintypes.DWORD()
        buffer = self.ctypes.create_unicode_buffer(256)
        if self.user32.GetUserObjectInformationW(
            desktop_handle,
            2,
            buffer,
            self.ctypes.sizeof(buffer),
            self.ctypes.byref(needed),
        ):
            return buffer.value or "unnamed"
        return "error:{}".format(self.ctypes.get_last_error())

    def _ensure_windows_input_desktop(self):
        thread_id = int(self.kernel32.GetCurrentThreadId())
        cached = self.input_desktop_threads.get(thread_id)
        if cached is not None:
            self.last_desktop_name = cached[1]
            return
        # The secure UDP receive thread may have inherited a non-input desktop.
        # Keep the returned HDESK open for the lifetime of that thread.
        access = 0x0001 | 0x0080 | 0x0100  # READOBJECTS | WRITEOBJECTS | SWITCHDESKTOP
        input_desktop = self.user32.OpenInputDesktop(0, False, access)
        if not input_desktop:
            raise OSError(
                self.ctypes.get_last_error(),
                "OpenInputDesktop 失败；Windows 可能处于锁屏或安全桌面",
            )
        current_desktop = self.user32.GetThreadDesktop(thread_id)
        current_name = self._windows_desktop_name(current_desktop)
        input_name = self._windows_desktop_name(input_desktop)
        if current_name != input_name and not self.user32.SetThreadDesktop(input_desktop):
            raise OSError(
                self.ctypes.get_last_error(),
                "SetThreadDesktop 从 {} 切换到 {} 失败".format(current_name, input_name),
            )
        self.input_desktop_threads[thread_id] = (input_desktop, input_name)
        self.last_desktop_name = input_name

    def input_backend_status(self) -> str:
        if self.is_windows:
            return "win32-sendinput/desktop={}".format(self.last_desktop_name)
        return "pynput-x11"

    def _send_windows_mouse(self, flags: int, data: int = 0, x: int = 0, y: int = 0):
        native_input = self.Input(type=0)
        native_input.mi = self.MouseInput(
            int(x),
            int(y),
            self.wintypes.DWORD(data).value,
            flags,
            0,
            0,
        )
        self._send_windows_input(native_input)

    def _move_mouse(self, absolute_x: int, absolute_y: int):
        if not self.is_windows:
            self.mouse.position = (absolute_x, absolute_y)
            return
        self._ensure_windows_input_desktop()
        self.last_mouse_target = (absolute_x, absolute_y)
        # The captured D3D/X11 frame and monitor region are physical pixels.
        # SetCursorPos/GetCursorPos can be virtualized into the caller's DPI
        # coordinate space and can therefore agree with each other while both
        # disagree with the captured image.  The explicit physical APIs keep
        # injection and verification in the capture coordinate space.
        if self.set_physical_cursor_pos(absolute_x, absolute_y):
            point = self.wintypes.POINT()
            if self.get_physical_cursor_pos(self.ctypes.byref(point)):
                self.last_mouse_actual = (point.x, point.y)
                if abs(point.x - absolute_x) <= 2 and abs(point.y - absolute_y) <= 2:
                    return
        # SendInput absolute coordinates span the complete virtual desktop.
        virtual_left = self.user32.GetSystemMetrics(76)
        virtual_top = self.user32.GetSystemMetrics(77)
        virtual_width = max(1, self.user32.GetSystemMetrics(78))
        virtual_height = max(1, self.user32.GetSystemMetrics(79))
        normalized_x = round((absolute_x - virtual_left) * 65535 / max(1, virtual_width - 1))
        normalized_y = round((absolute_y - virtual_top) * 65535 / max(1, virtual_height - 1))
        normalized_x = max(0, min(65535, normalized_x))
        normalized_y = max(0, min(65535, normalized_y))
        self._send_windows_mouse(0x0001 | 0x8000 | 0x4000, x=normalized_x, y=normalized_y)
        time.sleep(0.005)
        point = self.wintypes.POINT()
        if not self.get_physical_cursor_pos(self.ctypes.byref(point)):
            raise OSError(
                self.ctypes.get_last_error(),
                "GetPhysicalCursorPos 无法验证鼠标位置",
            )
        self.last_mouse_actual = (point.x, point.y)
        if abs(point.x - absolute_x) > 4 or abs(point.y - absolute_y) > 4:
            raise RuntimeError(
                "鼠标注入未生效：目标 {} 实际 {} 桌面 {}".format(
                    self.last_mouse_target,
                    self.last_mouse_actual,
                    self.last_desktop_name,
                )
            )

    def _mouse_button_event(self, button_name: str, down: bool):
        if not self.is_windows:
            button = {
                "left": self.Button.left,
                "middle": self.Button.middle,
                "right": self.Button.right,
            }[button_name]
            if down:
                self.mouse.press(button)
            else:
                self.mouse.release(button)
            return button
        flags = {
            ("left", True): 0x0002,
            ("left", False): 0x0004,
            ("right", True): 0x0008,
            ("right", False): 0x0010,
            ("middle", True): 0x0020,
            ("middle", False): 0x0040,
        }[(button_name, down)]
        self._send_windows_mouse(flags)
        return button_name

    def _mouse_scroll(self, dx: int, dy: int):
        if not self.is_windows:
            self.mouse.scroll(dx, dy)
            return
        if dy:
            self._send_windows_mouse(0x0800, data=int(dy) * 120)
        if dx:
            self._send_windows_mouse(0x1000, data=int(dx) * 120)

    def _send_windows_key(self, key, down: bool):
        key_type, value = key
        flags = 0 if down else 0x0002
        virtual_key = value
        scan_code = 0
        if key_type == "unicode":
            flags |= 0x0004
            virtual_key = 0
            scan_code = value
        native_input = self.Input(type=1)
        native_input.ki = self.KeyboardInput(virtual_key, scan_code, flags, 0, 0)
        self._send_windows_input(native_input)

    def _keyboard_event(self, key, down: bool):
        if self.is_windows:
            self._send_windows_key(key, down)
        elif down:
            self.keyboard.press(key)
        else:
            self.keyboard.release(key)

    def _key_for(self, keysym: str, character: str):
        if getattr(self, "is_windows", False):
            virtual_key = self.WINDOWS_SPECIAL_KEYS.get(keysym)
            if virtual_key is not None:
                return "vk", virtual_key
            if keysym.startswith("F") and keysym[1:].isdigit():
                number = int(keysym[1:])
                if 1 <= number <= 24:
                    return "vk", 0x70 + number - 1
            if len(keysym) == 1 and keysym.isascii() and keysym.isalnum():
                return "vk", ord(keysym.upper())
            virtual_key = self.WINDOWS_PRINTABLE_KEYS.get(keysym)
            if virtual_key is not None:
                return "vk", virtual_key
            if character and character.isprintable() and ord(character[0]) >= 32:
                codepoint = ord(character[0])
                if codepoint <= 0xFFFF:
                    return "unicode", codepoint
            return None
        attribute = self.SPECIAL_KEYS.get(keysym)
        if attribute and hasattr(self.Key, attribute):
            return getattr(self.Key, attribute)
        if keysym.startswith("F") and keysym[1:].isdigit():
            attribute = keysym.lower()
            if hasattr(self.Key, attribute):
                return getattr(self.Key, attribute)
        if len(keysym) == 1:
            base_key = keysym.lower() if keysym.isalpha() and keysym.isascii() else keysym
            return self.KeyCode.from_char(base_key)
        base_key = self.PRINTABLE_KEYSYMS.get(keysym)
        if base_key:
            return self.KeyCode.from_char(base_key)
        if character and character.isprintable() and ord(character[0]) >= 32:
            return self.KeyCode.from_char(character)
        return None

    def handle(self, payload: bytes):
        data = decode_json(payload)
        with self.lock:
            order = data.get("order")
            if order is not None:
                order = int(order)
                if order < self.next_order or order > self.next_order + 2048:
                    return
                self.ordered_events[order] = data
                while self.next_order in self.ordered_events:
                    ordered = self.ordered_events.pop(self.next_order)
                    self.next_order += 1
                    self._handle_data_locked(ordered)
                return
            self._handle_data_locked(data)

    def _handle_data_locked(self, data: Dict):
        event_type = data.get("type")
        if event_type == "mouse_move":
            x = max(0, min(65535, int(data.get("x", 0))))
            y = max(0, min(65535, int(data.get("y", 0))))
            region = self.region
            absolute_x = region["left"] + round((region["width"] - 1) * x / 65535)
            absolute_y = region["top"] + round((region["height"] - 1) * y / 65535)
            self._move_mouse(absolute_x, absolute_y)
            return
        if event_type == "mouse_button":
            button_name = data.get("button")
            if button_name not in ("left", "middle", "right"):
                return
            if data.get("down"):
                button = self._mouse_button_event(button_name, True)
                self.pressed["mouse:" + button_name] = button
            else:
                self._mouse_button_event(button_name, False)
                self.pressed.pop("mouse:" + button_name, None)
            return
        if event_type == "mouse_wheel":
            self._mouse_scroll(int(data.get("dx", 0)), int(data.get("dy", 0)))
            return
        if event_type in ("key_down", "key_up"):
            key_id = str(data.get("id", ""))[:64]
            if not key_id:
                return
            if event_type == "key_down":
                if key_id in self.pressed:
                    return
                key = self._key_for(
                    str(data.get("keysym", ""))[:32],
                    str(data.get("char", ""))[:4],
                )
                if key is not None:
                    self._keyboard_event(key, True)
                    self.pressed[key_id] = key
            else:
                key = self.pressed.pop(key_id, None)
                if key is not None:
                    self._keyboard_event(key, False)
            return
        if event_type == "release_all":
            self._release_all_locked()

    def reset_session(self):
        with self.lock:
            self._release_all_locked()
            self.next_order = 1
            self.ordered_events.clear()

    def _release_all_locked(self):
        for key_id, item in list(self.pressed.items()):
            try:
                if key_id.startswith("mouse:"):
                    button_name = item if self.is_windows else key_id.split(":", 1)[1]
                    self._mouse_button_event(button_name, False)
                else:
                    self._keyboard_event(item, False)
            except Exception:
                pass
        self.pressed.clear()

    def release_all(self):
        with self.lock:
            self._release_all_locked()


_GST = None
_GST_INIT_LOCK = threading.Lock()


def load_gstreamer():
    """Load the platform GStreamer Python bindings lazily."""
    global _GST
    with _GST_INIT_LOCK:
        if _GST is not None:
            return _GST
        os.environ.setdefault("GST_XINITTHREADS", "1")
        try:
            import gi

            gi.require_version("Gst", "1.0")
            from gi.repository import Gst
        except Exception as exc:
            raise RuntimeError(
                "缺少 GStreamer Python 运行时，请按 README 安装：{}".format(exc)
            )
        Gst.init(None)
        _GST = Gst
        return Gst

