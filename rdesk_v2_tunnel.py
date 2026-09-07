"""Reliable multiplexed TCP bridge over an authenticated P2P UDP session."""

from __future__ import annotations

import base64
import secrets
import socket
import threading
import time


SIGNAL_STREAM = 1
CONTROL_STREAM = 2
CHUNK_SIZE = 780
WINDOW_SIZE = 48
RESEND_AFTER = 0.18


class ReliableP2PTunnel:
    """Carry small TCP signalling/control streams; media never enters here."""

    def __init__(
        self,
        session,
        sockets,
        role,
        targets=None,
        status=lambda _text: None,
        on_disconnect=None,
        peer_timeout=12.0,
    ):
        if role not in ("host", "client"):
            raise ValueError("隧道角色必须是 host 或 client")
        self.session = session
        self.sockets = sockets
        self.role = role
        self.targets = targets or {}
        self.status = status
        self.on_disconnect = on_disconnect
        self.peer_timeout = max(5.0, float(peer_timeout))
        self.running = threading.Event()
        self.lock = threading.RLock()
        self.window_ready = threading.Condition(self.lock)
        self.streams = {}
        self.listeners = {}
        self.send_seq = {}
        self.recv_next = {}
        self.recv_buffers = {}
        self.unacked = {}
        self.pending_open = set()
        self.pending_close = {}
        self.last_open = {}
        self.stream_tokens = {}
        self.last_keepalive = 0.0
        self.last_receive_error = 0.0
        self.last_peer_activity = time.monotonic()
        self.disconnected = threading.Event()
        self.disconnect_reason = ""
        self.threads = []

    def add_local_listener(self, stream_id, bind="127.0.0.1") -> int:
        if self.role != "client":
            raise ValueError("只有控制端创建本地入口")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((bind, 0))
        listener.listen(4)
        listener.settimeout(0.5)
        self.listeners[stream_id] = listener
        return int(listener.getsockname()[1])

    def start(self) -> None:
        self.running.set()
        self._thread(self._receive_loop, "p2p-tunnel-udp")
        self._thread(self._resend_loop, "p2p-tunnel-resend")
        for stream_id, listener in self.listeners.items():
            self._thread(
                lambda sid=stream_id, sock=listener: self._accept_local(sid, sock),
                "p2p-tunnel-listen-{}".format(stream_id),
            )

    def close(self, notify_peer=True) -> None:
        if notify_peer and self.running.is_set():
            for _ in range(3):
                try:
                    self.session.send({"type": "tunnel_session_close"})
                except OSError:
                    break
        self.running.clear()
        self.disconnected.set()
        with self.window_ready:
            self.window_ready.notify_all()
        self._close_resources()

    def _close_resources(self) -> None:
        for listener in list(self.listeners.values()):
            try:
                listener.close()
            except OSError:
                pass
        with self.lock:
            streams = list(self.streams.values())
            self.streams.clear()
            self.stream_tokens.clear()
        for stream in streams:
            try:
                stream.close()
            except OSError:
                pass
        for sock in self.sockets.values():
            try:
                sock.close()
            except OSError:
                pass

    def wait_disconnected(self, timeout=None) -> bool:
        return self.disconnected.wait(timeout)

    def _signal_disconnect(self, reason) -> None:
        if self.disconnected.is_set():
            return
        self.disconnect_reason = str(reason)
        self.disconnected.set()
        self.running.clear()
        with self.window_ready:
            self.window_ready.notify_all()
        self.status(self.disconnect_reason)
        self._close_resources()
        if self.on_disconnect is not None:
            try:
                self.on_disconnect(self, self.disconnect_reason)
            except Exception:
                pass

    def _thread(self, target, name):
        thread = threading.Thread(target=target, name=name, daemon=True)
        self.threads.append(thread)
        thread.start()

    def _accept_local(self, stream_id, listener):
        while self.running.is_set():
            try:
                stream, _address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            token = secrets.token_hex(8)
            self._attach_stream(stream_id, stream, token)
            with self.lock:
                self.pending_open.add(stream_id)
                self.last_open[stream_id] = 0.0
            self._send_open(stream_id)

    def _connect_host_stream(self, stream_id, token):
        with self.lock:
            if (
                stream_id in self.streams
                and self.stream_tokens.get(stream_id) == token
            ):
                return self.streams[stream_id]
        target = self.targets.get(stream_id)
        if target is None:
            return None
        stream = socket.create_connection(target, timeout=3)
        stream.settimeout(None)
        self._attach_stream(stream_id, stream, token)
        self.status("P2P 隧道已连接本机端口 {}".format(target[1]))
        return stream

    def _attach_stream(self, stream_id, stream, token):
        stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        stream.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        with self.lock:
            previous = self.streams.get(stream_id)
            self.streams[stream_id] = stream
            self.stream_tokens[stream_id] = token
            key = (stream_id, token)
            self.send_seq.setdefault(key, 0)
            self.recv_next.setdefault(key, 0)
            self.recv_buffers.setdefault(key, {})
        if previous is not None and previous is not stream:
            previous.close()
        self._thread(
            lambda: self._read_tcp(stream_id, stream, token),
            "p2p-tunnel-tcp-{}".format(stream_id),
        )
        self._flush_received(stream_id, token)

    def _read_tcp(self, stream_id, stream, token):
        try:
            while self.running.is_set():
                payload = stream.recv(CHUNK_SIZE)
                if not payload:
                    break
                with self.window_ready:
                    while (
                        self.running.is_set()
                        and sum(
                            1
                            for marker in self.unacked
                            if marker[0] == stream_id and marker[1] == token
                        )
                        >= WINDOW_SIZE
                    ):
                        self.window_ready.wait(0.2)
                    if not self.running.is_set():
                        return
                    key = (stream_id, token)
                    sequence = self.send_seq[key]
                    self.send_seq[key] += 1
                    self.unacked[(stream_id, token, sequence)] = [payload, 0.0, 0]
                self._send_data(stream_id, sequence, payload, token)
        except OSError:
            pass
        finally:
            deadline = time.monotonic() + 2
            key = (stream_id, token)
            final_sequence = self.send_seq.get(key, 0)
            while self.running.is_set() and time.monotonic() < deadline:
                with self.lock:
                    waiting = any(
                        marker[0] == stream_id and marker[1] == token
                        for marker in self.unacked
                    )
                    final_sequence = self.send_seq.get(key, 0)
                if not waiting:
                    break
                time.sleep(0.03)
            for _ in range(3):
                try:
                    self.session.send(
                        {
                            "type": "tunnel_close",
                            "stream": stream_id,
                            "connection": token,
                            "final_seq": final_sequence,
                        }
                    )
                except OSError:
                    break
            with self.window_ready:
                if (
                    self.streams.get(stream_id) is stream
                    and self.stream_tokens.get(stream_id) == token
                ):
                    self.streams.pop(stream_id, None)
                    self.stream_tokens.pop(stream_id, None)
                for marker in list(self.unacked):
                    if marker[0] == stream_id and marker[1] == token:
                        self.unacked.pop(marker, None)
                self.window_ready.notify_all()
            try:
                stream.close()
            except OSError:
                pass

    def _send_open(self, stream_id):
        with self.lock:
            token = self.stream_tokens.get(stream_id, "")
        self.session.send(
            {"type": "tunnel_open", "stream": stream_id, "connection": token}
        )
        with self.lock:
            self.last_open[stream_id] = time.monotonic()

    def _send_data(self, stream_id, sequence, payload, token=None):
        if token is None:
            with self.lock:
                token = self.stream_tokens.get(stream_id, "")
        self.session.send(
            {
                "type": "tunnel_data",
                "stream": stream_id,
                "connection": token,
                "seq": sequence,
                "data": base64.b64encode(payload).decode("ascii"),
            }
        )
        with self.lock:
            record = self.unacked.get((stream_id, token, sequence))
            if record is not None:
                record[1] = time.monotonic()
                record[2] += 1

    def _receive_loop(self):
        self.session.sock.settimeout(0.5)
        while self.running.is_set():
            try:
                packet, address = self.session.sock.recvfrom(65_507)
            except socket.timeout:
                continue
            except OSError as exc:
                if not self.running.is_set():
                    return
                now = time.monotonic()
                if now - self.last_receive_error >= 2.0:
                    self.last_receive_error = now
                    self.status("P2P UDP 接收瞬时错误，正在保持连接：{}".format(exc))
                time.sleep(0.05)
                continue
            if (str(address[0]), int(address[1])) != (
                str(self.session.address[0]),
                int(self.session.address[1]),
            ):
                continue
            try:
                message = self.session.decrypt(packet)
                self.last_peer_activity = time.monotonic()
                self._handle(message)
            except Exception:
                continue

    def _handle(self, message):
        message_type = message.get("type")
        if message_type == "tunnel_session_close":
            self._signal_disconnect("对端已结束当前会话，等待重新连接")
            return
        if message_type == "tunnel_keepalive":
            if not message.get("reply"):
                self.session.send(
                    {
                        "type": "tunnel_keepalive",
                        "reply": True,
                        "time": message.get("time"),
                    }
                )
            return
        stream_id = int(message.get("stream", 0))
        if stream_id not in (SIGNAL_STREAM, CONTROL_STREAM):
            return
        if message_type == "tunnel_open":
            if self.role == "host":
                try:
                    token = str(message.get("connection", ""))
                    if not token:
                        return
                    self._connect_host_stream(stream_id, token)
                    self.session.send(
                        {
                            "type": "tunnel_open_ack",
                            "stream": stream_id,
                            "connection": token,
                        }
                    )
                    self._flush_received(stream_id, token)
                except OSError as exc:
                    self.status("P2P 隧道连接本机服务失败：{}".format(exc))
            return
        if message_type == "tunnel_open_ack":
            with self.lock:
                if message.get("connection") == self.stream_tokens.get(stream_id):
                    self.pending_open.discard(stream_id)
            return
        if message_type == "tunnel_ack":
            with self.lock:
                if message.get("connection") != self.stream_tokens.get(stream_id):
                    return
            marker = (
                stream_id,
                str(message.get("connection", "")),
                int(message.get("seq", -1)),
            )
            with self.window_ready:
                self.unacked.pop(marker, None)
                self.window_ready.notify_all()
            return
        if message_type == "tunnel_close":
            token = str(message.get("connection", ""))
            with self.lock:
                if token != self.stream_tokens.get(stream_id):
                    return
            final_sequence = max(0, int(message.get("final_seq", 0)))
            with self.lock:
                key = (stream_id, token)
                if self.recv_next.get(key, 0) < final_sequence:
                    self.pending_close[key] = final_sequence
                    return
            self._close_stream(stream_id, token)
            return
        if message_type != "tunnel_data":
            return
        sequence = int(message.get("seq", -1))
        if sequence < 0:
            return
        token = str(message.get("connection", ""))
        with self.lock:
            active_token = self.stream_tokens.get(stream_id)
        if self.role == "client" and token != active_token:
            return
        if self.role == "host" and active_token is not None and token != active_token:
            return
        payload = base64.b64decode(message.get("data", ""), validate=True)
        if len(payload) > CHUNK_SIZE:
            return
        if self.role == "host" and stream_id not in self.streams:
            try:
                if not token:
                    return
                self._connect_host_stream(stream_id, token)
            except OSError:
                return
        self.session.send(
            {
                "type": "tunnel_ack",
                "stream": stream_id,
                "connection": token,
                "seq": sequence,
            }
        )
        with self.lock:
            key = (stream_id, token)
            expected = self.recv_next.setdefault(key, 0)
            if expected <= sequence < expected + WINDOW_SIZE * 4:
                self.recv_buffers.setdefault(key, {})[sequence] = payload
        self._flush_received(stream_id, token)

    def _flush_received(self, stream_id, token):
        key = (stream_id, token)
        while self.running.is_set():
            with self.lock:
                if self.stream_tokens.get(stream_id) != token:
                    return
                stream = self.streams.get(stream_id)
                expected = self.recv_next.setdefault(key, 0)
                payload = self.recv_buffers.setdefault(key, {}).pop(expected, None)
                if stream is None or payload is None:
                    return
                self.recv_next[key] = expected + 1
            try:
                stream.sendall(payload)
            except OSError:
                return
            with self.lock:
                final_sequence = self.pending_close.get(key)
                if (
                    final_sequence is not None
                    and self.recv_next.get(key, 0) >= final_sequence
                ):
                    self.pending_close.pop(key, None)
                    self._close_stream(stream_id, token)
                    return

    def _close_stream(self, stream_id, token=None):
        with self.window_ready:
            if token is not None and self.stream_tokens.get(stream_id) != token:
                return
            token = self.stream_tokens.get(stream_id, token)
            stream = self.streams.pop(stream_id, None)
            self.stream_tokens.pop(stream_id, None)
            key = (stream_id, token)
            self.send_seq.pop(key, None)
            self.recv_next.pop(key, None)
            self.recv_buffers.pop(key, None)
            self.pending_close.pop(key, None)
            for marker in list(self.unacked):
                if marker[0] == stream_id and marker[1] == token:
                    self.unacked.pop(marker, None)
            self.window_ready.notify_all()
        if stream is not None:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            stream.close()

    def _resend_loop(self):
        while self.running.is_set():
            now = time.monotonic()
            with self.lock:
                opens = [
                    stream_id
                    for stream_id in self.pending_open
                    if now - self.last_open.get(stream_id, 0) >= RESEND_AFTER
                ]
                resend = [
                    (stream_id, token, sequence, record[0])
                    for (stream_id, token, sequence), record in self.unacked.items()
                    if now - record[1] >= RESEND_AFTER
                ]
            for stream_id in opens:
                try:
                    self._send_open(stream_id)
                except OSError:
                    pass
            for stream_id, token, sequence, payload in resend:
                try:
                    self._send_data(stream_id, sequence, payload, token)
                except OSError:
                    pass
            if now - self.last_keepalive >= 2.0:
                self.last_keepalive = now
                try:
                    self.session.send({"type": "tunnel_keepalive", "time": round(now, 3)})
                except OSError:
                    pass
            if now - self.last_peer_activity >= self.peer_timeout:
                self._signal_disconnect(
                    "P2P 对端超过 {:.0f} 秒无响应，准备重新会合".format(
                        self.peer_timeout
                    )
                )
                return
            time.sleep(0.05)
