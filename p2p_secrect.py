"""Authenticated, encrypted, serverless IPv6/IPv4 UDP P2P chat test.

The filename intentionally follows the user's requested ``secrect`` spelling.
The host is passive: it binds a fixed dual-stack port and never needs the
controller address. The controller races every supplied host candidate and
uses the first path that completes the pre-shared-key handshake.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import os
import select
import socket
import struct
import sys
import threading
import time

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from p2p import discover_manual_candidates, format_candidates, format_endpoint, parse_candidates


MAGIC = b"RPS1"
HELLO = 1
CHALLENGE = 2
AUTH = 3
READY = 4
DATA = 5
MAX_DATAGRAM = 65_507
HANDSHAKE_TAG_SIZE = 16


def derive_key(secret: str) -> bytes:
    if len(secret) < 6:
        raise ValueError("密钥至少需要 6 个字符")
    return hashlib.pbkdf2_hmac(
        "sha256", secret.encode("utf-8"), b"rdesk-p2p-secrect-v1", 220_000, 32
    )


def auth_tag(key: bytes, label: bytes, *parts: bytes) -> bytes:
    return hmac.new(key, label + b"".join(parts), hashlib.sha256).digest()[:HANDSHAKE_TAG_SIZE]


def normalize_address(address):
    return str(address[0]), int(address[1])


def session_id(client_nonce: bytes, host_nonce: bytes) -> bytes:
    return hashlib.sha256(client_nonce + host_nonce).digest()[:8]


class SecureDatagramSession:
    """ChaCha20-Poly1305 UDP session with replay protection and no ordering wait."""

    def __init__(self, sock, address, key, client_nonce, host_nonce, is_client):
        self.sock = sock
        self.address = address
        self.session_id = session_id(client_nonce, host_nonce)
        session_key = hmac.new(
            key, b"session" + client_nonce + host_nonce, hashlib.sha256
        ).digest()
        self.cipher = ChaCha20Poly1305(session_key)
        self.send_prefix = b"CLNT" if is_client else b"HOST"
        self.recv_prefix = b"HOST" if is_client else b"CLNT"
        self.send_counter = 0
        self.recv_highest = -1
        self.recv_seen = set()
        self.send_lock = threading.Lock()

    def send(self, value) -> None:
        plaintext = json.dumps(
            value, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        if len(plaintext) > 60_000:
            raise ValueError("消息过大")
        with self.send_lock:
            counter = self.send_counter
            self.send_counter += 1
            counter_bytes = struct.pack("!Q", counter)
            header = MAGIC + bytes((DATA,)) + self.session_id + counter_bytes
            ciphertext = self.cipher.encrypt(
                self.send_prefix + counter_bytes, plaintext, header
            )
            self.sock.sendto(header + ciphertext, self.address)

    def decrypt(self, packet: bytes):
        if len(packet) < 21 + 16 or packet[:5] != MAGIC + bytes((DATA,)):
            raise ValueError("不是加密数据包")
        packet_session = packet[5:13]
        if not hmac.compare_digest(packet_session, self.session_id):
            raise ValueError("会话不匹配")
        counter_bytes = packet[13:21]
        counter = struct.unpack("!Q", counter_bytes)[0]
        if counter in self.recv_seen or counter <= self.recv_highest - 64:
            raise ValueError("重复或过期数据包")
        header = packet[:21]
        plaintext = self.cipher.decrypt(
            self.recv_prefix + counter_bytes, packet[21:], header
        )
        self.recv_seen.add(counter)
        self.recv_highest = max(self.recv_highest, counter)
        floor = self.recv_highest - 64
        self.recv_seen = {value for value in self.recv_seen if value > floor}
        value = json.loads(plaintext.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("消息格式错误")
        return value


def read_secret(argument: str) -> str:
    secret = argument or getpass.getpass("请输入共享密钥（输入不可见）：")
    derive_key(secret)
    return secret


def _packet(packet_type: int, client_nonce: bytes, host_nonce: bytes, tag: bytes) -> bytes:
    return MAGIC + bytes((packet_type,)) + client_nonce + host_nonce + tag


def nominate_session(active, lock, session, family, peer, client_nonce) -> bool:
    """Atomically nominate one address family for a dual-stack handshake."""
    with lock:
        if active["session"] is not None and active["client_nonce"] == client_nonce:
            return False
        active.update(
            session=session,
            family=family,
            peer=peer,
            client_nonce=client_nonce,
            last_seen=time.monotonic(),
        )
    return True


def host_main(args) -> int:
    key = derive_key(read_secret(args.secret))
    sockets, candidates, notes = discover_manual_candidates(args.port)
    print("\n被控端已被动监听，不需要控制端 IP。")
    for note in notes:
        print("- " + note)
    print("\n把下面候选串和端口发给控制端：\n")
    print(format_candidates(candidates))
    print("\n等待密钥正确的控制端连接；/status 查看状态，/quit 退出。")

    running = threading.Event()
    running.set()
    lock = threading.Lock()
    active = {
        "session": None,
        "family": None,
        "peer": None,
        "client_nonce": None,
        "last_seen": 0.0,
    }
    pending = {}
    counters = {
        "received": 0,
        "hello_valid": 0,
        "hello_invalid": 0,
        "challenge_sent": 0,
        "auth_valid": 0,
        "auth_invalid": 0,
        "data_valid": 0,
    }

    def receive_loop():
        while running.is_set():
            try:
                readable, _, _ = select.select(tuple(sockets.values()), (), (), 0.5)
            except (OSError, ValueError):
                return
            for sock in readable:
                try:
                    packet, raw_address = sock.recvfrom(MAX_DATAGRAM)
                except OSError:
                    continue
                if len(packet) < 5 or packet[:4] != MAGIC:
                    continue
                counters["received"] += 1
                address = normalize_address(raw_address)
                family = sock.family
                packet_type = packet[4]
                if packet_type == HELLO and len(packet) == 37:
                    client_nonce, received_tag = packet[5:21], packet[21:37]
                    expected = auth_tag(key, b"hello", client_nonce)
                    if not hmac.compare_digest(received_tag, expected):
                        counters["hello_invalid"] += 1
                        continue
                    counters["hello_valid"] += 1
                    host_nonce = os.urandom(16)
                    pending[(family, address, client_nonce, host_nonce)] = time.monotonic()
                    tag = auth_tag(key, b"challenge", client_nonce, host_nonce)
                    sock.sendto(_packet(CHALLENGE, client_nonce, host_nonce, tag), raw_address)
                    counters["challenge_sent"] += 1
                    continue
                if packet_type == AUTH and len(packet) == 53:
                    client_nonce, host_nonce, received_tag = packet[5:21], packet[21:37], packet[37:53]
                    pending_value = pending.get((family, address, client_nonce, host_nonce))
                    if pending_value is None:
                        counters["auth_invalid"] += 1
                        continue
                    expected = auth_tag(key, b"auth", client_nonce, host_nonce)
                    if not hmac.compare_digest(received_tag, expected):
                        counters["auth_invalid"] += 1
                        continue
                    counters["auth_valid"] += 1
                    pending.pop((family, address, client_nonce, host_nonce), None)
                    session = SecureDatagramSession(
                        sock, raw_address, key, client_nonce, host_nonce, is_client=False
                    )
                    # IPv6 and IPv4 AUTH packets from one controller race each
                    # other. Nominate only the first; replying READY on both
                    # could make the peers choose different families.
                    if not nominate_session(
                        active, lock, session, family, address, client_nonce
                    ):
                        continue
                    tag = auth_tag(key, b"ready", client_nonce, host_nonce)
                    sock.sendto(_packet(READY, client_nonce, host_nonce, tag), raw_address)
                    label = "IPv6" if family == socket.AF_INET6 else "IPv4"
                    print("\n[认证成功] {} {}".format(label, format_endpoint(address)))
                    print("> ", end="", flush=True)
                    continue
                if packet_type != DATA:
                    continue
                with lock:
                    session = active["session"]
                    peer = active["peer"]
                    selected_family = active["family"]
                if session is None or family != selected_family or address != peer:
                    continue
                try:
                    value = session.decrypt(packet)
                except Exception:
                    continue
                counters["data_valid"] += 1
                with lock:
                    active["last_seen"] = time.monotonic()
                if value.get("type") == "ping":
                    session.send({"type": "pong", "time": value.get("time")})
                elif value.get("type") == "text":
                    print("\n控制端 > {}".format(value.get("text", "")))
                    print("> ", end="", flush=True)
            cutoff = time.monotonic() - 10
            for marker, created in list(pending.items()):
                if created < cutoff:
                    pending.pop(marker, None)

    thread = threading.Thread(target=receive_loop, name="secure-host-recv", daemon=True)
    thread.start()
    try:
        while True:
            message = input("> ")
            if message == "/quit":
                break
            with lock:
                session = active["session"]
                family = active["family"]
                peer = active["peer"]
                last_seen = active["last_seen"]
            if message == "/status":
                if session is None:
                    print("尚无已认证控制端")
                else:
                    label = "IPv6" if family == socket.AF_INET6 else "IPv4"
                    age = time.monotonic() - last_seen
                    print("已认证：{} {}，最近通信 {:.1f}s 前".format(label, format_endpoint(peer), age))
                print(
                    "握手计数：收包 {received} / HELLO正确 {hello_valid} / "
                    "HELLO密钥错误 {hello_invalid} / 已发挑战 {challenge_sent} / "
                    "AUTH正确 {auth_valid} / AUTH无效 {auth_invalid} / "
                    "加密数据 {data_valid}".format(**counters)
                )
            elif session is None:
                print("尚无已认证控制端")
            else:
                session.send({"type": "text", "text": message})
        return 0
    except (KeyboardInterrupt, EOFError):
        return 0
    finally:
        running.clear()
        for sock in sockets.values():
            sock.close()


def controller_handshake(candidates, key, timeout=12):
    sockets = {}
    client_nonce = os.urandom(16)
    challenges = {}
    attempts = {family: 0 for family in candidates}
    send_errors = {}
    for family in candidates:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind(("::", 0))
        else:
            sock.bind(("0.0.0.0", 0))
        sockets[family] = sock
    hello = MAGIC + bytes((HELLO,)) + client_nonce + auth_tag(key, b"hello", client_nonce)
    deadline = time.monotonic() + timeout
    last_send = 0.0
    try:
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now - last_send >= 0.4:
                for family, endpoint in candidates.items():
                    try:
                        sockets[family].sendto(hello, endpoint)
                        attempts[family] += 1
                    except OSError as exc:
                        send_errors[family] = str(exc)
                last_send = now
            readable, _, _ = select.select(tuple(sockets.values()), (), (), 0.2)
            for sock in readable:
                packet, raw_address = sock.recvfrom(MAX_DATAGRAM)
                if len(packet) != 53 or packet[:4] != MAGIC:
                    continue
                packet_type = packet[4]
                echoed_client, host_nonce, received_tag = packet[5:21], packet[21:37], packet[37:53]
                if not hmac.compare_digest(echoed_client, client_nonce):
                    continue
                family = sock.family
                address = normalize_address(raw_address)
                if packet_type == CHALLENGE:
                    expected = auth_tag(key, b"challenge", client_nonce, host_nonce)
                    if not hmac.compare_digest(received_tag, expected):
                        continue
                    challenges[(family, address)] = (host_nonce, raw_address)
                    tag = auth_tag(key, b"auth", client_nonce, host_nonce)
                    sock.sendto(_packet(AUTH, client_nonce, host_nonce, tag), raw_address)
                elif packet_type == READY:
                    expected = auth_tag(key, b"ready", client_nonce, host_nonce)
                    known = challenges.get((family, address))
                    if known is None or not hmac.compare_digest(known[0], host_nonce):
                        continue
                    if not hmac.compare_digest(received_tag, expected):
                        continue
                    session = SecureDatagramSession(
                        sock, raw_address, key, client_nonce, host_nonce, is_client=True
                    )
                    for other_family, other_sock in list(sockets.items()):
                        if other_family != family:
                            other_sock.close()
                            sockets.pop(other_family, None)
                    return session, family, sockets
        details = []
        for family in candidates:
            label = "IPv6" if family == socket.AF_INET6 else "IPv4"
            challenged = any(marker[0] == family for marker in challenges)
            detail = "{} 已发送{}次，{}".format(
                label,
                attempts[family],
                "收到挑战" if challenged else "未收到挑战",
            )
            if family in send_errors:
                detail += "，发送错误：{}".format(send_errors[family])
            details.append(detail)
        raise TimeoutError(
            "IPv6/IPv4 均未完成密钥认证（{}）。检查被控端 /status、端口、防火墙和密钥".format(
                "；".join(details)
            )
        )
    except Exception:
        for sock in sockets.values():
            sock.close()
        raise


def client_main(args) -> int:
    key = derive_key(read_secret(args.secret))
    peer_text = args.peer or input("请输入被控端候选串：").strip()
    candidates = parse_candidates(peer_text)
    print("正在并行认证 {}...".format(
        " / ".join("IPv6" if family == socket.AF_INET6 else "IPv4" for family in candidates)
    ))
    session, family, sockets = controller_handshake(candidates, key, args.timeout)
    label = "IPv6" if family == socket.AF_INET6 else "IPv4"
    print("[连接成功] {} {}，通信已加密；/status 查看路径，/quit 退出。".format(
        label, format_endpoint(normalize_address(session.address))
    ))
    running = threading.Event()
    running.set()

    def receive_loop():
        session.sock.settimeout(0.5)
        while running.is_set():
            try:
                packet, address = session.sock.recvfrom(MAX_DATAGRAM)
            except socket.timeout:
                continue
            except OSError:
                return
            if normalize_address(address) != normalize_address(session.address):
                continue
            try:
                value = session.decrypt(packet)
            except Exception:
                continue
            if value.get("type") == "text":
                print("\n被控端 > {}".format(value.get("text", "")))
                print("> ", end="", flush=True)

    def keepalive_loop():
        while running.is_set():
            time.sleep(5)
            if not running.is_set():
                return
            try:
                session.send({"type": "ping", "time": time.time()})
            except OSError:
                return

    threading.Thread(target=receive_loop, name="secure-client-recv", daemon=True).start()
    threading.Thread(target=keepalive_loop, name="secure-client-keepalive", daemon=True).start()
    try:
        while True:
            message = input("> ")
            if message == "/quit":
                break
            if message == "/status":
                print("当前路径：{} {}；ChaCha20-Poly1305".format(
                    label, format_endpoint(normalize_address(session.address))
                ))
            else:
                session.send({"type": "text", "text": message})
        return 0
    except (KeyboardInterrupt, EOFError):
        return 0
    finally:
        running.clear()
        for sock in sockets.values():
            sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="被控端被动监听、控制端双栈竞速的密钥认证加密 UDP P2P 测试"
    )
    subparsers = parser.add_subparsers(dest="role", required=True)
    host = subparsers.add_parser("host", help="被控端：只设置端口和密钥")
    host.add_argument("--port", type=int, default=45020)
    host.add_argument("--secret", default="", help="省略则安全地交互输入")
    client = subparsers.add_parser("client", help="控制端：填写被控端候选和密钥")
    client.add_argument("--peer", default="", help="被控端 ipv6=...;ipv4=... 候选串")
    client.add_argument("--secret", default="", help="省略则安全地交互输入")
    client.add_argument("--timeout", type=float, default=12)
    args = parser.parse_args()
    try:
        return host_main(args) if args.role == "host" else client_main(args)
    except Exception as exc:
        print("[ERROR] {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
