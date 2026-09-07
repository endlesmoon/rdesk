"""Rendezvous-assisted, end-to-end encrypted IPv4/IPv6 UDP P2P test.

The public server only verifies registrations and exchanges address candidates.
It never receives the pre-shared secret and it has no packet-relay function.
After matching, both peers punch directly from the same sockets used to register.

Roles:
    server  public address-only rendezvous service (standard library only)
    host    controlled Ubuntu endpoint
    client  controlling Windows endpoint
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import select
import socket
import sys
import threading
import time


PROTOCOL_MAGIC = "rdesk-address-rendezvous-v1"
PROTOCOL_VERSION = 1
REGISTER_INTERVAL = 0.45
ROOM_TTL = 35.0
MAX_CONTROL_PACKET = 4096

PUNCH_MAGIC = b"RPH1"
PUNCH_HOST = 1
PUNCH_CLIENT = 2


def parse_endpoint(text: str):
    text = text.strip()
    if text.startswith("["):
        closing = text.find("]")
        if closing < 0 or not text[closing + 1 :].startswith(":"):
            raise ValueError("IPv6 格式应为 [IPv6]:PORT")
        host, port_text = text[1:closing], text[closing + 2 :]
    elif text.count(":") == 1:
        host, port_text = text.rsplit(":", 1)
    else:
        raise ValueError("格式应为 IPv4:PORT 或 [IPv6]:PORT")
    port = int(port_text)
    if not host or not 1 <= port <= 65535:
        raise ValueError("IP 或端口无效")
    return host, port


def format_endpoint(endpoint) -> str:
    host, port = str(endpoint[0]), int(endpoint[1])
    return "[{}]:{}".format(host, port) if ":" in host else "{}:{}".format(host, port)


def normalize_address(address):
    host = str(address[0])
    if host.lower().startswith("::ffff:"):
        host = host.rsplit(":", 1)[-1]
    return host, int(address[1])


def control_packet(packet_type: str, **values) -> bytes:
    message = {
        "magic": PROTOCOL_MAGIC,
        "version": PROTOCOL_VERSION,
        "type": packet_type,
    }
    message.update(values)
    encoded = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_CONTROL_PACKET:
        raise ValueError("会合控制包过大")
    return encoded


def parse_control_packet(data: bytes):
    if len(data) > MAX_CONTROL_PACKET:
        raise ValueError("控制包过大")
    message = json.loads(data.decode("utf-8"))
    if not isinstance(message, dict):
        raise ValueError("控制包不是对象")
    if message.get("magic") != PROTOCOL_MAGIC or message.get("version") != PROTOCOL_VERSION:
        raise ValueError("控制包协议不匹配")
    return message


def room_id(key: bytes, room_name: str) -> str:
    """Return an opaque, fixed-size rendezvous identifier; never send the key."""
    room_bytes = room_name.encode("utf-8")
    return hmac.new(key, b"rendezvous-room-v1\0" + room_bytes, hashlib.sha256).hexdigest()[:32]


def _candidate(family: int, endpoint):
    return {
        "family": 6 if family == socket.AF_INET6 else 4,
        "host": str(endpoint[0]),
        "port": int(endpoint[1]),
    }


def _parse_candidates(values):
    result = []
    seen = set()
    if not isinstance(values, list):
        return result
    for value in values[:8]:
        try:
            family_number = int(value["family"])
            host = str(value["host"])
            port = int(value["port"])
            address = ipaddress.ip_address(host.split("%", 1)[0])
            if family_number not in (4, 6) or address.version != family_number:
                continue
            if not 1 <= port <= 65535 or address.is_unspecified or address.is_multicast:
                continue
            marker = (family_number, host, port)
            if marker not in seen:
                result.append({"family": family_number, "host": host, "port": port})
                seen.add(marker)
        except (KeyError, TypeError, ValueError):
            continue
    return result


class RendezvousServer:
    """Small UDP rendezvous service with cookie-verified source addresses."""

    def __init__(self, bind=("::", 45030), ttl=ROOM_TTL, max_rooms=2048):
        bind_host, bind_port = str(bind[0]), int(bind[1])
        self.sock, self.dual_stack = self._bind_socket(bind_host, bind_port)
        self._ipv6_pktinfo_type = None
        self._ipv6_pktinfo_enabled = False
        recv_pktinfo = getattr(socket, "IPV6_RECVPKTINFO", None)
        pktinfo_type = getattr(socket, "IPV6_PKTINFO", None)
        if (
            self.sock.family == socket.AF_INET6
            and recv_pktinfo is not None
            and pktinfo_type is not None
            and hasattr(self.sock, "recvmsg")
            and hasattr(self.sock, "sendmsg")
        ):
            try:
                self.sock.setsockopt(socket.IPPROTO_IPV6, recv_pktinfo, 1)
                self._ipv6_pktinfo_type = pktinfo_type
                self._ipv6_pktinfo_enabled = True
            except OSError:
                pass
        self.sock.settimeout(0.5)
        self.address = normalize_address(self.sock.getsockname())
        self.ttl = float(ttl)
        self.max_rooms = int(max_rooms)
        self.cookie_key = os.urandom(32)
        self.rooms = {}
        self.running = threading.Event()
        self.running.set()
        self.stats = {"packets": 0, "verified": 0, "matches": 0, "invalid": 0}

    @staticmethod
    def _bind_socket(host, port):
        """Bind one IPv6/IPv4 UDP socket, preferring dual-stack for ``::``."""
        flags = socket.AI_PASSIVE if host in ("", "::", "0.0.0.0") else 0
        try:
            results = socket.getaddrinfo(
                host or "::",
                port,
                socket.AF_UNSPEC,
                socket.SOCK_DGRAM,
                0,
                flags,
            )
        except socket.gaierror:
            results = []
        # An IPv6 wildcard socket with V6ONLY=0 also accepts IPv4-mapped UDP,
        # keeping deployment to one process and one public port.
        results.sort(key=lambda value: 0 if value[0] == socket.AF_INET6 else 1)
        last_error = None
        for family, socktype, protocol, _canonname, address in results:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            sock = socket.socket(family, socktype, protocol)
            dual_stack = False
            try:
                if family == socket.AF_INET6:
                    dual_stack = host in ("", "::")
                    sock.setsockopt(
                        socket.IPPROTO_IPV6,
                        socket.IPV6_V6ONLY,
                        0 if dual_stack else 1,
                    )
                sock.bind(address)
                return sock, dual_stack
            except OSError as exc:
                last_error = exc
                sock.close()
        if last_error is not None:
            raise last_error
        raise OSError("无法绑定会合服务器地址 {}:{}".format(host, port))

    def close(self):
        self.running.clear()
        self.sock.close()

    def _cookie(self, address, room, role, bucket=None):
        if bucket is None:
            bucket = int(time.time() // 30)
        material = "{}:{}|{}|{}|{}".format(
            address[0], address[1], room, role, bucket
        ).encode("utf-8")
        digest = hmac.new(self.cookie_key, material, hashlib.sha256).digest()[:18]
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    def _valid_cookie(self, cookie, address, room, role):
        current = int(time.time() // 30)
        return any(
            hmac.compare_digest(str(cookie), self._cookie(address, room, role, bucket))
            for bucket in (current, current - 1)
        )

    def _send(self, address, packet_type, reply_route=None, **values):
        packet = control_packet(packet_type, **values)
        if (
            reply_route is not None
            and self._ipv6_pktinfo_enabled
            and self._ipv6_pktinfo_type is not None
        ):
            try:
                # Reuse the exact IPV6_PKTINFO from recvmsg. This forces the
                # reply source to be the destination address selected by the
                # client, instead of a different temporary/privacy address.
                self.sock.sendmsg(
                    [packet],
                    [
                        (
                            socket.IPPROTO_IPV6,
                            self._ipv6_pktinfo_type,
                            reply_route,
                        )
                    ],
                    0,
                    address,
                )
                return
            except OSError:
                # Client-side validated alias pinning remains the portable
                # fallback on platforms without working IPV6_PKTINFO sendmsg.
                pass
        self.sock.sendto(packet, address)

    def _receive(self):
        if self._ipv6_pktinfo_enabled:
            data, ancillary, _flags, address = self.sock.recvmsg(
                MAX_CONTROL_PACKET + 1,
                socket.CMSG_SPACE(20),
            )
            for level, message_type, value in ancillary:
                if (
                    level == socket.IPPROTO_IPV6
                    and message_type == self._ipv6_pktinfo_type
                    and len(value) >= 20
                ):
                    return data, address, value[:20]
            return data, address, None
        data, address = self.sock.recvfrom(MAX_CONTROL_PACKET + 1)
        return data, address, None

    def _purge(self):
        cutoff = time.monotonic() - self.ttl
        for room, peers in list(self.rooms.items()):
            for role in ("host", "client"):
                peer = peers.get(role)
                if peer is not None and peer["seen"] < cutoff:
                    peers.pop(role, None)
            if "host" not in peers and "client" not in peers:
                self.rooms.pop(room, None)

    def _register(self, message, address, reply_address=None, reply_route=None):
        reply_address = reply_address or address
        room = str(message.get("room", ""))
        role = str(message.get("role", ""))
        if len(room) != 32 or role not in ("host", "client"):
            raise ValueError("注册房间或角色无效")
        int(room, 16)

        cookie = str(message.get("cookie", ""))
        if not self._valid_cookie(cookie, address, room, role):
            self._send(
                reply_address,
                "register_challenge",
                reply_route=reply_route,
                room=room,
                role=role,
                cookie=self._cookie(address, room, role),
                observed=_candidate(_address_family(address), address),
            )
            return

        candidates = _parse_candidates(message.get("candidates", []))
        observed_family = _address_family(address)
        # The source mapping observed by the server is authoritative for its
        # family. Retain only advertised candidates from the other family so a
        # peer registered over IPv4 can still publish IPv6, and vice versa.
        peer_candidates = [_candidate(observed_family, address)]
        peer_candidates.extend(
            value
            for value in candidates
            if value["family"] != (6 if observed_family == socket.AF_INET6 else 4)
        )

        if room not in self.rooms and len(self.rooms) >= self.max_rooms:
            raise ValueError("会合房间已满")
        peers = self.rooms.setdefault(room, {})
        previous = peers.get(role)
        if previous and previous["address"] != address:
            peers.pop("match_id", None)
        peers[role] = {
            "address": address,
            "reply_address": reply_address,
            "reply_route": reply_route,
            "candidates": peer_candidates,
            "seen": time.monotonic(),
        }
        self.stats["verified"] += 1
        self._send(
            reply_address,
            "registered",
            reply_route=reply_route,
            room=room,
            role=role,
            observed=_candidate(observed_family, address),
        )

        if "host" not in peers or "client" not in peers:
            return
        match_id = peers.setdefault("match_id", os.urandom(8).hex())
        punch_at = time.time() + 0.55
        for target_role, other_role in (("host", "client"), ("client", "host")):
            target = peers[target_role]
            other = peers[other_role]
            self._send(
                target["reply_address"],
                "match",
                reply_route=target.get("reply_route"),
                room=room,
                match_id=match_id,
                peer_role=other_role,
                peer_candidates=other["candidates"],
                punch_at=punch_at,
            )
        self.stats["matches"] += 1

    def serve_forever(self):
        last_purge = 0.0
        while self.running.is_set():
            try:
                data, raw_address, reply_route = self._receive()
            except socket.timeout:
                data = None
            except OSError:
                return
            if data is not None:
                self.stats["packets"] += 1
                try:
                    message = parse_control_packet(data)
                    if message.get("type") != "register":
                        raise ValueError("服务器只接受注册包")
                    self._register(
                        message,
                        normalize_address(raw_address),
                        raw_address,
                        reply_route,
                    )
                except Exception:
                    self.stats["invalid"] += 1
            now = time.monotonic()
            if now - last_purge >= 2:
                self._purge()
                last_purge = now


def _address_family(address):
    parsed = ipaddress.ip_address(str(address[0]).split("%", 1)[0])
    return socket.AF_INET6 if parsed.version == 6 else socket.AF_INET


def _resolve_server(endpoint, enable_ipv6=True):
    host, port = str(endpoint[0]).strip(), int(endpoint[1])
    # The GUI stores host and port separately, but accept either ``2001:db8::1``
    # or ``[2001:db8::1]`` so users can paste an address from endpoint notation.
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    results = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    results = [
        value
        for value in results
        if value[0] == socket.AF_INET
        or (enable_ipv6 and value[0] == socket.AF_INET6)
    ]
    if not results:
        family_text = "IPv4/IPv6" if enable_ipv6 else "IPv4"
        raise OSError("无法解析会合服务器 {} 地址".format(family_text))
    family, _socktype, _protocol, _canonname, address = results[0]
    return family, address


def _server_control_source_allowed(
    family, address, server_family, server_port, pinned_address=None
):
    """Allow a valid first reply from another address owned by the server.

    A UDP socket bound to ``::`` can receive a datagram on one stable IPv6
    address while the kernel selects a different privacy IPv6 address for the
    reply.  The control packet's secret-derived room ID and role are validated
    before an initial source is pinned; after that, address validation is
    strict again.
    """
    normalized = normalize_address(address)
    if family != server_family or normalized[1] != int(server_port):
        return False
    return pinned_address is None or normalized == normalize_address(pinned_address)


def _routed_ipv6():
    probe = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        probe.connect(("2001:4860:4860::8888", 53))
        address = str(probe.getsockname()[0])
        parsed = ipaddress.ip_address(address.split("%", 1)[0])
        return address if not parsed.is_unspecified and not parsed.is_loopback else None
    except OSError:
        return None
    finally:
        probe.close()


def create_peer_sockets(port=0, enable_ipv6=True):
    port = int(port)
    if not 0 <= port <= 65535:
        raise ValueError("本地端口必须是 0-65535")
    sockets = {}
    ipv4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ipv4.bind(("0.0.0.0", port))
    sockets[socket.AF_INET] = ipv4
    selected_port = int(ipv4.getsockname()[1])
    if enable_ipv6:
        ipv6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            ipv6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            ipv6.bind(("::", selected_port))
            sockets[socket.AF_INET6] = ipv6
        except OSError:
            ipv6.close()
    return sockets, selected_port


def local_candidates(sockets, local_port):
    values = []
    if socket.AF_INET6 in sockets:
        address = _routed_ipv6()
        if address:
            values.append(_candidate(socket.AF_INET6, (address, local_port)))
    return values


def _candidate_targets(values, sockets):
    targets = []
    seen = set()
    for value in _parse_candidates(values):
        family = socket.AF_INET6 if value["family"] == 6 else socket.AF_INET
        if family not in sockets:
            continue
        endpoint = (value["host"], value["port"])
        marker = (family, endpoint)
        if marker not in seen:
            targets.append(marker)
            seen.add(marker)
    return targets


def _punch_packet(key, role, nonce):
    role_byte = PUNCH_HOST if role == "host" else PUNCH_CLIENT
    body = PUNCH_MAGIC + bytes((role_byte,)) + nonce
    return body + hmac.new(key, b"punch-v1" + body, hashlib.sha256).digest()[:16]


def _parse_punch(packet, key):
    if len(packet) != 37 or packet[:4] != PUNCH_MAGIC:
        raise ValueError("不是打洞包")
    body, received = packet[:21], packet[21:]
    expected = hmac.new(key, b"punch-v1" + body, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(received, expected):
        raise ValueError("打洞包认证失败")
    role = "host" if packet[4] == PUNCH_HOST else "client" if packet[4] == PUNCH_CLIENT else None
    if role is None:
        raise ValueError("打洞角色无效")
    return role, packet[5:21]


def establish_peer(role, server, key, room_name="default", port=0, timeout=30, enable_ipv6=True):
    """Rendezvous, simultaneous punch, and complete the encrypted PSK handshake."""
    import p2p_secrect as secure

    if role not in ("host", "client"):
        raise ValueError("端点角色必须是 host 或 client")
    server_family, server_address = _resolve_server(server, enable_ipv6)
    sockets, local_port = create_peer_sockets(port, enable_ipv6)
    if server_family not in sockets:
        for sock in sockets.values():
            sock.close()
        raise OSError("没有可用于连接会合服务器的 UDP 地址族")
    normalized_server_address = normalize_address(server_address)
    pinned_server_reply = None
    rendezvous_room = room_id(key, room_name)
    advertised = local_candidates(sockets, local_port)
    cookie = ""
    registered = False
    targets = []
    punch_at = 0.0
    match_id = ""
    own_nonce = os.urandom(16)
    client_nonce = os.urandom(16) if role == "client" else None
    pending = {}
    challenges = {}
    session = None
    selected_family = None
    last_register = 0.0
    last_direct_send = 0.0
    started = time.monotonic()
    counters = {
        "register": 0,
        "challenge": 0,
        "registered": 0,
        "match": 0,
        "punch_sent": 0,
        "punch_received": 0,
        "hello_sent": 0,
        "hello_received": 0,
    }

    def send_register():
        nonlocal last_register
        packet = control_packet(
            "register",
            room=rendezvous_room,
            role=role,
            cookie=cookie,
            candidates=advertised,
        )
        sockets[server_family].sendto(packet, server_address)
        counters["register"] += 1
        last_register = time.monotonic()

    try:
        while time.monotonic() - started < float(timeout):
            now = time.monotonic()
            if now - last_register >= REGISTER_INTERVAL:
                send_register()

            if targets and time.time() >= punch_at and now - last_direct_send >= 0.12:
                punch = _punch_packet(key, role, own_nonce)
                hello = None
                if role == "client":
                    hello = (
                        secure.MAGIC
                        + bytes((secure.HELLO,))
                        + client_nonce
                        + secure.auth_tag(key, b"hello", client_nonce)
                    )
                for family, endpoint in list(targets):
                    try:
                        sockets[family].sendto(punch, endpoint)
                        counters["punch_sent"] += 1
                        if hello is not None:
                            sockets[family].sendto(hello, endpoint)
                            counters["hello_sent"] += 1
                    except OSError:
                        continue
                last_direct_send = now

            readable, _, _ = select.select(tuple(sockets.values()), (), (), 0.12)
            for sock in readable:
                packet, raw_address = sock.recvfrom(secure.MAX_DATAGRAM)
                family = sock.family
                address = secure.normalize_address(raw_address)

                server_source_candidate = _server_control_source_allowed(
                    family,
                    address,
                    server_family,
                    normalized_server_address[1],
                    pinned_server_reply,
                )
                if server_source_candidate:
                    try:
                        message = parse_control_packet(packet)
                    except Exception:
                        message = None
                    packet_type = message.get("type") if message is not None else None
                    valid_room = (
                        message is not None
                        and message.get("room") == rendezvous_room
                    )
                    bootstrap_reply = (
                        valid_room
                        and packet_type in ("register_challenge", "registered")
                        and message.get("role") == role
                    )
                    if pinned_server_reply is None and bootstrap_reply:
                        pinned_server_reply = address
                        # Keep sending registrations to the configured stable
                        # address, but only accept subsequent replies from this
                        # room/role-validated source.
                        if address != normalized_server_address:
                            print(
                                "[会合] 配置地址 {} 的实际回包地址为 {}，已验证并锁定。".format(
                                    format_endpoint(normalized_server_address),
                                    format_endpoint(address),
                                )
                            )
                    if not valid_room or pinned_server_reply != address:
                        # It was not an authenticated rendezvous control packet;
                        # allow the normal P2P packet handlers below to inspect it.
                        message = None

                if server_source_candidate and message is not None:
                    if packet_type == "register_challenge" and message.get("role") == role:
                        cookie = str(message.get("cookie", ""))
                        counters["challenge"] += 1
                        last_register = 0.0
                    elif packet_type == "registered" and message.get("role") == role:
                        if not registered:
                            observed = message.get("observed", {})
                            observed_label = (
                                "IPv6" if int(observed.get("family", 4)) == 6 else "IPv4"
                            )
                            print(
                                "[会合] 已注册，服务器观察到 {} {}:{}".format(
                                    observed_label,
                                    observed.get("host", "?"), observed.get("port", "?")
                                )
                            )
                        registered = True
                        counters["registered"] = 1
                    elif packet_type == "match":
                        new_targets = _candidate_targets(message.get("peer_candidates", []), sockets)
                        if new_targets:
                            targets = new_targets
                            incoming_match_id = str(message.get("match_id", ""))
                            if incoming_match_id != match_id:
                                match_id = incoming_match_id
                                punch_at = min(
                                    float(message.get("punch_at", time.time())),
                                    time.time() + 1.5,
                                )
                                counters["match"] += 1
                                print(
                                    "[会合] 已取得对端 {} 个候选，双方开始同时打洞；后续数据不经过服务器。".format(
                                        len(targets)
                                    )
                                )
                    continue

                if packet.startswith(PUNCH_MAGIC):
                    try:
                        peer_role, _nonce = _parse_punch(packet, key)
                    except ValueError:
                        continue
                    if peer_role == role:
                        continue
                    counters["punch_received"] += 1
                    marker = (family, address)
                    if marker not in targets:
                        targets.insert(0, marker)
                    continue

                if len(packet) < 5 or packet[:4] != secure.MAGIC:
                    continue
                packet_type = packet[4]
                if role == "host" and packet_type == secure.HELLO and len(packet) == 37:
                    remote_client_nonce = packet[5:21]
                    received_tag = packet[21:37]
                    expected = secure.auth_tag(key, b"hello", remote_client_nonce)
                    if not hmac.compare_digest(received_tag, expected):
                        continue
                    counters["hello_received"] += 1
                    marker = (family, address, remote_client_nonce)
                    host_nonce, _created = pending.get(marker, (os.urandom(16), now))
                    pending[marker] = (host_nonce, now)
                    tag = secure.auth_tag(key, b"challenge", remote_client_nonce, host_nonce)
                    sock.sendto(
                        secure._packet(secure.CHALLENGE, remote_client_nonce, host_nonce, tag),
                        raw_address,
                    )
                    continue

                if role == "host" and packet_type == secure.AUTH and len(packet) == 53:
                    remote_client_nonce = packet[5:21]
                    host_nonce = packet[21:37]
                    received_tag = packet[37:53]
                    marker = (family, address, remote_client_nonce)
                    known = pending.get(marker)
                    if known is None or not hmac.compare_digest(known[0], host_nonce):
                        continue
                    expected = secure.auth_tag(key, b"auth", remote_client_nonce, host_nonce)
                    if not hmac.compare_digest(received_tag, expected):
                        continue
                    session = secure.SecureDatagramSession(
                        sock, raw_address, key, remote_client_nonce, host_nonce, is_client=False
                    )
                    selected_family = family
                    tag = secure.auth_tag(key, b"ready", remote_client_nonce, host_nonce)
                    # A few READY copies make the final nomination resilient to UDP loss.
                    for _ in range(3):
                        sock.sendto(
                            secure._packet(secure.READY, remote_client_nonce, host_nonce, tag),
                            raw_address,
                        )
                    break

                if role == "client" and packet_type == secure.CHALLENGE and len(packet) == 53:
                    echoed_client = packet[5:21]
                    host_nonce = packet[21:37]
                    received_tag = packet[37:53]
                    if not hmac.compare_digest(echoed_client, client_nonce):
                        continue
                    expected = secure.auth_tag(key, b"challenge", client_nonce, host_nonce)
                    if not hmac.compare_digest(received_tag, expected):
                        continue
                    challenges[(family, address)] = host_nonce
                    tag = secure.auth_tag(key, b"auth", client_nonce, host_nonce)
                    sock.sendto(
                        secure._packet(secure.AUTH, client_nonce, host_nonce, tag), raw_address
                    )
                    continue

                if role == "client" and packet_type == secure.READY and len(packet) == 53:
                    echoed_client = packet[5:21]
                    host_nonce = packet[21:37]
                    received_tag = packet[37:53]
                    known = challenges.get((family, address))
                    if known is None or not hmac.compare_digest(echoed_client, client_nonce):
                        continue
                    if not hmac.compare_digest(known, host_nonce):
                        continue
                    expected = secure.auth_tag(key, b"ready", client_nonce, host_nonce)
                    if not hmac.compare_digest(received_tag, expected):
                        continue
                    session = secure.SecureDatagramSession(
                        sock, raw_address, key, client_nonce, host_nonce, is_client=True
                    )
                    selected_family = family
                    break

            if session is not None:
                for other_family, other_sock in list(sockets.items()):
                    if other_family != selected_family:
                        other_sock.close()
                        sockets.pop(other_family, None)
                return session, selected_family, sockets, counters

            cutoff = now - 10
            for marker, value in list(pending.items()):
                if value[1] < cutoff:
                    pending.pop(marker, None)

        raise TimeoutError(
            "{} 秒内未建立直连：发注册{}次、收挑战{}次、注册确认{}次、匹配{}次、发打洞包{}、收打洞包{}、发HELLO{}、收HELLO{}".format(
                timeout,
                counters["register"],
                counters["challenge"],
                counters["registered"],
                counters["match"],
                counters["punch_sent"],
                counters["punch_received"],
                counters["hello_sent"],
                counters["hello_received"],
            )
        )
    except Exception:
        for sock in sockets.values():
            sock.close()
        raise


def chat_peer(args):
    import p2p_secrect as secure

    secret = secure.read_secret(args.secret)
    key = secure.derive_key(secret)
    server = parse_endpoint(args.server)
    print(
        "{} 正在向 {} 注册（房间名：{}）；密钥不会发送给服务器。".format(
            "被控端" if args.role == "host" else "控制端",
            format_endpoint(server),
            args.room,
        )
    )
    session, family, sockets, counters = establish_peer(
        args.role,
        server,
        key,
        room_name=args.room,
        port=args.port,
        timeout=args.timeout,
        enable_ipv6=not args.ipv4_only,
    )
    label = "IPv6" if family == socket.AF_INET6 else "IPv4"
    print(
        "[P2P成功] {} {}；认证和通信为 ChaCha20-Poly1305 端到端加密。".format(
            label, format_endpoint(secure.normalize_address(session.address))
        )
    )
    print("服务器已退出数据路径；/status 查看状态，/quit 退出。")
    running = threading.Event()
    running.set()
    last_seen = [time.monotonic()]

    def receive_loop():
        session.sock.settimeout(0.5)
        while running.is_set():
            try:
                packet, raw_address = session.sock.recvfrom(secure.MAX_DATAGRAM)
            except socket.timeout:
                continue
            except OSError:
                return
            if secure.normalize_address(raw_address) != secure.normalize_address(session.address):
                continue
            try:
                value = session.decrypt(packet)
            except Exception:
                continue
            last_seen[0] = time.monotonic()
            if value.get("type") == "ping":
                session.send({"type": "pong", "time": value.get("time")})
            elif value.get("type") == "text":
                peer_name = "控制端" if args.role == "host" else "被控端"
                print("\n{} > {}".format(peer_name, value.get("text", "")))
                print("> ", end="", flush=True)

    threading.Thread(target=receive_loop, name="rendezvous-p2p-recv", daemon=True).start()

    def timed_keepalive():
        while running.is_set():
            time.sleep(5)
            if running.is_set():
                try:
                    session.send({"type": "ping", "time": time.time()})
                except OSError:
                    return

    threading.Thread(target=timed_keepalive, name="rendezvous-p2p-keepalive", daemon=True).start()
    try:
        while True:
            message = input("> ")
            if message == "/quit":
                break
            if message == "/status":
                print(
                    "当前路径：{} {}；最近收包 {:.1f}s 前；会合后服务器流量 0；{}".format(
                        label,
                        format_endpoint(secure.normalize_address(session.address)),
                        time.monotonic() - last_seen[0],
                        ", ".join("{}={}".format(k, v) for k, v in counters.items()),
                    )
                )
            else:
                session.send({"type": "text", "text": message})
        return 0
    except (KeyboardInterrupt, EOFError):
        return 0
    finally:
        running.clear()
        for sock in sockets.values():
            sock.close()


def server_main(args):
    service = RendezvousServer((args.bind, args.port), ttl=args.ttl, max_rooms=args.max_rooms)
    print("只交换地址的 UDP 会合服务器已启动：{}".format(format_endpoint(service.address)))
    if service.sock.family == socket.AF_INET6:
        print(
            "IPv6 回包源地址固定：{}".format(
                "已启用 IPV6_PKTINFO"
                if service._ipv6_pktinfo_enabled
                else "当前系统不支持，使用客户端地址锁定兼容模式"
            )
        )
    print("不会接收密钥、聊天、画面或媒体数据；Ctrl+C 退出。")
    try:
        service.serve_forever()
        return 0
    except KeyboardInterrupt:
        print("\n服务器已停止。")
        return 0
    finally:
        service.close()


def main():
    parser = argparse.ArgumentParser(description="只交换地址、媒体和数据端到端直连的 UDP P2P 测试")
    subparsers = parser.add_subparsers(dest="role", required=True)

    server = subparsers.add_parser("server", help="公网服务器：仅交换地址")
    server.add_argument(
        "--bind",
        default="::",
        help="监听地址；默认 ::，在支持的平台上同时接收 IPv6/IPv4",
    )
    server.add_argument("--port", type=int, default=45030)
    server.add_argument("--ttl", type=float, default=ROOM_TTL)
    server.add_argument("--max-rooms", type=int, default=2048)

    for role, help_text in (("host", "Ubuntu 被控端"), ("client", "Windows 控制端")):
        peer = subparsers.add_parser(role, help=help_text)
        peer.add_argument(
            "--server",
            required=True,
            help="会合服务器地址，例如 203.0.113.10:45030 或 [2001:db8::10]:45030",
        )
        peer.add_argument("--room", default="default", help="两端填写相同的房间名")
        peer.add_argument("--secret", default="", help="省略则安全地交互输入")
        peer.add_argument("--port", type=int, default=0, help="本地 UDP 端口，0 为自动")
        peer.add_argument("--timeout", type=float, default=30)
        peer.add_argument("--ipv4-only", action="store_true", help="仅用于诊断")

    args = parser.parse_args()
    try:
        return server_main(args) if args.role == "server" else chat_peer(args)
    except Exception as exc:
        print("[ERROR] {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
