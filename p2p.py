import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import socket
import struct
import threading
import time


# =========================
# 配置
# =========================

STUN_HOST = "stun.l.google.com"
STUN_PORT = 19302

MAGIC_COOKIE = 0x2112A442

running = True

DIAG_MAGIC = "rdesk-p2p-diag-v1"


def diag_session_token(secret, session):
    return hmac.new(
        secret.encode("utf-8"), session.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def diag_packet(secret, session, packet_type, **values):
    packet = {
        "magic": DIAG_MAGIC,
        "session": session,
        "token": diag_session_token(secret, session),
        "type": packet_type,
    }
    packet.update(values)
    return json.dumps(packet, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def parse_diag_packet(data, secret, session):
    packet = json.loads(data.decode("utf-8"))
    if packet.get("magic") != DIAG_MAGIC or packet.get("session") != session:
        raise ValueError("诊断包标识不匹配")
    expected = diag_session_token(secret, session)
    if not hmac.compare_digest(str(packet.get("token", "")), expected):
        raise ValueError("诊断密钥不匹配")
    return packet


def diagnostic_main(server_text, session, name, secret, timeout=24):
    """Use a public rendezvous server to classify each NAT and direction."""
    server_host, server_port = parse_endpoint(server_text)
    server_ip = socket.gethostbyname(server_host)
    primary = (server_ip, server_port)
    secondary = (server_ip, server_port + 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    sock.settimeout(0.5)
    local = sock.getsockname()
    print("=" * 64)
    print("rdesk UDP P2P 双端诊断")
    print(
        "本地 socket：{}:{}；会合服务器：{}:{} / UDP {}".format(
            local[0], local[1], server_ip, server_port, server_port + 1
        )
    )
    print("会话：{}；本端名称：{}".format(session, name))
    print("请让另一端使用相同 --session 和 --secret、不同 --name 同时运行。")
    print("=" * 64)

    state = {
        "running": True,
        "server_ack": False,
        "primary_mapping": None,
        "secondary_mapping": None,
        "peer": None,
        "peer_name": "",
        "punch_at": 0.0,
        "direct_recv": 0,
        "direct_ack": 0,
        "diagnosis": None,
    }
    lock = threading.Lock()

    def send_server(packet_type, **values):
        sock.sendto(
            diag_packet(secret, session, packet_type, name=name, **values), primary
        )

    def report(event, **values):
        try:
            send_server("event", event=event, **values)
        except OSError:
            pass

    def receive_loop():
        while state["running"]:
            try:
                data, address = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                packet = parse_diag_packet(data, secret, session)
            except Exception:
                continue
            packet_type = str(packet.get("type", ""))
            is_server = address[0] == server_ip and address[1] in (
                server_port,
                server_port + 1,
            )
            if is_server:
                if packet_type == "register_ack":
                    endpoint = packet.get("endpoint")
                    with lock:
                        state["server_ack"] = True
                        state["primary_mapping"] = tuple(endpoint) if endpoint else None
                    print("[服务器往返] 成功；主端口观察到：{}".format(endpoint))
                    report("server_ack")
                elif packet_type == "mapping_ack":
                    endpoint = packet.get("endpoint")
                    with lock:
                        state["secondary_mapping"] = tuple(endpoint) if endpoint else None
                    print("[NAT 映射] 次端口观察到：{}".format(endpoint))
                elif packet_type == "peer":
                    endpoint = packet.get("endpoint")
                    if endpoint:
                        with lock:
                            state["peer"] = (str(endpoint[0]), int(endpoint[1]))
                            state["peer_name"] = str(packet.get("peer_name", "peer"))
                            state["punch_at"] = float(packet.get("punch_at", time.time()))
                elif packet_type == "diagnosis":
                    with lock:
                        state["diagnosis"] = packet.get("result")
                continue

            if packet_type == "punch":
                with lock:
                    state["direct_recv"] += 1
                    state["peer"] = address
                    received = state["direct_recv"]
                if received == 1:
                    print(
                        "[P2P] 首次收到 {} 的直连包：{}:{}".format(
                            packet.get("name", "peer"), address[0], address[1]
                        )
                    )
                sock.sendto(diag_packet(secret, session, "direct_ack", name=name), address)
                report("direct_recv", remote=list(address))
            elif packet_type == "direct_ack":
                with lock:
                    state["direct_ack"] += 1
                    received = state["direct_ack"]
                if received == 1:
                    print("[P2P] 首次收到直连 ACK：{}:{}".format(*address))
                report("direct_ack", remote=list(address))

    threading.Thread(target=receive_loop, daemon=True).start()
    started = time.monotonic()
    last_register = 0.0
    last_mapping = 0.0
    punch_started = False
    punch_finished_at = 0.0
    done_sent = False
    try:
        while time.monotonic() - started < timeout:
            now = time.monotonic()
            if not state["server_ack"] and now - last_register >= 0.5:
                send_server("register")
                last_register = now
            if (
                state["server_ack"]
                and state["secondary_mapping"] is None
                and now - last_mapping >= 0.5
            ):
                sock.sendto(
                    diag_packet(secret, session, "mapping_probe", name=name), secondary
                )
                last_mapping = now
            peer = state["peer"]
            if peer and not punch_started and time.time() >= state["punch_at"]:
                punch_started = True
                punch_finished_at = now + 12.0
                print(
                    "[P2P] 同步向 {} {}:{} 发包 12 秒…".format(
                        state["peer_name"], peer[0], peer[1]
                    )
                )
            if punch_started and now < punch_finished_at:
                sock.sendto(
                    diag_packet(secret, session, "punch", name=name, sent_at=time.time()),
                    state["peer"],
                )
                time.sleep(0.1)
                continue
            if punch_started and now >= punch_finished_at and not done_sent:
                send_server(
                    "done",
                    direct_recv=state["direct_recv"],
                    direct_ack=state["direct_ack"],
                )
                done_sent = True
            if state["diagnosis"] is not None:
                break
            time.sleep(0.05)
    finally:
        state["running"] = False
        sock.close()

    print()
    primary_mapping = state["primary_mapping"]
    secondary_mapping = state["secondary_mapping"]
    if not state["server_ack"]:
        print("[结论] 本端未收到服务器 UDP 回复：检查云安全组、本机防火墙或出口 UDP。")
        return 2
    if primary_mapping and secondary_mapping:
        if primary_mapping == secondary_mapping:
            print("[本端 NAT] 映射稳定：两个服务器端口看到相同公网 IP:端口。")
        else:
            print("[本端 NAT] 映射随目标变化：疑似对称/硬 NAT，打洞成功率低。")
    result = state["diagnosis"]
    if result:
        print("[服务器综合诊断]")
        for line in result.get("summary", []):
            print("- " + str(line))
        print(json.dumps(result.get("peers", {}), ensure_ascii=False, indent=2))
        return 0 if result.get("success") else 1
    print("[结论] 另一端未及时加入，或诊断结果未返回。")
    return 3


# =========================
# STUN
# =========================

def create_stun_request():
    """
    创建最基本的 STUN Binding Request

    STUN Header:
        2 bytes Message Type
        2 bytes Message Length
        4 bytes Magic Cookie
        12 bytes Transaction ID
    """

    message_type = 0x0001      # Binding Request
    message_length = 0
    transaction_id = os.urandom(12)

    packet = struct.pack(
        "!HHI12s",
        message_type,
        message_length,
        MAGIC_COOKIE,
        transaction_id
    )

    return packet, transaction_id


def parse_stun_response(data, transaction_id):
    if len(data) < 20:
        raise ValueError("STUN response 太短")

    message_type, message_length, magic_cookie = struct.unpack(
        "!HHI", data[:8]
    )

    received_transaction_id = data[8:20]

    if magic_cookie != MAGIC_COOKIE:
        raise ValueError("不是有效的 STUN 消息")

    if received_transaction_id != transaction_id:
        raise ValueError("STUN transaction ID 不匹配")

    offset = 20
    end = min(len(data), 20 + message_length)

    while offset + 4 <= end:

        attr_type, attr_length = struct.unpack(
            "!HH", data[offset:offset + 4]
        )

        offset += 4

        value = data[offset:offset + attr_length]

        # XOR-MAPPED-ADDRESS
        if attr_type == 0x0020 and len(value) >= 8:

            family = value[1]

            xport = struct.unpack(
                "!H",
                value[2:4]
            )[0]

            port = xport ^ (MAGIC_COOKIE >> 16)

            # IPv4
            if family == 0x01:

                xip = struct.unpack(
                    "!I",
                    value[4:8]
                )[0]

                ip_int = xip ^ MAGIC_COOKIE

                ip = socket.inet_ntoa(
                    struct.pack("!I", ip_int)
                )

                return ip, port

            # IPv6 XOR address uses the cookie followed by transaction ID.
            if family == 0x02 and len(value) >= 20:
                mask = struct.pack("!I", MAGIC_COOKIE) + transaction_id
                raw = bytes(left ^ right for left, right in zip(value[4:20], mask))
                return socket.inet_ntop(socket.AF_INET6, raw), port

        # 老式 MAPPED-ADDRESS，作为 fallback
        if attr_type == 0x0001 and len(value) >= 8:

            family = value[1]

            port = struct.unpack(
                "!H",
                value[2:4]
            )[0]

            if family == 0x01:

                ip = socket.inet_ntoa(
                    value[4:8]
                )

                return ip, port

            if family == 0x02 and len(value) >= 20:
                return socket.inet_ntop(socket.AF_INET6, value[4:20]), port

        # STUN attribute 四字节对齐
        offset += (attr_length + 3) & ~3

    raise ValueError(
        "STUN response 中没有找到公网地址"
    )


def get_public_endpoint(sock):

    print()
    family_text = "IPv6" if sock.family == socket.AF_INET6 else "IPv4"
    print("[STUN] 正在查询 {} 公网地址...".format(family_text))

    targets = socket.getaddrinfo(
        STUN_HOST, STUN_PORT, sock.family, socket.SOCK_DGRAM
    )
    if not targets:
        raise OSError("STUN 没有 {} 地址".format(family_text))
    stun_address = targets[0][4]

    request, transaction_id = create_stun_request()

    sock.sendto(
        request,
        stun_address
    )

    old_timeout = sock.gettimeout()

    sock.settimeout(5)

    try:

        while True:

            data, addr = sock.recvfrom(2048)

            try:

                result = parse_stun_response(
                    data,
                    transaction_id
                )

                return result

            except ValueError:
                continue

    finally:
        sock.settimeout(old_timeout)


# =========================
# P2P 接收
# =========================

def receiver(sock, peer_holder):

    global running

    sock.settimeout(1)

    while running:

        try:

            data, addr = sock.recvfrom(65535)

        except socket.timeout:
            continue

        except OSError:
            break

        # 第一次真正收到对方数据
        if peer_holder["addr"] is None:
            peer_holder["addr"] = addr

        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            print(
                f"\n[收到二进制数据] "
                f"{len(data)} bytes from {addr}"
            )
            continue

        # 打洞包不显示
        if text.startswith("__PUNCH__"):
            peer_holder["addr"] = addr

            sock.sendto(
                b"__PUNCH_ACK__",
                addr
            )

            continue

        if text == "__PUNCH_ACK__":

            peer_holder["addr"] = addr

            print(
                f"\n[P2P] 已收到对方响应："
                f"{addr[0]}:{addr[1]}"
            )

            print("> ", end="", flush=True)

            continue

        if text == "__KEEPALIVE__":
            continue

        print(
            f"\nPeer {addr[0]}:{addr[1]} > {text}"
        )

        print("> ", end="", flush=True)


# =========================
# UDP Hole Punching
# =========================

def punch(sock, peer_addr):

    print()
    print(
        f"[P2P] 开始向 "
        f"{peer_addr[0]}:{peer_addr[1]} "
        f"UDP 打洞..."
    )

    # 多发几次是故意的
    # 两边都向对方发送数据，
    # NAT 才可能建立对应映射。

    for i in range(30):

        message = (
            f"__PUNCH__:{i}"
        ).encode()

        try:
            sock.sendto(
                message,
                peer_addr
            )

        except OSError as e:
            print(
                "[P2P] sendto error:",
                e
            )

        time.sleep(0.2)

    print("[P2P] 打洞包发送完成")


# =========================
# NAT Keepalive
# =========================

def keepalive(sock, peer_holder):

    global running

    while running:

        time.sleep(10)

        peer = peer_holder["addr"]

        if peer is None:
            continue

        try:

            sock.sendto(
                b"__KEEPALIVE__",
                peer
            )

        except OSError:
            break


# =========================
# 地址解析
# =========================

def parse_endpoint(text):
    text = text.strip()
    if text.startswith("["):
        closing = text.find("]")
        if closing < 0 or not text[closing + 1:].startswith(":"):
            raise ValueError("IPv6 格式应为 [IPv6]:PORT")
        host, port_text = text[1:closing], text[closing + 2:]
    elif text.count(":") == 1:
        host, port_text = text.rsplit(":", 1)
    else:
        raise ValueError("格式应为 IPv4:PORT 或 [IPv6]:PORT")
    port = int(port_text)
    if not host or not 1 <= port <= 65535:
        raise ValueError("IP 或端口无效")
    ipaddress.ip_address(host.split("%", 1)[0])
    return host, port


def endpoint_family(endpoint):
    address = ipaddress.ip_address(str(endpoint[0]).split("%", 1)[0])
    return socket.AF_INET6 if address.version == 6 else socket.AF_INET


def format_endpoint(endpoint):
    host, port = str(endpoint[0]), int(endpoint[1])
    return "[{}]:{}".format(host, port) if ":" in host else "{}:{}".format(host, port)


def format_candidates(candidates):
    parts = []
    if socket.AF_INET6 in candidates:
        parts.append("ipv6=" + format_endpoint(candidates[socket.AF_INET6]))
    if socket.AF_INET in candidates:
        parts.append("ipv4=" + format_endpoint(candidates[socket.AF_INET]))
    return ";".join(parts)


def parse_candidates(text):
    """Parse a copy/paste dual-stack candidate string or one legacy endpoint."""
    result = {}
    for item in text.strip().split(";"):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            label, endpoint_text = item.split("=", 1)
            label = label.strip().lower()
        else:
            label, endpoint_text = "", item
        endpoint = parse_endpoint(endpoint_text.strip())
        family = endpoint_family(endpoint)
        if label in ("ipv4", "v4") and family != socket.AF_INET:
            raise ValueError("ipv4 标签后不是 IPv4 地址")
        if label in ("ipv6", "v6") and family != socket.AF_INET6:
            raise ValueError("ipv6 标签后不是 IPv6 地址")
        result[family] = endpoint
    if not result:
        raise ValueError("没有找到有效候选地址")
    return result


def _routed_address(family):
    target = (
        ("2001:4860:4860::8888", 53, 0, 0)
        if family == socket.AF_INET6
        else ("8.8.8.8", 53)
    )
    probe = socket.socket(family, socket.SOCK_DGRAM)
    try:
        probe.connect(target)
        return str(probe.getsockname()[0])
    finally:
        probe.close()


def discover_manual_candidates(bind_port=0):
    """Open one socket per family and publish every usable direct candidate."""
    bind_port = int(bind_port)
    if not 0 <= bind_port <= 65535:
        raise ValueError("绑定端口必须是 0-65535")
    sockets = {}
    candidates = {}
    notes = {}
    workers = []
    result_lock = threading.Lock()

    def discover(family, wildcard, label):
        sock = None
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((wildcard, bind_port))
            local_port = int(sock.getsockname()[1])
            try:
                endpoint = get_public_endpoint(sock)
                source = "STUN"
            except Exception as exc:
                # Global IPv6 normally needs no NAT mapping. A routed address
                # remains a valid ICE-style host candidate when IPv6 STUN is
                # unavailable. IPv4 fallback is useful on the same LAN.
                endpoint = (_routed_address(family), local_port)
                source = "本机路由（STUN 失败：{}）".format(exc)
            address = ipaddress.ip_address(str(endpoint[0]).split("%", 1)[0])
            if family == socket.AF_INET6 and not address.is_global:
                raise OSError("没有全局 IPv6 地址（发现 {}）".format(address))
            with result_lock:
                sockets[family] = sock
                candidates[family] = (str(endpoint[0]), int(endpoint[1]))
                notes[family] = "{} {} {}".format(
                    label, format_endpoint(endpoint), source
                )
            sock = None
        except Exception as exc:
            with result_lock:
                notes[family] = "{} 不可用：{}".format(label, exc)
        finally:
            if sock is not None:
                sock.close()

    for family, wildcard, label in (
        (socket.AF_INET6, "::", "IPv6"),
        (socket.AF_INET, "0.0.0.0", "IPv4"),
    ):
        worker = threading.Thread(
            target=discover,
            args=(family, wildcard, label),
            name="p2p-discover-{}".format(label),
            daemon=True,
        )
        workers.append(worker)
        worker.start()
    for worker in workers:
        worker.join(timeout=7)
    if not sockets:
        raise OSError("IPv4 和 IPv6 都不可用")
    ordered_notes = [
        notes[family]
        for family in (socket.AF_INET6, socket.AF_INET)
        if family in notes
    ]
    return sockets, candidates, ordered_notes


def _select_path(state, family, sock, address, reason):
    normalized = (str(address[0]), int(address[1]))
    with state["lock"]:
        state["peer_by_family"][family] = normalized
        if state["selected"] is not None:
            return False
        state["selected"] = (family, sock, normalized)
    label = "IPv6" if family == socket.AF_INET6 else "IPv4"
    print("\n[P2P] {} 路径已建立：{}（{}）".format(label, format_endpoint(normalized), reason))
    print("> ", end="", flush=True)
    return True


def hybrid_receiver(sock, family, state):
    global running
    sock.settimeout(1)
    while running:
        try:
            data, raw_address = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            return
        address = (raw_address[0], raw_address[1])
        if data.startswith(b"__PUNCH__"):
            sock.sendto(b"__PUNCH_ACK__", raw_address)
            _select_path(state, family, sock, address, "收到打洞包")
            continue
        if data == b"__PUNCH_ACK__":
            _select_path(state, family, sock, address, "收到双向 ACK")
            continue
        if data == b"__KEEPALIVE__":
            continue
        _select_path(state, family, sock, address, "收到应用数据")
        try:
            text = data.decode("utf-8")
            print("\nPeer {} > {}".format(format_endpoint(address), text))
        except UnicodeDecodeError:
            print("\n[收到二进制数据] {} bytes from {}".format(len(data), format_endpoint(address)))
        print("> ", end="", flush=True)


def hybrid_punch(sock, family, endpoint):
    label = "IPv6" if family == socket.AF_INET6 else "IPv4"
    print("[P2P] {} 并行尝试 {}".format(label, format_endpoint(endpoint)))
    for index in range(50):
        if not running:
            return
        try:
            sock.sendto("__PUNCH__:{}:{}".format(label, index).encode(), endpoint)
        except OSError as exc:
            if index == 0:
                print("[P2P] {} 发送失败：{}".format(label, exc))
        time.sleep(0.15)


def hybrid_keepalive(state):
    while running:
        time.sleep(10)
        with state["lock"]:
            selected = state["selected"]
        if selected is None:
            continue
        _family, sock, endpoint = selected
        try:
            sock.sendto(b"__KEEPALIVE__", endpoint)
        except OSError:
            return


# =========================
# Main
# =========================

def legacy_manual_main():

    global running

    print("=" * 55)
    print("       Python UDP P2P / NAT Hole Punch Demo")
    print("=" * 55)

    # 创建 UDP socket
    #
    # 很重要：
    # STUN 和后面的 P2P 必须继续使用
    # 同一个 UDP socket。
    #
    # 不要查完公网端口后重新创建 socket。

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    # 让操作系统选择一个本地 UDP 端口
    sock.bind(
        ("0.0.0.0", 0)
    )

    local_ip, local_port = sock.getsockname()

    print()
    print(
        f"[LOCAL] UDP socket:"
        f" {local_ip}:{local_port}"
    )

    # 查询 NAT 公网映射

    try:

        public_ip, public_port = \
            get_public_endpoint(sock)

    except Exception as e:

        print()
        print("[ERROR] STUN 查询失败：")
        print(e)

        sock.close()

        return

    print()
    print("=" * 55)

    print(
        "你的公网 UDP Endpoint："
    )

    print()
    print(
        f"    {public_ip}:{public_port}"
    )

    print()
    print("=" * 55)

    print()
    print(
        "把上面的 IP:端口 发给另一台机器。"
    )

    print(
        "同时让另一台机器把它显示的地址发给你。"
    )

    print()

    while True:

        peer_text = input(
            "请输入对方公网 IP:端口："
        )

        try:

            peer_addr = parse_endpoint(
                peer_text
            )

            break

        except Exception as e:

            print(
                "输入错误：",
                e
            )

    peer_holder = {
        "addr": peer_addr
    }

    # 接收线程

    recv_thread = threading.Thread(
        target=receiver,
        args=(
            sock,
            peer_holder
        ),
        daemon=True
    )

    recv_thread.start()

    # 开始 UDP hole punching

    punch_thread = threading.Thread(
        target=punch,
        args=(
            sock,
            peer_addr
        ),
        daemon=True
    )

    punch_thread.start()

    # Keepalive

    keepalive_thread = threading.Thread(
        target=keepalive,
        args=(
            sock,
            peer_holder
        ),
        daemon=True
    )

    keepalive_thread.start()

    print()
    print(
        "另一台机器也输入你的公网地址后，"
        "双方会同时尝试 UDP 打洞。"
    )

    print()
    print(
        "成功后可以直接输入消息。"
    )

    print(
        "输入 /quit 退出。"
    )

    print()

    # 聊天

    try:

        while True:

            message = input("> ")

            if message == "/quit":
                break

            peer = peer_holder["addr"]

            if peer is None:

                print(
                    "目前还没有可用 Peer"
                )

                continue

            sock.sendto(
                message.encode("utf-8"),
                peer
            )

    except KeyboardInterrupt:
        pass

    finally:

        running = False

        sock.close()

        print()
        print("Bye.")


def manual_main():
    """Run a serverless IPv6 + IPv4 race using copy/paste candidates."""
    global running
    running = True
    print("=" * 64)
    print("       rdesk IPv6 + IPv4 双栈 UDP P2P 测试")
    print("=" * 64)
    sockets = {}
    try:
        sockets, local_candidates, notes = discover_manual_candidates()
        print("\n本机候选：")
        for note in notes:
            print("- " + note)
        local_text = format_candidates(local_candidates)
        print("\n请把下面整行复制给对方：\n")
        print(local_text)
        print("\n双方都取得候选串后再继续，地址顺序不影响并行竞速。")

        while True:
            try:
                peer_candidates = parse_candidates(input("\n请输入对方候选串："))
                break
            except Exception as exc:
                print("输入错误：{}".format(exc))

        families = [
            family
            for family in (socket.AF_INET6, socket.AF_INET)
            if family in sockets and family in peer_candidates
        ]
        if not families:
            raise RuntimeError("双方没有共同地址族，无法直接 P2P")

        state = {
            "lock": threading.Lock(),
            "selected": None,
            "peer_by_family": {},
        }
        for family in families:
            threading.Thread(
                target=hybrid_receiver,
                args=(sockets[family], family, state),
                daemon=True,
            ).start()
            threading.Thread(
                target=hybrid_punch,
                args=(sockets[family], family, peer_candidates[family]),
                daemon=True,
            ).start()
        threading.Thread(target=hybrid_keepalive, args=(state,), daemon=True).start()

        attempted = ", ".join(
            "IPv6" if family == socket.AF_INET6 else "IPv4" for family in families
        )
        print("\n正在并行尝试 {}。成功后可输入消息，/status 查看路径，/quit 退出。".format(attempted))
        while True:
            message = input("> ")
            if message == "/quit":
                break
            if message == "/status":
                with state["lock"]:
                    selected = state["selected"]
                if selected is None:
                    print("尚未建立 P2P 路径")
                else:
                    family, _sock, endpoint = selected
                    label = "IPv6" if family == socket.AF_INET6 else "IPv4"
                    print("当前路径：{} {}".format(label, format_endpoint(endpoint)))
                continue
            with state["lock"]:
                selected = state["selected"]
            if selected is not None:
                _family, sock, endpoint = selected
                sock.sendto(message.encode("utf-8"), endpoint)
            else:
                # Before nomination, send the user payload on every candidate;
                # the first receiver will nominate that family immediately.
                for family in families:
                    try:
                        sockets[family].sendto(
                            message.encode("utf-8"), peer_candidates[family]
                        )
                    except OSError:
                        pass
                print("路径尚未确认，消息已同时发往所有候选")
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print("\n[ERROR] {}".format(exc))
        return 1
    finally:
        running = False
        for sock in sockets.values():
            try:
                sock.close()
            except OSError:
                pass
        print("\nBye.")


def main():
    parser = argparse.ArgumentParser(description="UDP P2P 打洞与双端诊断")
    parser.add_argument(
        "--server", help="诊断服务器 IP:主UDP端口，例如 203.0.113.10:45010"
    )
    parser.add_argument("--session", default="")
    parser.add_argument("--name", default=socket.gethostname())
    parser.add_argument("--secret", default="")
    parser.add_argument("--timeout", type=int, default=24)
    args = parser.parse_args()
    if args.server:
        if not args.session or not args.secret:
            parser.error("使用 --server 时必须同时提供 --session 和 --secret")
        return diagnostic_main(
            args.server, args.session, args.name, args.secret, args.timeout
        )
    return manual_main()


if __name__ == "__main__":
    raise SystemExit(main() or 0)
