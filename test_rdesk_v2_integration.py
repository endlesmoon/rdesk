"""Opt-in local WebRTC smoke test: real capture, auth proxy and decode."""

import sys
import re
import secrets
import threading
import time

from rdesk_v2_platform import load_gstreamer
from rdesk_v2 import _select_video_backend
from rdesk_v2_core import (
    AuthWebSocketProxy,
    ClientSettings,
    HostSettings,
    build_client_pipeline,
    build_host_pipeline,
    host_raw_video_caps,
)


def main() -> int:
    Gst = load_gstreamer()
    import gi

    gi.require_version("GstWebRTC", "1.0")
    from gi.repository import GstWebRTC  # noqa: F401
    password = secrets.token_urlsafe(24)
    host_settings = HostSettings(
        bind_host="127.0.0.1",
        signal_port=45110,
        control_port=45111,
        internal_signal_port=45112,
        width=640,
        height=360,
        fps=10,
        password=password,
    )
    client_settings = ClientSettings(
        peer="127.0.0.1",
        signal_port=45110,
        control_port=45111,
        password=password,
    )
    backend, backend_text = _select_video_backend(
        Gst, windows=sys.platform.startswith("win"), preference="auto"
    )
    print("self-test video backend: {} ({})".format(backend, backend_text))
    host = Gst.parse_launch(
        build_host_pipeline(
            host_settings,
            windows=sys.platform.startswith("win"),
            video_backend=backend,
        )
    )
    client_text = build_client_pipeline(
        client_settings, windows=sys.platform.startswith("win")
    )
    client_text, replacements = re.subn(
        r"identity name=video_probe signal-handoffs=true silent=true ! "
        r"(?:d3d11videosink|ximagesink) name=video_sink.*$",
        "fakesink name=video_sink sync=false signal-handoffs=true",
        client_text,
    )
    if replacements != 1:
        raise RuntimeError("failed to replace platform video sink for self-test")
    client = Gst.parse_launch(client_text)
    sink = client.get_by_name("video_sink")
    frames = 0
    frame_sizes = set()
    frame_ready = threading.Event()
    pointer_ready = threading.Event()
    dynamic_factories = set()
    channel_refs = []

    def pointer_message(_channel, text):
        if text == '{"type":"pointer","x":123,"y":456}':
            pointer_ready.set()

    def consumer_added(_web, _consumer_id, webrtcbin):
        options = Gst.Structure.new_empty("config")
        options.set_value("ordered", False)
        options.set_value("max-retransmits", 0)
        channel = webrtcbin.emit(
            "create-data-channel", "rdesk-pointer-v1", options
        )
        if channel is None:
            raise RuntimeError("failed to create pointer DataChannel")
        if channel.get_property("ordered") or channel.get_property("max-retransmits") != 0:
            raise RuntimeError("pointer DataChannel is not unordered/unreliable")
        channel.connect("on-message-string", pointer_message)
        channel_refs.append(channel)

    host.get_by_name("web").connect("consumer-added", consumer_added)

    def data_channel_added(_webrtcbin, channel):
        if channel.get_property("label") != "rdesk-pointer-v1":
            return
        channel_refs.append(channel)

        def opened(open_channel):
            open_channel.send_string_full('{"type":"pointer","x":123,"y":456}')

        channel.connect("on-open", opened)

    def element_added(_pipeline, _owner, element):
        factory = element.get_factory()
        if factory is not None:
            dynamic_factories.add(factory.get_name())
            if factory.get_name() == "webrtcbin":
                element.connect("on-data-channel", data_channel_added)

    client.connect("deep-element-added", element_added)

    def handoff(_sink, _buffer, _pad):
        nonlocal frames
        frames += 1
        try:
            caps = _pad.get_current_caps()
            structure = caps.get_structure(0)
            frame_sizes.add(
                (int(structure.get_value("width")), int(structure.get_value("height")))
            )
        except Exception:
            pass
        if frames >= 3:
            frame_ready.set()

    sink.connect("handoff", handoff)
    proxy = AuthWebSocketProxy(
        ("127.0.0.1", 45110), ("127.0.0.1", 45112), password
    )
    try:
        if host.set_state(Gst.State.PLAYING) == Gst.StateChangeReturn.FAILURE:
            raise RuntimeError("host pipeline failed")
        proxy.start()
        # Let the embedded signalling server bind before the authenticated
        # client reaches it through the proxy.
        # Encoder discovery (especially x264 in a busy VM) can take longer
        # than the signalling server bind. webrtcsrc only lists producers at
        # startup, so do not race it ahead of producer registration.
        time.sleep(4.0)
        if client.set_state(Gst.State.PLAYING) == Gst.StateChangeReturn.FAILURE:
            raise RuntimeError("client pipeline failed")
        deadline = time.monotonic() + 25
        while not frame_ready.wait(0.1):
            for name, pipeline in (("host", host), ("client", client)):
                message = pipeline.get_bus().pop_filtered(Gst.MessageType.ERROR)
                if message is not None:
                    error, debug = message.parse_error()
                    raise RuntimeError("{}: {} ({})".format(name, error, debug or ""))
            if time.monotonic() >= deadline:
                raise TimeoutError("no decoded WebRTC frames within 25 seconds")
        if "rtph264depay" not in dynamic_factories:
            raise RuntimeError("client did not expose the dynamic H.264 depayloader")
        configured_decoder = client.get_by_name("client_decoder")
        configured_decoder_factory = (
            configured_decoder.get_factory().get_name()
            if configured_decoder is not None and configured_decoder.get_factory() is not None
            else ""
        )
        if configured_decoder_factory not in ("avdec_h264", "openh264dec") and not any(
            name.endswith("h264dec") or name in ("avdec_h264", "openh264dec")
            for name in dynamic_factories
        ):
            raise RuntimeError("client did not expose the dynamic H.264 decoder")
        if not pointer_ready.wait(5):
            raise RuntimeError("unordered/unreliable pointer DataChannel did not pass data")
        import gi

        gi.require_version("GstVideo", "1.0")
        from gi.repository import GstVideo

        caps_filter = host.get_by_name("host_caps")
        caps_filter.set_property(
            "caps", Gst.Caps.from_string(host_raw_video_caps(backend, 320, 240, 10))
        )
        encoder = host.get_by_name("host_encoder")
        if encoder is not None:
            encoder.get_static_pad("src").send_event(
                GstVideo.video_event_new_upstream_force_key_unit(
                    Gst.CLOCK_TIME_NONE, True, 1
                )
            )
        deadline = time.monotonic() + 5
        while (320, 240) not in frame_sizes and time.monotonic() < deadline:
            time.sleep(0.05)
        if (320, 240) not in frame_sizes:
            raise RuntimeError("live resolution switch did not reach the decoder")
        print(
            "WebRTC smoke test OK: decoded {} frames, live caps {}".format(
                frames, sorted(frame_sizes)
            )
        )
        return 0
    finally:
        client.set_state(Gst.State.NULL)
        proxy.close()
        host.set_state(Gst.State.NULL)


if __name__ == "__main__":
    raise SystemExit(main())
