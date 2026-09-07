#!/usr/bin/env bash
set -euo pipefail

RDESK_DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/rdesk-v2"
RDESK_ENV_DIR="$RDESK_DATA_DIR/env"
if [ ! -x "$RDESK_ENV_DIR/bin/python" ]; then
  echo "V2 runtime not found. Run ./install_ubuntu20_v2.sh first." >&2
  exit 1
fi

export PATH="$RDESK_ENV_DIR/bin:$PATH"
export LD_LIBRARY_PATH="$RDESK_ENV_DIR/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export GST_PLUGIN_PATH="$RDESK_ENV_DIR/lib/gstreamer-1.0"
export GST_PLUGIN_SYSTEM_PATH_1_0="$RDESK_ENV_DIR/lib/gstreamer-1.0"
export GI_TYPELIB_PATH="$RDESK_ENV_DIR/lib/girepository-1.0${GI_TYPELIB_PATH:+:$GI_TYPELIB_PATH}"
export GST_REGISTRY_1_0="$RDESK_DATA_DIR/registry.x86_64.bin"

for scanner in \
  "$RDESK_ENV_DIR/libexec/gstreamer-1.0/gst-plugin-scanner" \
  "$RDESK_ENV_DIR/lib/gstreamer-1.0/gst-plugin-scanner"; do
  if [ -x "$scanner" ]; then
    export GST_PLUGIN_SCANNER="$scanner"
    break
  fi
done

# Verify through the exact Python/GI runtime used by the application. This is
# stricter than calling gst-inspect from an unrelated system installation.
GST_PREFLIGHT="import gi; gi.require_version('Gst','1.0'); from gi.repository import Gst; Gst.init(None); required=('webrtcsink','webrtcsrc','webrtcbin','nicesrc','nicesink','dtlssrtpenc','srtpenc','srtpdec','sctpenc','sctpdec','rtpgccbwe','rtprtxsend','rtprtxreceive','rtpulpfecenc','rtpulpfecdec'); missing=[x for x in required if not Gst.ElementFactory.find(x)]; assert not missing, 'missing: '+', '.join(missing)"
if ! "$RDESK_ENV_DIR/bin/python" -c "$GST_PREFLIGHT"; then
  rm -f "$GST_REGISTRY_1_0"
  if ! "$RDESK_ENV_DIR/bin/python" -c "$GST_PREFLIGHT"; then
    echo "V2 WebRTC plugins are unavailable in the isolated Python runtime." >&2
    echo "Run ./install_ubuntu20_v2.sh again, then retry this launcher." >&2
    exit 1
  fi
fi

if [ "${1:-}" = "selftest" ]; then
  shift
  exec "$RDESK_ENV_DIR/bin/python" "$(dirname "$0")/test_rdesk_v2_integration.py" "$@"
fi

exec "$RDESK_ENV_DIR/bin/python" "$(dirname "$0")/rdesk_v2.py" "$@"
