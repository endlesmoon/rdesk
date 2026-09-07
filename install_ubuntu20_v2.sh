#!/usr/bin/env bash
set -euo pipefail

# Installs an isolated GStreamer 1.28 runtime for Ubuntu 20.04. The operating
# system's GStreamer 1.16 installation is intentionally left untouched.

RDESK_DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/rdesk-v2"
RDESK_ENV_DIR="$RDESK_DATA_DIR/env"
RDESK_BUILD_DIR="$RDESK_DATA_DIR/build"
MICROMAMBA="$RDESK_DATA_DIR/bin/micromamba"
# Keep every GStreamer library/plugin on one published release. conda-forge
# currently has the complete 1.28.5 family for Ubuntu x86_64.
GST_RUNTIME_VERSION="${RDESK_GST_VERSION:-1.28.5}"
LIBNICE_VERSION="${RDESK_LIBNICE_VERSION:-0.1.23}"
USRSCTP_VERSION="${RDESK_USRSCTP_VERSION:-0.9.5.0}"

sudo apt-get update
sudo apt-get install -y \
  build-essential curl bzip2 git pkg-config ca-certificates \
  fonts-noto-cjk \
  libx11-dev libxext-dev libxfixes-dev libxdamage-dev libxtst-dev \
  libsrtp2-dev libssl-dev

mkdir -p "$RDESK_DATA_DIR/bin" "$RDESK_BUILD_DIR"
if [ ! -x "$MICROMAMBA" ]; then
  temp_archive="$(mktemp)"
  curl -L "https://micro.mamba.pm/api/micromamba/linux-64/latest" -o "$temp_archive"
  tar -xjf "$temp_archive" -C "$RDESK_DATA_DIR/bin" --strip-components=1 bin/micromamba
  rm -f "$temp_archive"
fi

# The conda-forge Linux gst-plugins-bad package omits libnice/WebRTC support.
# Base media packages still come from conda; the missing Linux pieces are
# added from Ubuntu/build sources below.
create_ok=0
micromamba_action="create"
if [ -d "$RDESK_ENV_DIR/conda-meta" ]; then
  micromamba_action="install"
fi
for attempt in 1 2 3; do
  if MAMBA_DOWNLOAD_TIMEOUT_SECONDS=120 "$MICROMAMBA" "$micromamba_action" -y \
    -p "$RDESK_ENV_DIR" -c conda-forge \
    python=3.10 pip tk pygobject cryptography pynput \
    "gstreamer=$GST_RUNTIME_VERSION" \
    "gst-plugins-base=$GST_RUNTIME_VERSION" \
    "gst-plugins-good=$GST_RUNTIME_VERSION" \
    "gst-plugins-bad=$GST_RUNTIME_VERSION" \
    "gst-plugins-ugly=$GST_RUNTIME_VERSION" \
    "gst-libav=$GST_RUNTIME_VERSION" \
    x264 pkg-config zlib meson ninja; then
    create_ok=1
    break
  fi
  echo "Conda download attempt $attempt failed; retrying in 5 seconds..." >&2
  sleep 5
done
if [ "$create_ok" -ne 1 ]; then
  echo "Unable to create the GStreamer runtime after 3 attempts." >&2
  exit 1
fi

if [ ! -x "$HOME/.cargo/bin/rustup" ]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain none --profile minimal
fi

# cargo may exist as a rustup proxy while no default toolchain is configured.
# Always make the desired toolchain explicit so rerunning this script repairs
# that partially installed state.
"$HOME/.cargo/bin/rustup" toolchain install stable --profile minimal
"$HOME/.cargo/bin/rustup" default stable

export PATH="$RDESK_ENV_DIR/bin:$HOME/.cargo/bin:$PATH"
export CONDA_PREFIX="$RDESK_ENV_DIR"
export CONDA_DEFAULT_ENV="$RDESK_ENV_DIR"
DEB_MULTIARCH="$(dpkg-architecture -qDEB_HOST_MULTIARCH)"
export PKG_CONFIG_PATH="$RDESK_ENV_DIR/lib/pkgconfig:$RDESK_ENV_DIR/share/pkgconfig:/usr/lib/$DEB_MULTIARCH/pkgconfig:/usr/lib/pkgconfig:/usr/share/pkgconfig"
export LD_LIBRARY_PATH="$RDESK_ENV_DIR/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# gio-2.0.pc has a private build-time dependency on zlib. The smaller
# libzlib runtime package contains libz.so but not zlib.pc, so install the
# zlib development output above and fail here instead of halfway through the
# Rust build. Setting CONDA_PREFIX also keeps conda-forge's pkg-config wrapper
# usable when this script is run without an interactive `micromamba activate`.
for pc_module in zlib gio-2.0 gstreamer-1.0 gstreamer-webrtc-1.0 openssl; do
  if ! "$RDESK_ENV_DIR/bin/pkg-config" --exists "$pc_module"; then
    echo "Missing pkg-config module in V2 runtime: $pc_module" >&2
    echo "Re-run this installer; do not invoke cargo directly." >&2
    exit 1
  fi
done

PLUGIN_SOURCE="$RDESK_BUILD_DIR/gst-plugins-rs"
GST_VERSION="$("$RDESK_ENV_DIR/bin/gst-inspect-1.0" --version | awk '/GStreamer/{print $2; exit}')"
GST_PLUGIN_TAG="gstreamer-$GST_VERSION"

# conda-forge's Linux gst-plugins-bad build intentionally has no libnice
# dependency, so it omits webrtcbin. Build only the missing WebRTC/DTLS/SRTP
# plug-ins against the isolated GStreamer runtime. Ubuntu 20.04 only provides
# libnice 0.1.16, while GStreamer 1.28 requires >= 0.1.23. Build the matching
# libnice release (including nicesrc/nicesink) inside the same isolated prefix;
# never copy the system plug-in because that mixes GStreamer 1.16 and 1.28.
LIBNICE_ARCHIVE="$RDESK_BUILD_DIR/libnice-$LIBNICE_VERSION.tar.gz"
LIBNICE_SOURCE="$RDESK_BUILD_DIR/libnice-$LIBNICE_VERSION"
LIBNICE_BUILD="$RDESK_BUILD_DIR/libnice-$LIBNICE_VERSION-build"
if [ ! -f "$LIBNICE_SOURCE/meson.build" ]; then
  echo "Downloading libnice $LIBNICE_VERSION..."
  curl --fail --location --retry 3 \
    "https://libnice.freedesktop.org/releases/libnice-$LIBNICE_VERSION.tar.gz" \
    --output "$LIBNICE_ARCHIVE"
  tar -xzf "$LIBNICE_ARCHIVE" -C "$RDESK_BUILD_DIR"
fi

libnice_setup=(
  --prefix "$RDESK_ENV_DIR" --libdir lib --buildtype release
  -Dauto_features=disabled -Dgstreamer=enabled -Dcrypto-library=openssl
)
if [ -f "$LIBNICE_BUILD/meson-private/coredata.dat" ]; then
  "$RDESK_ENV_DIR/bin/meson" setup --reconfigure --clearcache \
    "$LIBNICE_BUILD" "$LIBNICE_SOURCE" "${libnice_setup[@]}"
else
  "$RDESK_ENV_DIR/bin/meson" setup \
    "$LIBNICE_BUILD" "$LIBNICE_SOURCE" "${libnice_setup[@]}"
fi
"$RDESK_ENV_DIR/bin/meson" compile -C "$LIBNICE_BUILD"
"$RDESK_ENV_DIR/bin/meson" install -C "$LIBNICE_BUILD"

if ! "$RDESK_ENV_DIR/bin/pkg-config" \
  --atleast-version="$LIBNICE_VERSION" nice; then
  found_nice="$("$RDESK_ENV_DIR/bin/pkg-config" --modversion nice 2>/dev/null || echo missing)"
  echo "libnice installation failed: need >= $LIBNICE_VERSION, found $found_nice" >&2
  exit 1
fi

# gst-plugins-bad 1.28 makes SCTP mandatory whenever WebRTC is enabled.
# Ubuntu 20.04's package is older, so build the upstream 0.9.5.0 release into
# the same prefix and expose its usrsctp.pc to the following Meson configure.
USRSCTP_ARCHIVE="$RDESK_BUILD_DIR/usrsctp-$USRSCTP_VERSION.tar.gz"
USRSCTP_SOURCE="$RDESK_BUILD_DIR/usrsctp-$USRSCTP_VERSION"
USRSCTP_BUILD="$RDESK_BUILD_DIR/usrsctp-$USRSCTP_VERSION-build"
if [ ! -f "$USRSCTP_SOURCE/meson.build" ]; then
  echo "Downloading usrsctp $USRSCTP_VERSION..."
  curl --fail --location --retry 3 \
    "https://github.com/sctplab/usrsctp/archive/refs/tags/$USRSCTP_VERSION.tar.gz" \
    --output "$USRSCTP_ARCHIVE"
  tar -xzf "$USRSCTP_ARCHIVE" -C "$RDESK_BUILD_DIR"
fi

usrsctp_setup=(
  --prefix "$RDESK_ENV_DIR" --libdir lib --buildtype release
  --default-library shared -Dsctp_build_programs=false -Dsctp_debug=false
)
if [ -f "$USRSCTP_BUILD/meson-private/coredata.dat" ]; then
  "$RDESK_ENV_DIR/bin/meson" setup --reconfigure --clearcache \
    "$USRSCTP_BUILD" "$USRSCTP_SOURCE" "${usrsctp_setup[@]}"
else
  "$RDESK_ENV_DIR/bin/meson" setup \
    "$USRSCTP_BUILD" "$USRSCTP_SOURCE" "${usrsctp_setup[@]}"
fi
"$RDESK_ENV_DIR/bin/meson" compile -C "$USRSCTP_BUILD"
"$RDESK_ENV_DIR/bin/meson" install -C "$USRSCTP_BUILD"

if ! "$RDESK_ENV_DIR/bin/pkg-config" \
  --atleast-version="$USRSCTP_VERSION" usrsctp; then
  found_usrsctp="$("$RDESK_ENV_DIR/bin/pkg-config" --modversion usrsctp 2>/dev/null || echo missing)"
  echo "usrsctp installation failed: need >= $USRSCTP_VERSION, found $found_usrsctp" >&2
  exit 1
fi

GST_BAD_ARCHIVE="$RDESK_BUILD_DIR/gst-plugins-bad-$GST_VERSION.tar.xz"
GST_BAD_SOURCE="$RDESK_BUILD_DIR/gst-plugins-bad-$GST_VERSION"
GST_BAD_BUILD="$RDESK_BUILD_DIR/gst-plugins-bad-$GST_VERSION-build"
if [ ! -f "$GST_BAD_SOURCE/meson.build" ]; then
  curl --fail --location --retry 3 \
    "https://gstreamer.freedesktop.org/src/gst-plugins-bad/gst-plugins-bad-$GST_VERSION.tar.xz" \
    --output "$GST_BAD_ARCHIVE"
  tar -xf "$GST_BAD_ARCHIVE" -C "$RDESK_BUILD_DIR"
fi
if [ -f "$GST_BAD_BUILD/meson-private/coredata.dat" ]; then
  "$RDESK_ENV_DIR/bin/meson" setup --reconfigure --clearcache \
    "$GST_BAD_BUILD" "$GST_BAD_SOURCE" \
    --prefix "$RDESK_ENV_DIR" --libdir lib --buildtype release \
    -Dauto_features=disabled -Dwebrtc=enabled -Ddtls=enabled \
    -Dsrtp=enabled -Dsctp=enabled
else
  "$RDESK_ENV_DIR/bin/meson" setup \
    "$GST_BAD_BUILD" "$GST_BAD_SOURCE" \
    --prefix "$RDESK_ENV_DIR" --libdir lib --buildtype release \
    -Dauto_features=disabled -Dwebrtc=enabled -Ddtls=enabled \
    -Dsrtp=enabled -Dsctp=enabled
fi
"$RDESK_ENV_DIR/bin/meson" compile -C "$GST_BAD_BUILD"
"$RDESK_ENV_DIR/bin/meson" install -C "$GST_BAD_BUILD"

if [ ! -d "$PLUGIN_SOURCE/.git" ]; then
  git clone --depth 1 --branch "$GST_PLUGIN_TAG" \
    https://gitlab.freedesktop.org/gstreamer/gst-plugins-rs.git "$PLUGIN_SOURCE"
else
  git -C "$PLUGIN_SOURCE" fetch --depth 1 origin "$GST_PLUGIN_TAG"
  git -C "$PLUGIN_SOURCE" checkout --detach FETCH_HEAD
fi

cargo build --manifest-path "$PLUGIN_SOURCE/Cargo.toml" \
  --package gst-plugin-webrtc \
  --package gst-plugin-rtp \
  --release
install -m 755 "$PLUGIN_SOURCE/target/release/libgstrswebrtc.so" \
  "$RDESK_ENV_DIR/lib/gstreamer-1.0/libgstrswebrtc.so"
install -m 755 "$PLUGIN_SOURCE/target/release/libgstrsrtp.so" \
  "$RDESK_ENV_DIR/lib/gstreamer-1.0/libgstrsrtp.so"

"$RDESK_ENV_DIR/bin/pip" install -r "$(dirname "$0")/requirements-v2.txt"

export GST_REGISTRY_1_0="$RDESK_DATA_DIR/registry.x86_64.bin"
rm -f "$GST_REGISTRY_1_0"
GST_PLUGIN_PATH="$RDESK_ENV_DIR/lib/gstreamer-1.0" \
  "$RDESK_ENV_DIR/bin/gst-inspect-1.0" webrtcsink >/dev/null
GST_PLUGIN_PATH="$RDESK_ENV_DIR/lib/gstreamer-1.0" \
  "$RDESK_ENV_DIR/bin/gst-inspect-1.0" webrtcsrc >/dev/null
for element in webrtcbin nicesrc nicesink dtlssrtpenc srtpenc srtpdec \
  sctpenc sctpdec rtpgccbwe rtprtxsend rtprtxreceive \
  rtpulpfecenc rtpulpfecdec; do
  GST_PLUGIN_PATH="$RDESK_ENV_DIR/lib/gstreamer-1.0" \
    "$RDESK_ENV_DIR/bin/gst-inspect-1.0" "$element" >/dev/null
done

echo "rdesk V2 Ubuntu runtime installed: $RDESK_ENV_DIR"
echo "Run: ./start_rdesk_v2_ubuntu.sh"
