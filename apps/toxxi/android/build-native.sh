#!/bin/sh
# Builds toxxi and what it needs for one Android ABI into app/src/main/jniLibs.
#
# Usage: build-native.sh ABI
#
# Needs ANDROID_NDK_HOME, cargo with the ABI's Rust target, LIBCLANG_PATH, cmake, make and
# pkg-config. c-toxcore comes from TOXCORE_SRC if set, otherwise its master is cloned. Everything is
# built in BUILD_DIR, by default ~/.cache/toxxi-android.
set -eu

ABI=$1
API=26
case $ABI in
  arm64-v8a) TARGET=aarch64-linux-android VPX_TARGET=arm64-android-gcc ;;
  x86_64) TARGET=x86_64-linux-android VPX_TARGET=x86_64-android-gcc ;;
  *) echo "unknown ABI: $ABI" >&2 && exit 1 ;;
esac

HERE=$(cd "$(dirname "$0")" && pwd)
BUILD_DIR=${BUILD_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/toxxi-android}
BUILD=$BUILD_DIR/$ABI
PREFIX=$BUILD/prefix
DOWNLOADS=$BUILD_DIR/downloads
JNILIBS=$HERE/app/src/main/jniLibs/$ABI
NDK=$ANDROID_NDK_HOME
TOOLCHAIN=$NDK/toolchains/llvm/prebuilt/linux-x86_64
JOBS=$(nproc)

export CC=$TOOLCHAIN/bin/$TARGET$API-clang
export CXX=$TOOLCHAIN/bin/$TARGET$API-clang++
export AR=$TOOLCHAIN/bin/llvm-ar
export RANLIB=$TOOLCHAIN/bin/llvm-ranlib
export STRIP=$TOOLCHAIN/bin/llvm-strip
export CFLAGS="-O2 -fPIC"
export PKG_CONFIG_LIBDIR=$PREFIX/lib/pkgconfig
export PKG_CONFIG_PATH=$PKG_CONFIG_LIBDIR

mkdir -p "$BUILD" "$DOWNLOADS" "$JNILIBS"

# Whether $1 still needs building.
todo() {
  [ ! -f "$BUILD/$1.done" ]
}

# Downloads a tarball, checks its hash, unpacks it into $BUILD/$1 and changes to that directory.
unpack() {
  name=$1 url=$2 sha256=$3
  file=$DOWNLOADS/$name-$(basename "$url")
  [ -f "$file" ] || curl -fsSLo "$file" "$url"
  echo "$sha256  $file" | sha256sum -c
  rm -rf "${BUILD:?}/$name" && mkdir -p "$BUILD/$name"
  tar xf "$file" -C "$BUILD/$name" --strip-components=1
  cd "$BUILD/$name"
}

if todo libsodium; then
  unpack libsodium https://github.com/jedisct1/libsodium/releases/download/1.0.22-RELEASE/libsodium-1.0.22.tar.gz \
    adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349
  ./configure --host="$TARGET" --prefix="$PREFIX" --disable-shared --with-pic
  make -j"$JOBS" install
  touch "$BUILD/libsodium.done"
fi

if todo opus; then
  unpack opus https://downloads.xiph.org/releases/opus/opus-1.6.1.tar.gz \
    6ffcb593207be92584df15b32466ed64bbec99109f007c82205f0194572411a1
  ./configure --host="$TARGET" --prefix="$PREFIX" --disable-shared --with-pic --disable-doc \
    --disable-extra-programs
  make -j"$JOBS" install
  touch "$BUILD/opus.done"
fi

if todo libvpx; then
  unpack libvpx https://storage.googleapis.com/downloads.webmproject.org/releases/webm/libvpx-1.17.0.tar.gz \
    7f98aae5c52c46e85b7b26feabcab9b1554605e771bd1df1d6e6a00ee22fa8ed
  ./configure --prefix="$PREFIX" --target="$VPX_TARGET" --libc="$TOOLCHAIN/sysroot" --disable-vp9 \
    --disable-examples --disable-tools --disable-docs --disable-unit-tests --enable-pic
  # libvpx's Android targets assume GNU as and strip.
  sed -i -e "s|^AS=as|AS=$CC -c|" -e "s|^STRIP=strip|STRIP=$STRIP|" ./*.mk
  make -j"$JOBS" install
  touch "$BUILD/libvpx.done"
fi

if todo c-toxcore; then
  rm -rf "$BUILD/c-toxcore"
  if [ -n "${TOXCORE_SRC-}" ]; then
    cp -r "$TOXCORE_SRC" "$BUILD/c-toxcore"
  else
    git clone --depth=1 --recursive https://github.com/TokTok/c-toxcore "$BUILD/c-toxcore"
  fi
  cd "$BUILD/c-toxcore"
  cmake -B _build -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" -DANDROID_ABI="$ABI" \
    -DANDROID_PLATFORM=android-$API -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_PREFIX_PATH="$PREFIX" \
    -DCMAKE_FIND_ROOT_PATH="$PREFIX;$TOOLCHAIN/sysroot" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DENABLE_SHARED=OFF -DBOOTSTRAP_DAEMON=OFF -DDHT_BOOTSTRAP=OFF \
    -DMUST_BUILD_TOXAV=ON
  cmake --build _build -j"$JOBS" --target install
  # The bindings also use the headers CMake doesn't install.
  cp toxcore/tox_attributes.h toxcore/tox_events.h toxcore/tox_private.h "$PREFIX/include/tox/"
  # toxcore.pc asks for libpthread, which Android has in libc.
  "$AR" rcs "$PREFIX/lib/libpthread.a"
  touch "$BUILD/c-toxcore.done"
fi

# Cargo's variables for the target, e.g. CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER.
CARGO_TARGET=$(echo "$TARGET" | tr a-z- A-Z_)
env \
  "CARGO_TARGET_${CARGO_TARGET}_LINKER=$CC" \
  "CARGO_TARGET_${CARGO_TARGET}_RUSTFLAGS=-C link-arg=-Wl,-z,max-page-size=16384" \
  "CC_$TARGET=$CC" "AR_$TARGET=$AR" \
  "BINDGEN_EXTRA_CLANG_ARGS_$TARGET=--target=$TARGET$API --sysroot=$TOOLCHAIN/sysroot -I$PREFIX/include" \
  PKG_CONFIG_ALLOW_CROSS=1 PKG_CONFIG_ALL_STATIC=1 CARGO_TARGET_DIR="$BUILD_DIR/target" \
  cargo build --manifest-path "$HERE/Cargo.toml" --release --target "$TARGET"
"$STRIP" -o "$JNILIBS/libtoxxi_android.so" "$BUILD_DIR/target/$TARGET/release/libtoxxi_android.so"
