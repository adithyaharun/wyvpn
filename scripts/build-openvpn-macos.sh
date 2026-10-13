#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[ "$(uname -s)" = Darwin ] || die "macOS only"
load_openvpn_pins

export MACOSX_DEPLOYMENT_TARGET=13.0
CACHE="$PACKAGING_DIR/cache"
WORK="$PACKAGING_DIR/openvpn-macos"
OUT="$TAURI_DIR/resources/openvpn-macos"
JOBS="$(sysctl -n hw.ncpu)"

OPENVPN_TGZ="$CACHE/openvpn-$OPENVPN_VERSION.tar.gz"
OPENSSL_TGZ="$CACHE/openssl-$OPENSSL_VERSION.tar.gz"
LZ4_TGZ="$CACHE/lz4-$LZ4_VERSION.tar.gz"
LZO_TGZ="$CACHE/lzo-$LZO_VERSION.tar.gz"

fetch_verified "$OPENVPN_SOURCE_URL" "$OPENVPN_SOURCE_SHA256" "$OPENVPN_TGZ"
fetch_verified "$OPENSSL_URL" "$OPENSSL_SHA256" "$OPENSSL_TGZ"
fetch_verified "$LZ4_URL" "$LZ4_SHA256" "$LZ4_TGZ"
fetch_verified "$LZO_URL" "$LZO_SHA256" "$LZO_TGZ"

build_arch() {
  local arch="$1" host ossl_target
  case "$arch" in
    arm64) host=aarch64-apple-darwin ossl_target=darwin64-arm64-cc ;;
    x86_64) host=x86_64-apple-darwin ossl_target=darwin64-x86_64-cc ;;
    *) die "unknown arch $arch" ;;
  esac
  local dir="$WORK/$arch" prefix="$WORK/$arch/prefix"
  local cflags="-arch $arch -mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET -O2"
  rm -rf "$dir"
  mkdir -p "$prefix"
  for tgz in "$OPENSSL_TGZ" "$LZ4_TGZ" "$LZO_TGZ" "$OPENVPN_TGZ"; do
    tar -xzf "$tgz" -C "$dir"
  done

  say "[$arch] OpenSSL $OPENSSL_VERSION"
  (
    cd "$dir/openssl-$OPENSSL_VERSION"
    ./Configure "$ossl_target" no-shared no-tests \
      --prefix="$prefix" --libdir=lib "-mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET"
    make -j"$JOBS"
    make install_sw
  ) >"$dir/openssl.log" 2>&1 || die "OpenSSL build failed; see $dir/openssl.log"

  say "[$arch] LZ4 $LZ4_VERSION"
  make -C "$dir/lz4-$LZ4_VERSION/lib" -j"$JOBS" install \
    PREFIX="$prefix" BUILD_SHARED=no CFLAGS="$cflags" \
    >"$dir/lz4.log" 2>&1 || die "LZ4 build failed; see $dir/lz4.log"

  say "[$arch] LZO $LZO_VERSION"
  (
    cd "$dir/lzo-$LZO_VERSION"
    ./configure --host="$host" --prefix="$prefix" --disable-shared --enable-static CFLAGS="$cflags"
    make -j"$JOBS"
    make install
  ) >"$dir/lzo.log" 2>&1 || die "LZO build failed; see $dir/lzo.log"

  say "[$arch] OpenVPN $OPENVPN_VERSION"
  (
    cd "$dir/openvpn-$OPENVPN_VERSION"
    ./configure --host="$host" --prefix="$prefix" \
      --with-crypto-library=openssl --disable-plugins --disable-unit-tests \
      OPENSSL_CFLAGS="-I$prefix/include" \
      OPENSSL_LIBS="$prefix/lib/libssl.a $prefix/lib/libcrypto.a" \
      LZ4_CFLAGS="-I$prefix/include" LZ4_LIBS="-L$prefix/lib -llz4" \
      LZO_CFLAGS="-I$prefix/include" LZO_LIBS="-L$prefix/lib -llzo2" \
      CFLAGS="$cflags" LDFLAGS="-arch $arch -mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET"
    make -j"$JOBS"
  ) >"$dir/openvpn.log" 2>&1 || die "OpenVPN build failed; see $dir/openvpn.log"
}

build_arch arm64
build_arch x86_64

rm -rf "$OUT"
mkdir -p "$OUT/third-party"
lipo -create \
  "$WORK/arm64/openvpn-$OPENVPN_VERSION/src/openvpn/openvpn" \
  "$WORK/x86_64/openvpn-$OPENVPN_VERSION/src/openvpn/openvpn" \
  -output "$OUT/openvpn"
chmod 755 "$OUT/openvpn"

archs="$(lipo -archs "$OUT/openvpn")"
[[ "$archs" == *arm64* && "$archs" == *x86_64* ]] || die "openvpn is not universal: $archs"
if otool -L "$OUT/openvpn" | grep -E '^[[:space:]]' | grep -Ev '^[[:space:]]+/(usr/lib|System/Library)/'; then
  die "openvpn links non-system libraries"
fi

src="$WORK/arm64"
cp "$src/openvpn-$OPENVPN_VERSION/COPYRIGHT.GPL" "$OUT/LICENSE"
cp "$src/openvpn-$OPENVPN_VERSION/COPYING" "$OUT/COPYING"
cp "$src/openssl-$OPENSSL_VERSION/LICENSE.txt" "$OUT/third-party/OpenSSL-$OPENSSL_VERSION.txt"
cp "$src/lz4-$LZ4_VERSION/lib/LICENSE" "$OUT/third-party/LZ4-$LZ4_VERSION.txt"
cp "$src/lzo-$LZO_VERSION/COPYING" "$OUT/third-party/LZO-$LZO_VERSION.txt"
printf '%s\n' "$OPENVPN_VERSION" >"$OUT/VERSION"

"$OUT/openvpn" --version | head -n 1 >&2 || true
say "staged $OUT"
