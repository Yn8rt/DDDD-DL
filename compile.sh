#!/usr/bin/env bash

set -euo pipefail

LDFLAGS="-s -w -buildid="
CGO_ENABLED=0
BUILD_ALL=0
HAS_VALID_TARGET=0
BUILT_FILES=()

cd "$(dirname "$0")"

if ! command -v go >/dev/null 2>&1; then
    echo "Go command not found. Please install Go or add go to PATH."
    exit 1
fi

mkdir -p outp

echo "========================================"
echo "DDDD cross-platform build"
echo "========================================"
echo
echo "Select build targets. Use spaces or commas for multiple targets."
echo "Press Enter or input A to build all targets."
echo
echo "  [1] Windows amd64       - outp/dddd64.exe"
echo "  [2] Linux amd64         - outp/dddd_linux_amd64"
echo "  [3] Linux arm64         - outp/dddd_linux_arm64"
echo "  [4] macOS arm64         - outp/dddd_darwin_arm64"
echo "  [5] macOS amd64 Intel   - outp/dddd_darwin_amd64"
echo

read -r -p "Input target numbers: " TARGETS

if [[ -z "$TARGETS" ]]; then
    TARGETS="A"
fi

TARGETS="${TARGETS//,/ }"
TARGETS="${TARGETS//;/ }"

for target in $TARGETS; do
    case "$target" in
        [Aa]|[Aa][Ll][Ll])
            BUILD_ALL=1
            ;;
        1|2|3|4|5)
            HAS_VALID_TARGET=1
            ;;
    esac
done

if [[ "$BUILD_ALL" -eq 0 && "$HAS_VALID_TARGET" -eq 0 ]]; then
    echo "No valid build target selected."
    exit 1
fi

build_if_selected() {
    local target_id="$1"
    local target_name="$2"
    local target_goos="$3"
    local target_goarch="$4"
    local target_output="$5"
    local matched=0

    if [[ "$BUILD_ALL" -eq 0 ]]; then
        for target in $TARGETS; do
            if [[ "$target" == "$target_id" ]]; then
                matched=1
                break
            fi
        done

        if [[ "$matched" -eq 0 ]]; then
            return 0
        fi
    fi

   echo "Building $target_name..."
   CGO_ENABLED="$CGO_ENABLED" GOOS="$target_goos" GOARCH="$target_goarch" \
       go build -ldflags="$LDFLAGS" -trimpath -o "$target_output" ./cmd/dddd
   BUILT_FILES+=("$target_output")
   echo
    compress_with_upx "$target_output" "$target_goos"
}

echo

# 可选：使用 UPX 进一步压缩二进制（Linux/Windows 原生支持；macOS 需 --force-macos）
# 设置 DDDD_NO_UPX=1 可禁用
compress_with_upx() {
    local output="$1"
    local goos="$2"

    if [[ -n "${DDDD_NO_UPX:-}" ]]; then
        echo "DDDD_NO_UPX is set, skipping UPX compression."
        return 0
    fi

   if ! command -v upx >/dev/null 2>&1; then
       echo "UPX not found, leaving binary uncompressed. Install UPX to reduce size."
       return 0
   fi

    # UPX 对 macOS 需要 --force-macos，且运行可能被 Gatekeeper 拦截，默认不压缩
    if [[ "$goos" == "darwin" && -z "${DDDD_UPX_FORCE:-}" ]]; then
        echo "Skipping UPX for macOS binary (set DDDD_UPX_FORCE=1 to force with --force-macos)."
        return 0
    fi

   local upx_args=("-9")
   if [[ "$goos" == "darwin" ]]; then
        upx_args+=("--force-macos")
    fi

    echo "Compressing $output with UPX..."
    local size_before size_after
    size_before=$(du -h "$output" | cut -f1)
    if upx "${upx_args[@]}" -o "${output}.upx" "$output" >/dev/null 2>&1; then
        mv -f "${output}.upx" "$output"
        size_after=$(du -h "$output" | cut -f1)
        echo "  Compressed: $size_before -> $size_after"
    else
        rm -f "${output}.upx"
        echo "  UPX compression failed, keeping uncompressed binary."
    fi
}

echo
build_if_selected 1 "Windows amd64" windows amd64 "./outp/dddd64.exe"
build_if_selected 2 "Linux amd64" linux amd64 "./outp/dddd_linux_amd64"
build_if_selected 3 "Linux arm64" linux arm64 "./outp/dddd_linux_arm64"
build_if_selected 4 "macOS arm64" darwin arm64 "./outp/dddd_darwin_arm64"
build_if_selected 5 "macOS amd64 Intel" darwin amd64 "./outp/dddd_darwin_amd64"

echo "========================================"
echo "Build completed"
echo "========================================"
echo
echo "Output files:"
for file in "${BUILT_FILES[@]}"; do
    echo "  $file"
done
echo
