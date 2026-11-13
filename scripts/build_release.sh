#!/usr/bin/env bash
set -euo pipefail

PIO="${PIO:-pio}"
PIO_HOME="${PLATFORMIO_CORE_DIR:-${HOME}/.platformio}"
ESPTOOL="${PIO_HOME}/packages/tool-esptool/esptool"
FRAMEWORK="${PIO_HOME}/packages/framework-arduinoespressif32"

"${PIO}" test -e native
"${PIO}" run -e esp32-s3
"${PIO}" run -e esp32-s3-4mb

mkdir -p firmware

merge_image() {
    local environment="$1"
    local size="$2"
    local output="$3"
    "${ESPTOOL}" --chip esp32s3 merge-bin \
        -o "${output}" \
        --flash-mode qio --flash-freq 80m --flash-size "${size}" \
        0x0 ".pio/build/${environment}/bootloader.bin" \
        0x8000 ".pio/build/${environment}/partitions.bin" \
        0xe000 "${FRAMEWORK}/tools/partitions/boot_app0.bin" \
        0x10000 ".pio/build/${environment}/firmware.bin"
}

merge_image esp32-s3 8MB firmware/VaultKey_revD_8MB_factory.bin
merge_image esp32-s3-4mb 4MB firmware/VaultKey_revD_4MB_factory.bin
cp .pio/build/esp32-s3/firmware.bin \
    firmware/VaultKey_revD_8MB_firmware.bin
cp .pio/build/esp32-s3-4mb/firmware.bin \
    firmware/VaultKey_revD_4MB_firmware.bin

(cd firmware && sha256sum VaultKey_*.bin > SHA256SUMS.txt)
echo "Release binaries written to firmware/"
