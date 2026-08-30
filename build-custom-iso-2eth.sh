#!/bin/sh
#
# build-custom-iso-2eth.sh
# Membangun custom FreeBSD 14.3 ISO NTPSense InetGateway CE - 2eth Variant
# (2-NIC minimal hardware) dengan install-gateway-2eth-v2.sh, webui-ce.tar.gz,
# dan installerconfig-2eth sudah tertanam untuk scripted-install otomatis penuh.
#
# DIJALANKAN DI: Laptop Linux (Ubuntu/Debian) ATAU VM FreeBSD-Build dengan
# akses internet penuh. TIDAK dijalankan di sandbox Claude.
#
# DIADAPTASI dari build-custom-iso-v2.sh (Tier 2, 3+ NIC dengan MGMT) -
# STRATEGI TEKNIS SAMA PERSIS (extract-inject-repack via xorriso, preserve
# boot equipment, verifikasi checksum binary, dll) - yang GENUINELY berbeda:
#   - Sumber file lokal: installerconfig-2eth, install-gateway-2eth-v2.sh,
#     webui-ce.tar.gz (SEKARANG WAJIB ADA - beda dari v2 yang waktu itu
#     opsional karena Web UI belum diimplementasi sama sekali)
#   - Nama output ISO diberi suffix -CE-2eth
#   - TIDAK ADA konsep MGMT di pesan konfirmasi/summary (2eth genuinely
#     tidak punya zona itu)
#
# FILE YANG WAJIB ADA DI DIREKTORI YANG SAMA DENGAN SCRIPT INI:
#   - installerconfig-2eth       (WAJIB)
#   - webui-ce.tar.gz            (WAJIB - beda dari v2, Web UI CE sudah lengkap)
#   - ntpsense-configd           (WAJIB - binary precompiled dari FreeBSD-Build)
#   - ntpsense_configd.rc        (WAJIB - rc.d script pasangan binary di atas)
#
set -e

WORKDIR="${HOME}/freebsd-custom-iso-build-2eth"
FREEBSD_VERSION="14.3"
FREEBSD_ARCH="amd64"
ISO_BASENAME="FreeBSD-${FREEBSD_VERSION}-RELEASE-${FREEBSD_ARCH}-disc1.iso"
ISO_URL="https://download.freebsd.org/releases/${FREEBSD_ARCH}/${FREEBSD_ARCH}/ISO-IMAGES/${FREEBSD_VERSION}/${ISO_BASENAME}.xz"
OUTPUT_ISO_NAME="NTPSense-InetGateway-CE-2eth-${FREEBSD_VERSION}-${FREEBSD_ARCH}.iso"
GATEWAY_SCRIPT_SOURCE=""   # diisi via argumen, lihat di bawah

log() {
    echo ">>> $1"
}
fatal() {
    echo "FATAL: $1" >&2
    exit 1
}

# ============================================================
# DETEKSI PLATFORM DAN PRIVILEGE - identik pola build-custom-iso-v2.sh.
# ============================================================
OS_NAME="$(uname -s)"
log "Platform terdeteksi: ${OS_NAME}"

if [ "$(id -u)" -eq 0 ]; then
    SUDO_CMD=""
    log "Berjalan sebagai root - operasi privileged dijalankan langsung (tanpa sudo)."
else
    SUDO_CMD="sudo"
    log "Berjalan sebagai user biasa - operasi privileged akan memakai sudo."
fi

# ============================================================
# 0. VALIDASI ARGUMEN & TOOLS
# ============================================================
if [ -z "$1" ]; then
    fatal "Usage: $0 /path/to/install-gateway-2eth-v2.sh [expected_sha256]
  Berikan path ke file install-gateway-2eth-v2.sh (deteksi 2 NIC + LAN1
  dobel-fungsi + WAN1 + pf anti-lockout + swap + install paket + bootstrap
  Web UI lengkap) yang akan disuntik ke dalam custom ISO 2eth. Argumen
  kedua (opsional) = checksum SHA256 yang diharapkan untuk ntpsense-configd."
fi

GATEWAY_SCRIPT_SOURCE="$1"
if [ ! -f "${GATEWAY_SCRIPT_SOURCE}" ]; then
    fatal "File tidak ditemukan: ${GATEWAY_SCRIPT_SOURCE}"
fi

GATEWAY_SCRIPT_SOURCE="$(cd "$(dirname "${GATEWAY_SCRIPT_SOURCE}")" && pwd)/$(basename "${GATEWAY_SCRIPT_SOURCE}")"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALLERCONFIG_SOURCE="${SCRIPT_DIR}/installerconfig-2eth"
WEBUI_TARBALL_SOURCE="${SCRIPT_DIR}/webui-ce.tar.gz"
NTPSENSE_CONFIGD_BINARY_SOURCE="${SCRIPT_DIR}/ntpsense-configd"
NTPSENSE_CONFIGD_RCD_SOURCE="${SCRIPT_DIR}/ntpsense_configd.rc"
CONSOLE_MENU_SOURCE="${SCRIPT_DIR}/ntpsense-console-menu.sh"
CONSOLE_SYNC_SOURCE="${SCRIPT_DIR}/ntpsense-sync-os-accounts.sh"
CONSOLE_SET_PASSWORD_SOURCE="${SCRIPT_DIR}/console-set-password.php"

# Checksum WAJIB di-update manual setiap kali source Rust berubah dan
# di-build ulang - diisi via argumen ke-2 (opsional) supaya build pertama
# kali TIDAK fatal cuma karena belum tahu checksum-nya (chicken-and-egg
# problem: harus build dulu baru tahu checksum). Kalau argumen ke-2 tidak
# diberikan, checksum verification di-SKIP dengan WARNING keras (bukan
# fatal) - supaya build pertama tetap bisa jalan, tapi admin sadar
# risikonya (bukan diam-diam dilewati tanpa pemberitahuan).
NTPSENSE_CONFIGD_EXPECTED_SHA256="${2:-}"

log "Validasi tools yang dibutuhkan (xorriso, wget/curl, xz, isoinfo)..."
MISSING_TOOLS=""
for tool in xorriso wget xz isoinfo; do
    if ! command -v "${tool}" > /dev/null 2>&1; then
        MISSING_TOOLS="${MISSING_TOOLS} ${tool}"
    fi
done

if [ -n "${MISSING_TOOLS}" ]; then
    echo ""
    echo "Tools berikut belum terinstall:${MISSING_TOOLS}"
    echo "Install dengan:"
    if [ "${OS_NAME}" = "FreeBSD" ]; then
        echo "  pkg install -y xorriso wget cdrtools"
        echo "  (xz TIDAK perlu pkg install - sudah bagian base system FreeBSD)"
    else
        echo "  sudo apt update"
        echo "  sudo apt install -y xorriso wget xz-utils genisoimage"
    fi
    echo ""
    fatal "Lengkapi tools di atas dulu, lalu jalankan ulang script ini."
fi
log "Semua tools tersedia."
log "Versi xorriso: $(xorriso --version 2>&1 | head -1)"

# ============================================================
# 0b. VALIDASI FILE WAJIB - berbeda dari v2 (yang webui/binary opsional
# waktu itu), varian 2eth WAJIB semuanya ada karena Web UI CE sudah
# genuinely lengkap dan sudah terverifikasi bekerja (bukan skeleton lagi).
# ============================================================
log "Validasi file wajib..."
for _f in "${INSTALLERCONFIG_SOURCE}" "${WEBUI_TARBALL_SOURCE}" "${NTPSENSE_CONFIGD_BINARY_SOURCE}" "${NTPSENSE_CONFIGD_RCD_SOURCE}" "${CONSOLE_MENU_SOURCE}" "${CONSOLE_SYNC_SOURCE}" "${CONSOLE_SET_PASSWORD_SOURCE}"; do
    if [ ! -f "${_f}" ]; then
        fatal "File wajib tidak ditemukan: ${_f}
  Varian 2eth WAJIB menyertakan semua file ini (beda dari build-custom-iso-v2.sh
  Tier 2 yang webui/binary-nya opsional saat itu) - Web UI CE 2eth sudah
  genuinely lengkap dan terverifikasi bekerja, jadi tidak ada alasan
  membangun ISO tanpanya."
    fi
done
log "Semua file wajib ditemukan."

# ============================================================
# 1. DOWNLOAD ISO ASLI (kalau belum ada) - identik pola v2.
# ============================================================
mkdir -p "${WORKDIR}"
cd "${WORKDIR}"

if [ -f "${ISO_BASENAME}" ]; then
    log "ISO asli sudah ada di lokal: ${WORKDIR}/${ISO_BASENAME}, skip download."
else
    if [ -f "${ISO_BASENAME}.xz" ]; then
        log "File .xz sudah ada, skip download, lanjut extract..."
    else
        log "Download ISO FreeBSD ${FREEBSD_VERSION} (~700MB, mohon tunggu)..."
        wget -O "${ISO_BASENAME}.xz" "${ISO_URL}"
    fi
    log "Extract ISO dari .xz..."
    xz -d -k "${ISO_BASENAME}.xz"
fi

if [ ! -f "${ISO_BASENAME}" ]; then
    fatal "ISO asli tidak ditemukan setelah proses download/extract. Cek koneksi internet dan coba lagi."
fi
log "ISO asli siap: ${WORKDIR}/${ISO_BASENAME}"

# ============================================================
# 2. AMBIL VOLUME ID & PROPOSAL BOOT PARAMETERS DARI ISO ASLI
# ============================================================
log "Mengambil Volume ID dari ISO asli..."
ORIGINAL_VOLID=$(isoinfo -d -i "${ISO_BASENAME}" | grep "Volume id:" | sed 's/Volume id: *//')

if [ -z "${ORIGINAL_VOLID}" ]; then
    fatal "Gagal membaca Volume ID dari ISO asli. File ISO mungkin korup."
fi
log "Volume ID asli: ${ORIGINAL_VOLID}"

log "Membaca proposal parameter boot (El Torito/UEFI) dari ISO asli..."
echo ""
echo "--- Output xorriso report (untuk referensi/debug) ---"
xorriso -indev "${ISO_BASENAME}" \
    -report_el_torito plain \
    -report_system_area plain \
    2>&1 | tee "${WORKDIR}/xorriso-report.txt"
echo "--- akhir output report ---"
echo ""
log "Report lengkap tersimpan di: ${WORKDIR}/xorriso-report.txt"

# ============================================================
# 3. EXTRACT ISI ISO KE DIREKTORI KERJA
# ============================================================
EXTRACT_DIR="${WORKDIR}/iso-extracted"

log "Membersihkan direktori kerja lama (jika ada)..."
rm -rf "${EXTRACT_DIR}"
mkdir -p "${EXTRACT_DIR}"

log "Mengekstrak isi ISO asli (via xorriso)..."
echo ""
echo "Proses ini memerlukan 'sudo' karena file-file di ISO FreeBSD asli"
echo "dimiliki oleh root:wheel."
echo ""
${SUDO_CMD} xorriso -osirrox on -indev "${ISO_BASENAME}" -extract / "${EXTRACT_DIR}" 2>&1 | tee "${WORKDIR}/xorriso-extract.log"

if [ -z "$(${SUDO_CMD} ls -A "${EXTRACT_DIR}" 2>/dev/null)" ]; then
    fatal "Direktori hasil extract kosong. Cek log di ${WORKDIR}/xorriso-extract.log"
fi
log "Isi ISO berhasil di-extract ke: ${EXTRACT_DIR}"

log "Memastikan ownership seluruh file root:wheel (0:0)..."
${SUDO_CMD} chown -R 0:0 "${EXTRACT_DIR}"

# ============================================================
# 4. SUNTIK FILE KUSTOM KE DALAM FILESYSTEM
# ============================================================
log "Menyuntik install-gateway-2eth-v2.sh ke dalam ISO..."
${SUDO_CMD} mkdir -p "${EXTRACT_DIR}/root"
${SUDO_CMD} cp "${GATEWAY_SCRIPT_SOURCE}" "${EXTRACT_DIR}/root/install-gateway-2eth-v2.sh"
${SUDO_CMD} chown 0:0 "${EXTRACT_DIR}/root/install-gateway-2eth-v2.sh"
${SUDO_CMD} chmod +x "${EXTRACT_DIR}/root/install-gateway-2eth-v2.sh"

log "Menyuntik binary ntpsense-configd (Rust daemon CE) ke dalam ISO..."
_configd_actual_sha256=$(sha256sum "${NTPSENSE_CONFIGD_BINARY_SOURCE}" 2>/dev/null | awk '{print $1}')
if [ -z "${_configd_actual_sha256}" ]; then
    _configd_actual_sha256=$(shasum -a 256 "${NTPSENSE_CONFIGD_BINARY_SOURCE}" 2>/dev/null | awk '{print $1}')
fi
if [ -z "${_configd_actual_sha256}" ]; then
    _configd_actual_sha256=$(sha256 -q "${NTPSENSE_CONFIGD_BINARY_SOURCE}" 2>/dev/null)
fi

if [ -z "${NTPSENSE_CONFIGD_EXPECTED_SHA256}" ]; then
    echo ""
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "PERINGATAN: checksum verifikasi TIDAK dijalankan (argumen ke-2"
    echo "tidak diberikan). SHA256 binary yang genuinely dipakai:"
    echo "  ${_configd_actual_sha256}"
    echo "CATAT nilai ini SEKARANG - jalankan ulang script ini dengan"
    echo "argumen ke-2 = nilai di atas untuk verifikasi supply-chain di"
    echo "build berikutnya:"
    echo "  $0 ${GATEWAY_SCRIPT_SOURCE} ${_configd_actual_sha256}"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo ""
elif [ "${_configd_actual_sha256}" != "${NTPSENSE_CONFIGD_EXPECTED_SHA256}" ]; then
    fatal "Checksum ntpsense-configd TIDAK COCOK!
  Expected: ${NTPSENSE_CONFIGD_EXPECTED_SHA256}
  Actual:   ${_configd_actual_sha256}
  Binary ini TIDAK disuntik ke ISO - kemungkinan file salah/corrupt/
  hasil build dari source yang berbeda dari yang sudah divalidasi."
else
    log "Checksum ntpsense-configd cocok: ${_configd_actual_sha256}"
fi

${SUDO_CMD} cp "${NTPSENSE_CONFIGD_BINARY_SOURCE}" "${EXTRACT_DIR}/root/ntpsense-configd"
${SUDO_CMD} chown 0:0 "${EXTRACT_DIR}/root/ntpsense-configd"
${SUDO_CMD} chmod +x "${EXTRACT_DIR}/root/ntpsense-configd"
${SUDO_CMD} cp "${NTPSENSE_CONFIGD_RCD_SOURCE}" "${EXTRACT_DIR}/root/ntpsense_configd.rc"
${SUDO_CMD} chown 0:0 "${EXTRACT_DIR}/root/ntpsense_configd.rc"
log "ntpsense-configd + rc.d script berhasil disuntik."

log "Menyuntik script console menu (ntpsense-console-menu.sh, ntpsense-sync-os-accounts.sh, console-set-password.php)..."
${SUDO_CMD} cp "${CONSOLE_MENU_SOURCE}" "${EXTRACT_DIR}/root/ntpsense-console-menu.sh"
${SUDO_CMD} chown 0:0 "${EXTRACT_DIR}/root/ntpsense-console-menu.sh"
${SUDO_CMD} chmod +x "${EXTRACT_DIR}/root/ntpsense-console-menu.sh"
${SUDO_CMD} cp "${CONSOLE_SYNC_SOURCE}" "${EXTRACT_DIR}/root/ntpsense-sync-os-accounts.sh"
${SUDO_CMD} chown 0:0 "${EXTRACT_DIR}/root/ntpsense-sync-os-accounts.sh"
${SUDO_CMD} chmod +x "${EXTRACT_DIR}/root/ntpsense-sync-os-accounts.sh"
${SUDO_CMD} cp "${CONSOLE_SET_PASSWORD_SOURCE}" "${EXTRACT_DIR}/root/console-set-password.php"
${SUDO_CMD} chown 0:0 "${EXTRACT_DIR}/root/console-set-password.php"
log "Script console menu berhasil disuntik."

log "Menyuntik webui-ce.tar.gz ke dalam ISO..."
${SUDO_CMD} cp "${WEBUI_TARBALL_SOURCE}" "${EXTRACT_DIR}/root/webui-ce.tar.gz"
${SUDO_CMD} chown 0:0 "${EXTRACT_DIR}/root/webui-ce.tar.gz"
log "webui-ce.tar.gz berhasil disuntik ($(du -h "${WEBUI_TARBALL_SOURCE}" | cut -f1))."

# ======================================================================
# Boot logo branding NTPSense untuk MEDIA INSTALLER ITU SENDIRI (bukan
# cuma hasil instalasi seperti yang sudah dilakukan installerconfig-2eth
# via chroot) - riset ditemukan OPNsense sendiri genuinely menyematkan
# brand custom mereka LANGSUNG di ISO installer (brand-opnsense.4th
# ditemukan di struktur ISO mereka) - jadi ini pola yang sudah terbukti
# dipakai vendor sejenis, bukan eksperimen sendirian. OPSIONAL - kalau
# file sumbernya tidak ada di folder ini, di-skip dengan PERINGATAN saja
# (bukan fatal), karena ini pemanis visual, bukan fitur inti fungsi ISO.
# ======================================================================
BOOTLOGO_BRAND_SOURCE="${SCRIPT_DIR}/gfx-ntpsensebrand.lua"
BOOTLOGO_LOGO_SOURCE="${SCRIPT_DIR}/gfx-hexagon.lua"

if [ -f "${BOOTLOGO_BRAND_SOURCE}" ] && [ -f "${BOOTLOGO_LOGO_SOURCE}" ]; then
    log "Menyuntik branding boot logo NTPSense ke media installer ITU SENDIRI..."
    ${SUDO_CMD} mkdir -p "${EXTRACT_DIR}/boot/lua"
    ${SUDO_CMD} cp "${BOOTLOGO_BRAND_SOURCE}" "${EXTRACT_DIR}/boot/lua/gfx-ntpsensebrand.lua"
    ${SUDO_CMD} chown 0:0 "${EXTRACT_DIR}/boot/lua/gfx-ntpsensebrand.lua"
    ${SUDO_CMD} cp "${BOOTLOGO_LOGO_SOURCE}" "${EXTRACT_DIR}/boot/lua/gfx-hexagon.lua"
    ${SUDO_CMD} chown 0:0 "${EXTRACT_DIR}/boot/lua/gfx-hexagon.lua"

    ${SUDO_CMD} tee "${EXTRACT_DIR}/boot/loader.conf.local" > /dev/null << 'BOOTLOGOCONF'
loader_logo="hexagon"
loader_brand="ntpsensebrand"
loader_menu_title="NTPSense InetGateway CE - Installer"
loader_logo_x="54"
loader_logo_y="10"
BOOTLOGOCONF
    ${SUDO_CMD} chown 0:0 "${EXTRACT_DIR}/boot/loader.conf.local"
    log "Branding boot logo media installer berhasil disuntik - layar boot USB SEKARANG juga tampil NTPSense, bukan cuma hasil instalasi."
else
    log "PERINGATAN: gfx-ntpsensebrand.lua/gfx-hexagon.lua tidak ditemukan di folder ini - media installer TETAP tampil logo FreeBSD default (hasil instalasi tetap dapat branding NTPSense seperti biasa lewat installerconfig-2eth, ini cuma soal layar installer-nya sendiri)."
fi

log "Menyuntik /etc/installerconfig (scripted install 2eth: partisi + LAN1/WAN1)..."
# ======================================================================
# TITIK PALING KRUSIAL - JANGAN DIUBAH: destination WAJIB PERSIS
# '/etc/installerconfig', bukan '/etc/installerconfig-2eth'. Sama alasan
# persis dengan build-custom-iso-v2.sh - bsdinstall hardcode nama ini.
# ======================================================================
${SUDO_CMD} cp "${INSTALLERCONFIG_SOURCE}" "${EXTRACT_DIR}/etc/installerconfig"
${SUDO_CMD} chown 0:0 "${EXTRACT_DIR}/etc/installerconfig"

echo ""
echo "============================================================"
echo "PERHATIAN: ISO ini akan melakukan INSTALASI OTOMATIS PENUH,"
echo "TANPA INTERAKSI MANUAL SAMA SEKALI (zero-interaction)!"
echo "  - Disk PERTAMA yang terdeteksi akan di-HAPUS TOTAL dan"
echo "    di-partisi ulang otomatis (deteksi nda0>nvd0>ada0>da0>vtbd0)."
echo "    Skema 6 partisi (LEBIH RINGAN dari Tier 2, hardware minimal):"
echo "    boot 512K, swap 2G, / 4G, /var 10G, /usr/local 8G, /data (auto)."
echo "  - Root TIDAK memiliki password yang diketahui siapa pun - token"
echo "    recovery dibuat otomatis di /root/.recovery-token."
echo "  - MINIMUM 2 NIC fisik (BUKAN 3 seperti Tier 2) - LAN1 (NIC"
echo "    pertama, 10.252.1.1/24, DOBEL-FUNGSI client+admin) + WAN1"
echo "    (NIC terakhir, DHCP). TIDAK ADA zona MGMT terpisah di varian"
echo "    ini - anti-lockout rule dipasang langsung di LAN1 (pola"
echo "    pfSense/OPNsense untuk hardware 2-NIC)."
echo "  - Setelah boot pertama: install-gateway-2eth-v2.sh OTOMATIS"
echo "    install paket (lighttpd/php84/session/sodium), setup grup"
echo "    ntpsenseweb, bootstrap direktori webui/, extract webui-ce.tar.gz,"
echo "    konfigurasi lighttpd+php-fpm (Unix socket) - Web UI LANGSUNG"
echo "    bisa diakses tanpa langkah manual apa pun."
echo "  TIDAK ADA prompt interaktif pada tahap INSTALASI FREEBSD - boot"
echo "  ISO ini akan LANGSUNG menginstall dasar sistem tanpa bertanya"
echo "  apapun. Pastikan ini benar-benar yang diinginkan sebelum boot"
echo "  ISO ini ke disk yang berisi data penting!"
echo "============================================================"
echo ""
log "Penyuntikan file selesai."

# ============================================================
# 5. REPACK ISO DENGAN BOOT PARAMETERS YANG SAMA - identik pola v2.
# ============================================================
log "Membangun ISO baru (menggunakan xorriso, mempertahankan boot setup asli)..."
${SUDO_CMD} xorriso \
    -indev "${WORKDIR}/${ISO_BASENAME}" \
    -outdev "${WORKDIR}/${OUTPUT_ISO_NAME}" \
    -volid "${ORIGINAL_VOLID}" \
    -map "${EXTRACT_DIR}" / \
    -boot_image any keep \
    -commit \
    2>&1 | tee "${WORKDIR}/xorriso-build.log"

if [ ! -f "${WORKDIR}/${OUTPUT_ISO_NAME}" ]; then
    fatal "ISO baru tidak terbentuk. Cek log di ${WORKDIR}/xorriso-build.log untuk detail error."
fi

${SUDO_CMD} chown "$(id -u):$(id -g)" "${WORKDIR}/${OUTPUT_ISO_NAME}"

# ============================================================
# 6. VERIFIKASI HASIL
# ============================================================
log "=== Verifikasi ISO Baru ==="
echo ""
echo "--- Volume ID ISO baru (harus sama dengan ISO asli) ---"
isoinfo -d -i "${WORKDIR}/${OUTPUT_ISO_NAME}" | grep "Volume id:"
echo "Volume ID asli  : ${ORIGINAL_VOLID}"
echo ""
echo "--- File yang disuntik (verifikasi ada di ISO baru) ---"
isoinfo -i "${WORKDIR}/${OUTPUT_ISO_NAME}" -R -x /root/install-gateway-2eth-v2.sh > /dev/null 2>&1 \
    && echo "install-gateway-2eth-v2.sh: OK" || echo "install-gateway-2eth-v2.sh: TIDAK DITEMUKAN (cek manual!)"
isoinfo -i "${WORKDIR}/${OUTPUT_ISO_NAME}" -R -x /root/ntpsense-configd > /dev/null 2>&1 \
    && echo "ntpsense-configd (binary): OK" || echo "ntpsense-configd (binary): TIDAK DITEMUKAN (cek manual!)"
isoinfo -i "${WORKDIR}/${OUTPUT_ISO_NAME}" -R -x /root/ntpsense_configd.rc > /dev/null 2>&1 \
    && echo "ntpsense_configd.rc: OK" || echo "ntpsense_configd.rc: TIDAK DITEMUKAN (cek manual!)"
isoinfo -i "${WORKDIR}/${OUTPUT_ISO_NAME}" -R -x /root/webui-ce.tar.gz > /dev/null 2>&1 \
    && echo "webui-ce.tar.gz: OK" || echo "webui-ce.tar.gz: TIDAK DITEMUKAN (cek manual!)"
isoinfo -i "${WORKDIR}/${OUTPUT_ISO_NAME}" -R -x /root/ntpsense-console-menu.sh > /dev/null 2>&1 \
    && echo "ntpsense-console-menu.sh: OK" || echo "ntpsense-console-menu.sh: TIDAK DITEMUKAN (cek manual!)"
isoinfo -i "${WORKDIR}/${OUTPUT_ISO_NAME}" -R -x /root/ntpsense-sync-os-accounts.sh > /dev/null 2>&1 \
    && echo "ntpsense-sync-os-accounts.sh: OK" || echo "ntpsense-sync-os-accounts.sh: TIDAK DITEMUKAN (cek manual!)"
isoinfo -i "${WORKDIR}/${OUTPUT_ISO_NAME}" -R -x /root/console-set-password.php > /dev/null 2>&1 \
    && echo "console-set-password.php: OK" || echo "console-set-password.php: TIDAK DITEMUKAN (cek manual!)"
isoinfo -i "${WORKDIR}/${OUTPUT_ISO_NAME}" -R -x /boot/lua/gfx-ntpsensebrand.lua > /dev/null 2>&1 \
    && echo "boot logo (brand, media installer): OK" || echo "boot logo (brand, media installer): tidak disuntik (opsional, cek apakah file sumber ada)"
isoinfo -i "${WORKDIR}/${OUTPUT_ISO_NAME}" -R -x /boot/lua/gfx-hexagon.lua > /dev/null 2>&1 \
    && echo "boot logo (logo, media installer): OK" || echo "boot logo (logo, media installer): tidak disuntik (opsional, cek apakah file sumber ada)"
isoinfo -i "${WORKDIR}/${OUTPUT_ISO_NAME}" -R -x /etc/installerconfig > /dev/null 2>&1 \
    && echo "/etc/installerconfig: OK (nama tujuan benar - installer akan auto-skip Welcome screen)" \
    || echo "/etc/installerconfig: TIDAK DITEMUKAN - bsdinstall TIDAK AKAN auto-install!"
echo ""
echo "--- Ukuran file ---"
ls -lh "${WORKDIR}/${ISO_BASENAME}" "${WORKDIR}/${OUTPUT_ISO_NAME}"
echo ""
echo "--- Boot equipment ISO baru ---"
xorriso -indev "${WORKDIR}/${OUTPUT_ISO_NAME}" \
    -report_el_torito plain \
    -report_system_area plain 2>&1 | head -20

echo ""
echo "============================================"
log "BUILD SELESAI!"
echo "============================================"
echo ""
echo "ISO custom tersimpan di:"
echo "  ${WORKDIR}/${OUTPUT_ISO_NAME}"
echo ""
echo "LANGKAH SELANJUTNYA (WAJIB TEST DI VM SEBELUM DIPAKAI DI HARDWARE FISIK):"
echo "  1. Buat VM baru dengan TEPAT 2 NIC, mount ISO ini sebagai boot media"
echo "  2. Boot ISO ini - TIDAK ADA layar Welcome yang muncul kalau"
echo "     /etc/installerconfig terdeteksi benar"
echo "  3. Instalasi FreeBSD berjalan otomatis penuh, reboot otomatis"
echo "  4. install-gateway-2eth-v2.sh jalan otomatis sebagai root: deteksi"
echo "     NIC -> LAN1/WAN1 -> pf -> swap -> paket -> grup ntpsenseweb ->"
echo "     webui bootstrap -> extract webui-ce.tar.gz -> lighttpd/php-fpm"
echo "  5. Akses https://10.252.1.1/ dari perangkat yang terhubung ke LAN1"
echo "     - Web UI SEHARUSNYA langsung bisa diakses tanpa langkah manual"
echo "     apa pun (beda dari testing manual sebelumnya yang butuh banyak"
echo "     fix satu-satu)"
echo ""
echo "Jika ISO tidak bisa boot di VM, cek log build di:"
echo "  ${WORKDIR}/xorriso-build.log"
echo "  ${WORKDIR}/xorriso-report.txt"
echo ""
