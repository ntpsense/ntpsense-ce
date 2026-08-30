#!/bin/sh
#
# install-gateway-2eth-v2.sh
# NTPSense InetGateway CE - "2eth" Minimal-Hardware Variant, v2
#
# Base: FreeBSD 14.3-RELEASE
#
# BERBEDA dari install-gateway-2eth.sh (v1): v2 ini MEMBAKUKAN seluruh
# perbaikan manual yang ditemukan lewat troubleshooting nyata di VM
# testing (26-27 Agustus 2026) - v1 cuma menyiapkan jaringan/pf.conf/
# scaffold kosong, TIDAK menginstall paket Web UI atau mengkonfigurasi
# lighttpd/php-fpm sampai genuinely bisa serve halaman. v2 melakukan
# SEMUA itu otomatis, supaya instalasi berikutnya TIDAK perlu lagi
# rangkaian debug manual (403/503/session_start/permission/dst) yang
# baru saja dilalui.
#
# RCA yang DIBAKUKAN di sini (masing-masing ditemukan dari kegagalan
# nyata saat testing manual, BUKAN diantisipasi di atas kertas):
#   1. Paket php84-session dan php84-sodium HARUS diinstall terpisah -
#      php84 inti TIDAK menyertakan keduanya. php84-openssl TIDAK ADA
#      sebagai paket terpisah (openssl sudah include di php84 inti) -
#      JANGAN coba install itu, satu nama paket tidak valid akan
#      membatalkan SELURUH command 'pkg install' multi-paket.
#   2. Grup 'ntpsenseweb' WAJIB ada dan user 'www' WAJIB jadi member -
#      tanpa ini, ntpsense-configd menolak SEMUA koneksi socket dari
#      PHP-FPM (peer credential check gagal).
#   3. Direktori /usr/local/etc/ntpsense/webui/ WAJIB dibuat EKSPLISIT
#      dengan owner root:ntpsenseweb mode 0770 SEBELUM Web UI pertama
#      diakses - Auth::ensureBootstrapped() TIDAK BISA mkdir() sendiri
#      (parent dir /usr/local/etc/ntpsense/ root:wheel, PHP-FPM jalan
#      sebagai 'www' tidak punya izin buat folder baru di situ).
#   4. php-fpm (rc.d script bernama 'php_fpm', UNDERSCORE bukan strip)
#      SECARA DEFAULT listen di TCP 127.0.0.1:9000 - lighttpd.conf yang
#      kita generate mengharapkan Unix socket /var/run/php-fpm.sock.
#      WAJIB override listen directive di php-fpm.d/www.conf.
#   5. lighttpd.conf HARUS digenerate LENGKAP di sini (SSL, fastcgi,
#      document-root) - bukan cuma scaffold kosong seperti v1, karena
#      tidak selalu ada VM lain yang bisa jadi sumber copy config.
#
# ============================================================
set -e

SCRIPT_VERSION="2026-08-27-r2-2eth-full-bootstrap"

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# RCA (ditemukan dari pertanyaan user langsung - "log instalasi di
# mana?"): sebelumnya SELURUH output script ini cuma tercetak ke
# console (lewat redirect di rc.local), TIDAK PERNAH tersimpan ke file
# - begitu console tertutup/scroll-back habis, riwayat instalasi
# hilang total. Fix: redirect PENUH ke file log persisten - pola SAMA
# PERSIS dengan installerconfig-2eth (DEBUGLOG), BUKAN 'tee' via
# process substitution >(...) yang BASHISM (tidak valid di POSIX
# /bin/sh FreeBSD - sempat dicoba, gagal 'redirection unexpected').
# Trade-off SADAR: output TIDAK live di console lagi (beda dari
# sebelumnya) - tapi genuinely tersimpan, bisa di-tail -f dari sesi
# SSH/console lain kalau perlu live-monitoring saat instalasi jalan.
INSTALL_LOG="/var/log/ntpsense-install-gateway-2eth.log"
exec >> "${INSTALL_LOG}" 2>&1
echo "=== install-gateway-2eth-v2.sh dimulai: $(date) ==="

INSTALL_MARKER="/var/db/ntpsense-install-complete"
if [ -f "${INSTALL_MARKER}" ]; then
    echo "NTPSense installer sudah pernah selesai sebelumnya (marker: ${INSTALL_MARKER})."
    echo "Melewati instalasi ulang - ini BUKAN error. Hapus marker file manual untuk paksa re-run."
    exit 0
fi

trap '' INT

log() {
    echo ">>> $1"
}

fatal() {
    echo "FATAL: $1" >&2
    exit 1
}

log "Welcome to NTPSense InetGateway CE - 2eth Variant v2 (full bootstrap)"
log "install-gateway-2eth-v2.sh version: ${SCRIPT_VERSION}"

if [ "$(id -u)" != "0" ]; then
    fatal "This script must be run as root."
fi

FREEBSD_VER=$(freebsd-version | cut -d- -f1)
log "Detected FreeBSD version: ${FREEBSD_VER}"

echo "Interfaces detected on this system:"
ifconfig -l
echo ""

PHYSICAL_IFACES=""
for IFACE in $(ifconfig -l); do
    case "${IFACE}" in
        lo*|pflog*|pfsync*|enc*|tun*|tap*|bridge*|vlan*|lagg*|ipfw*|wg*|gif*|gre*)
            ;;
        *)
            PHYSICAL_IFACES="${PHYSICAL_IFACES} ${IFACE}"
            ;;
    esac
done

PHYSICAL_IFACE_COUNT=0
for IFACE in ${PHYSICAL_IFACES}; do
    PHYSICAL_IFACE_COUNT=$((PHYSICAL_IFACE_COUNT + 1))
done

if [ "${PHYSICAL_IFACE_COUNT}" -lt 2 ]; then
    fatal "minimum 2 physical NICs required (LAN1 + WAN1) for the 2eth variant, found: ${PHYSICAL_IFACE_COUNT} (${PHYSICAL_IFACES})"
fi

if [ "${PHYSICAL_IFACE_COUNT}" -gt 2 ]; then
    echo "INFO: more than 2 physical NICs detected - the 2eth variant will only use the first (LAN1) and last (WAN1)."
fi

LAN1_IF=""
WAN1_IF=""

_pos=0
for IFACE in ${PHYSICAL_IFACES}; do
    _pos=$((_pos + 1))
    if [ "${_pos}" -eq 1 ]; then
        LAN1_IF="${IFACE}"
    fi
done
_last_pos=0
for IFACE in ${PHYSICAL_IFACES}; do
    _last_pos=$((_last_pos + 1))
    if [ "${_last_pos}" -eq "${PHYSICAL_IFACE_COUNT}" ]; then
        WAN1_IF="${IFACE}"
    fi
done

log "Zone assignment summary (2eth - NO separate MGMT):"
LAN1_GATEWAY_IP="10.252.1.100"  # bukan .1 - hindari bentrok gateway vswitch VMware saat testing
log "  LAN1  = ${LAN1_IF}  (${LAN1_GATEWAY_IP}/24, dual-purpose: client + admin Web UI/SSH)"
log "  WAN1  = ${WAN1_IF}"
log "  MGMT  = (none - by design for this variant)"

log "Assigning static LAN1 IP (dual-purpose: client + admin)..."

sysrc ifconfig_${LAN1_IF}="inet ${LAN1_GATEWAY_IP}/24"
ifconfig ${LAN1_IF} inet ${LAN1_GATEWAY_IP}/24 up

log "CHECKPOINT 3: LAN1 (${LAN1_IF}) static ${LAN1_GATEWAY_IP}/24 assigned"

sysrc gateway_enable=YES
sysctl net.inet.ip.forwarding=1 > /dev/null
log "CHECKPOINT 3b: gateway_enable=YES + net.inet.ip.forwarding=1"

log "Configuring WAN1 via DHCP..."

sysrc ifconfig_${WAN1_IF}="DHCP"
ifconfig ${WAN1_IF} up

_wan1_tries=0
_wan1_max_tries=5
_wan1_got_ip=0
while [ ${_wan1_tries} -lt ${_wan1_max_tries} ]; do
    _wan1_tries=$((_wan1_tries + 1))
    _wan1_ip=$(ifconfig ${WAN1_IF} | awk '/inet /{print $2}')
    if [ -n "${_wan1_ip}" ]; then
        _wan1_got_ip=1
        break
    fi
    log "WAN1 DHCP attempt ${_wan1_tries}/${_wan1_max_tries} on ${WAN1_IF}..."
    dhclient ${WAN1_IF} > /dev/null 2>&1 || true
    sleep 3
done

if [ "${_wan1_got_ip}" != "1" ]; then
    fatal "WAN1 (${WAN1_IF}) did not get an IP from DHCP after ${_wan1_max_tries} attempts. Check upstream WAN1 cable/connection, then re-run this script."
fi
log "CHECKPOINT 4a: WAN1 (${WAN1_IF}) got IP: ${_wan1_ip}"
pfctl -d 2>/dev/null || true

if ping -c 2 -t 5 1.1.1.1 > /dev/null 2>&1; then
    log "CHECKPOINT 4b: internet IP connectivity OK"
else
    fatal "WAN1 got a DHCP IP but cannot ping out to the internet (1.1.1.1). Check WAN1 upstream NAT/routing."
fi

if host -W 5 freebsd.org > /dev/null 2>&1; then
    log "CHECKPOINT 4c: DNS resolution OK"
else
    log "WARNING: DNS resolution failed - pkg install below will likely fail if this isn't fixed."
fi

# ============================================================
# 4d. SWAP MINIMUM 8GB - sama seperti v1, tidak berubah.
# ============================================================
log "Checking current swap against the recommended 8GB minimum..."

SWAP_TARGET_MB=8192
# RCA KRITIS (ditemukan dari kegagalan nyata - 'pkg' gagal 'No space
# left on device' saat testing end-to-end pertama kali): '/usr/swap0'
# SEBELUMNYA jatuh ke partisi ROOT (cuma 4GB di skema installerconfig-
# 2eth) karena '/usr' BUKAN partisi terpisah - cuma '/usr/local' yang
# dipisah. Menulis swap file sampai 8GB ke situ menghabiskan SELURUH
# partisi root. Fix: pindah ke /data/swap0 - partisi 'auto' yang dapat
# SEMUA sisa ruang disk, jelas paling lega untuk file besar seperti ini.
SWAP_FILE="/data/swap0"

_current_swap_kb=$(swapinfo -k 2>/dev/null | awk 'NR>1{sum+=$2} END{print sum+0}')
_current_swap_mb=$((_current_swap_kb / 1024))

log "Current swap: ${_current_swap_mb}MB (target: ${SWAP_TARGET_MB}MB)"

if [ "${_current_swap_mb}" -ge "${SWAP_TARGET_MB}" ]; then
    log "Current swap is already sufficient, no top-up needed"
else
    _needed_mb=$((SWAP_TARGET_MB - _current_swap_mb))
    log "Adding a swap file to reach the 8GB minimum (+${_needed_mb}MB via ${SWAP_FILE})"
    if [ ! -f "${SWAP_FILE}" ]; then
        dd if=/dev/zero of="${SWAP_FILE}" bs=1m count=${_needed_mb} status=none
        chmod 0600 "${SWAP_FILE}"
    fi
    if ! grep -q "${SWAP_FILE}" /etc/fstab 2>/dev/null; then
        echo "md99 none swap sw,file=${SWAP_FILE},late 0 0" >> /etc/fstab
    fi
    swapon -aq || true
    log "Swap file added and activated"
fi

# ============================================================
# 5. pf.conf - identik dengan v1, tidak berubah (sudah terverifikasi
# valid lewat pfctl -nf di testing sebelumnya).
# ============================================================
log "Building pf configuration (dual-purpose LAN1 + WAN1)..."

PF_CONF=/etc/pf.conf
PF_CONF_TMP=/tmp/pf.conf.new

{
    echo "# NTPSense InetGateway CE - 2eth variant pf.conf"
    echo "# AUTO-GENERATED oleh install-gateway-2eth-v2.sh - JANGAN edit manual."
    echo "#"
    echo "# CATATAN ARSITEKTUR: varian ini TIDAK PUNYA zona MGMT terpisah -"
    echo "# LAN1 dobel-fungsi (client + admin), dilindungi anti-lockout rule"
    echo "# permanen di bawah (pola pfSense/OPNsense untuk hardware 2-NIC)."
    echo ""
    echo "lan1_if = \"${LAN1_IF}\""
    echo "wan1_if = \"${WAN1_IF}\""
    echo 'lan1_net = "10.252.1.0/24"'
    echo ""
    echo "set skip on lo0"
    echo "set block-policy drop"
    echo "set ruleset-optimization basic"
    echo "scrub in all fragment reassemble"
    echo ""
    echo 'nat on $wan1_if from ! ($wan1_if) to any -> ($wan1_if)'
    echo ""
    echo "# NTPSENSE_NAT_PORTFWD_START"
    echo "# NTPSENSE_NAT_PORTFWD_END"
    echo ""
    echo "block log all"
    echo ""
    echo "# ANTI-LOCKOUT LAN1 (prioritas tertinggi, 'quick') - pengganti"
    echo "# rule anti-lockout MGMT - melindungi akses Web UI/SSH SAJA."
    echo 'pass in quick on $lan1_if to ($lan1_if) keep state'
    echo 'pass out quick on $lan1_if keep state'
    echo ""
    echo "# NTPSENSE_CUSTOM_RULES_${LAN1_IF}_START"
    echo "# NTPSENSE_CUSTOM_RULES_${LAN1_IF}_END"
    echo ""
    echo "# NTPSENSE_CUSTOM_RULES_${WAN1_IF}_START"
    echo "# NTPSENSE_CUSTOM_RULES_${WAN1_IF}_END"
    echo 'pass out quick on $wan1_if keep state'
    echo ""
} > "${PF_CONF_TMP}"

if pfctl -nf "${PF_CONF_TMP}"; then
    cp "${PF_CONF_TMP}" "${PF_CONF}"
    chmod 644 "${PF_CONF}"
    sysrc pf_enable=YES
    sysrc pflog_enable=YES
    pfctl -f "${PF_CONF}" 2>/dev/null || true
    pfctl -e 2>/dev/null || true
    log "CHECKPOINT 6: pf.conf valid and applied"
else
    fatal "pf.conf failed syntax validation (pfctl -nf). Draft at ${PF_CONF_TMP} for debugging."
fi

# ============================================================
# 7. GRUP ntpsenseweb - BARU di v2 (RCA #2 di komentar puncak file).
# WAJIB dibuat SEBELUM PHP-FPM di-start pertama kali - grup di-cache
# oleh proses yang sedang jalan, member baru cuma berlaku untuk
# proses yang di-(re)start SETELAH keanggotaan diubah.
# ============================================================
log "Setting up ntpsenseweb group (required for daemon socket auth)..."

pw groupadd ntpsenseweb 2>/dev/null || log "  group ntpsenseweb already exists"
pw groupmod ntpsenseweb -m www
log "CHECKPOINT 7: ntpsenseweb group ready, 'www' is a member"

# ============================================================
# 8. Direktori webui/ - BARU di v2 (RCA #3). Dibuat DI SINI, bukan
# diserahkan ke Auth::ensureBootstrapped() PHP-side yang tidak punya
# izin mkdir() di /usr/local/etc/ntpsense/ (root:wheel).
# ============================================================
log "Creating /usr/local/etc/ntpsense/webui/ (root:ntpsenseweb 0770)..."

mkdir -p /usr/local/etc/ntpsense/webui
chown root:ntpsenseweb /usr/local/etc/ntpsense/webui
chmod 770 /usr/local/etc/ntpsense/webui
log "CHECKPOINT 8: webui/ bootstrap directory ready"

# ============================================================
# 9. TLS cert self-signed - sama seperti v1.
# ============================================================
mkdir -p /usr/local/etc/ntpsense/ssl

if [ ! -f /usr/local/etc/ntpsense/ssl/webui.pem ]; then
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /usr/local/etc/ntpsense/ssl/webui.key \
        -out /usr/local/etc/ntpsense/ssl/webui.crt \
        -subj "/CN=ntpsense-gateway" > /dev/null 2>&1
    cat /usr/local/etc/ntpsense/ssl/webui.key /usr/local/etc/ntpsense/ssl/webui.crt \
        > /usr/local/etc/ntpsense/ssl/webui.pem
    chmod 600 /usr/local/etc/ntpsense/ssl/webui.key /usr/local/etc/ntpsense/ssl/webui.pem
    chmod 644 /usr/local/etc/ntpsense/ssl/webui.crt
fi
log "CHECKPOINT 9: self-signed TLS cert ready"

# ============================================================
# 10. INSTALL PAKET - BARU di v2 (RCA #1). Nama paket yang PERSIS
# valid di repo FreeBSD 14.3, SATU BARIS command TANPA nama paket
# yang tidak ada (php84-openssl BUKAN paket terpisah - satu nama
# tidak valid akan MEMBATALKAN SELURUH command install multi-paket).
# ============================================================
log "Installing lighttpd + php84 + required PHP extensions..."

ASSUME_ALWAYS_YES=yes pkg install -y lighttpd php84 php84-session php84-sodium

log "CHECKPOINT 10: packages installed"

# ============================================================
# 11. php-fpm - konfigurasi Unix socket (RCA #4). rc.d script bernama
# 'php_fpm' (underscore) - dikonfirmasi dari testing nyata, BUKAN
# 'php-fpm' (strip) seperti nama paketnya sendiri.
# ============================================================
log "Configuring php-fpm to use a Unix socket (matching lighttpd's expectation)..."

PHP_FPM_WWW_CONF=/usr/local/etc/php-fpm.d/www.conf

if [ -f "${PHP_FPM_WWW_CONF}" ]; then
    sed -i '' 's|^listen = 127.0.0.1:9000|listen = /var/run/php-fpm.sock|' "${PHP_FPM_WWW_CONF}"
    sed -i '' 's|^;listen.owner = www|listen.owner = www|' "${PHP_FPM_WWW_CONF}"
    sed -i '' 's|^;listen.group = www|listen.group = www|' "${PHP_FPM_WWW_CONF}"
    sed -i '' 's|^;listen.mode = 0660|listen.mode = 0660|' "${PHP_FPM_WWW_CONF}"
else
    fatal "php-fpm pool config not found at ${PHP_FPM_WWW_CONF} - php84 package structure may have changed, check manually."
fi

sysrc php_fpm_enable=YES
service php_fpm start
log "CHECKPOINT 11: php-fpm configured for Unix socket and started"

# ============================================================
# 12. lighttpd.conf - BARU di v2, digenerate LENGKAP (RCA #5) -
# bukan scaffold kosong seperti v1. Path/directive dikonfirmasi
# dari testing nyata yang berhasil.
# ============================================================
log "Generating complete lighttpd.conf (SSL + fastcgi + document-root)..."

cat > /usr/local/etc/lighttpd/lighttpd.conf << 'LIGHTTPDEOF'
# NTPSense InetGateway CE - AUTO-GENERATED by install-gateway-2eth-v2.sh
server.modules += ( "mod_openssl", "mod_fastcgi", "mod_accesslog" )

server.document-root = "/usr/local/www/ntpsense/public"
server.port          = 443
server.username       = "www"
server.groupname      = "www"
server.errorlog       = "/var/log/lighttpd/error.log"
server.breakagelog    = "/var/log/lighttpd/breakage.log"
server.upload-dirs    = ( "/var/tmp" )
server.max-request-size = 8388608

index-file.names = ( "index.php" )

ssl.engine  = "enable"
ssl.pemfile = "/usr/local/etc/ntpsense/ssl/webui.pem"

accesslog.filename = "/var/log/lighttpd/access.log"

fastcgi.server = ( ".php" =>
    (( "socket" => "/var/run/php-fpm.sock",
       "broken-scriptfilename" => "enable"
    ))
)

mimetype.assign = (
    ".html" => "text/html",
    ".css"  => "text/css",
    ".js"   => "application/javascript",
    ".png"  => "image/png",
    ".woff" => "font/woff",
    ".woff2" => "font/woff2",
    ".ttf"  => "font/ttf"
)
LIGHTTPDEOF

mkdir -p /var/log/lighttpd
chown www:www /var/log/lighttpd

log "CHECKPOINT 12: lighttpd.conf generated"

sysrc lighttpd_enable=YES

if pkgtest_output=$(lighttpd -f /usr/local/etc/lighttpd/lighttpd.conf -tt 2>&1); then
    log "CHECKPOINT 12b: lighttpd.conf syntax valid"
else
    fatal "lighttpd.conf failed syntax check: ${pkgtest_output}"
fi

log "Setting up Web UI scaffold directories..."
mkdir -p /usr/local/www/ntpsense
mkdir -p /usr/local/etc/ntpsense/plugins
mkdir -p /usr/local/etc/pkg/repos

cat > /usr/local/etc/pkg/repos/ntpsense.conf << 'PKGREPOEOF'
ntpsense: {
    url: "https://pkg.ntpsense.example.com/${ABI}",
    enabled: no,
    signature_type: "none"
}
PKGREPOEOF
chmod 644 /usr/local/etc/pkg/repos/ntpsense.conf

log "CHECKPOINT 13: Web UI scaffold ready"

# ============================================================
# 14. ntpsense-configd binary - dari CD-ROM media, sama seperti v1.
# Kalau tidak ketemu (mis. testing tanpa ISO custom), PERINGATAN
# saja, bukan fatal - deploy manual pasca-install tetap didukung.
# ============================================================
# RCA KRITIS (ditemukan dari deploy nyata ke hardware fisik - mini PC
# 2-NIC via USB flashdisk): '/dev/cd0' HANYA ada untuk virtual CD-ROM
# (VMware dst). Di hardware fisik yang di-boot dari USB flashdisk
# (ditulis via dd), media instalasi biasanya muncul sebagai device
# DISK USB (/dev/da0, da1, dst), BUKAN /dev/cd0 - mount gagal SILENT
# (2>/dev/null menelan errornya) dan seluruh langkah copy ntpsense-
# configd/webui-ce.tar.gz TIDAK PERNAH terjadi tanpa pesan fatal yang
# jelas. Fix: coba BEBERAPA kandidat device berurutan sampai salah
# satu berhasil di-mount DAN genuinely berisi file yang kita cari -
# bukan asumsi satu nama device saja.
mkdir -p /mnt3
_media_mounted=0
_retry3=0
while [ ${_retry3} -lt 5 ] && [ "${_media_mounted}" != "1" ]; do
    for _dev in /dev/cd0 /dev/cd1 /dev/da0 /dev/da1 /dev/da2; do
        if [ -e "${_dev}" ] && mount -t cd9660 "${_dev}" /mnt3 2>/dev/null; then
            if [ -f /mnt3/root/ntpsense-configd ]; then
                log "Media instalasi ditemukan di ${_dev}"
                _media_mounted=1
                break
            else
                umount /mnt3 2>/dev/null || true
            fi
        fi
    done
    if [ "${_media_mounted}" != "1" ]; then
        _retry3=$((_retry3 + 1))
        log "Media instalasi belum siap (percobaan ${_retry3}/5), tunggu 2 detik..."
        sleep 2
    fi
done
if [ "${_media_mounted}" = "1" ]; then
    if [ -f /mnt3/root/ntpsense-configd ] && [ -f /mnt3/root/ntpsense_configd.rc ]; then
        cp /mnt3/root/ntpsense-configd /usr/local/sbin/ntpsense-configd
        chmod 755 /usr/local/sbin/ntpsense-configd
        chown root:wheel /usr/local/sbin/ntpsense-configd

        mkdir -p /usr/local/etc/rc.d
        cp /mnt3/root/ntpsense_configd.rc /usr/local/etc/rc.d/ntpsense_configd
        chmod 755 /usr/local/etc/rc.d/ntpsense_configd
        chown root:wheel /usr/local/etc/rc.d/ntpsense_configd

        sysrc ntpsense_configd_enable=YES

        # Kalau ISO JUGA menyertakan webui-ce.tar.gz, ekstrak otomatis
        # (dukungan untuk ISO custom lengkap, opsional - tidak fatal
        # kalau tidak ada, mis. testing tanpa ISO custom).
        if [ -f /mnt3/root/webui-ce.tar.gz ]; then
            log "Extracting webui-ce.tar.gz from install media..."
            tar -xzf /mnt3/root/webui-ce.tar.gz -C /usr/local/www/ntpsense/
            log "CHECKPOINT 14b: Web UI files extracted from media"
        else
            log "webui-ce.tar.gz not found on media - Web UI files must be deployed manually (scp/tar) before the site will work."
        fi

        service ntpsense_configd start
        log "CHECKPOINT 14: ntpsense-configd installed and started"
    else
        log "WARNING: ntpsense-configd binary/rc.d not found on media - service NOT installed. Deploy manually before use."
    fi
    umount /mnt3 2>/dev/null || true
else
    log "WARNING: could not find/mount install media on any candidate device (cd0/cd1/da0/da1/da2) - service NOT installed. Deploy manually via network (fetch/scp) before use."
fi

# ============================================================
# 15. Fix permission Web UI (kalau webui-ce.tar.gz baru saja
# diekstrak di atas, atau kalau admin deploy manual belakangan dan
# menjalankan ulang blok ini via 'sh install-gateway-2eth-v2.sh
# --fix-permissions-only' - lihat argumen di bagian akhir file).
# ============================================================
if [ -d /usr/local/www/ntpsense/public ]; then
    chown -R www:ntpsenseweb /usr/local/www/ntpsense
    find /usr/local/www/ntpsense -type d -exec chmod 750 {} \;
    find /usr/local/www/ntpsense -type f -name "*.php" -exec chmod 750 {} \;
    find /usr/local/www/ntpsense -type f \( -name "*.css" -o -name "*.js" -o -name "*.png" -o -name "*.woff*" -o -name "*.ttf" \) -exec chmod 640 {} \; 2>/dev/null || true
    log "CHECKPOINT 15: Web UI file permissions fixed (www:ntpsenseweb)"

    service lighttpd start
    log "CHECKPOINT 16: lighttpd started"
else
    log "Web UI files not present yet - skipping permission fix and lighttpd start. Deploy files manually, then run: sh $0 --fix-permissions-only"
fi

log "2eth v2 install complete: LAN1 (dual-purpose) + WAN1 + anti-lockout rule + swap + packages + ntpsenseweb group + webui bootstrap + ntpsense-configd + lighttpd/php-fpm (Unix socket) all configured."

# ============================================================
# 17. Trigger bootstrap akun admin Web UI - Auth::ensureBootstrapped()
# dipanggil LAZY saat halaman PERTAMA diakses (bukan saat install) -
# webui-admin.json BELUM ADA sampai ada request masuk. Panggil
# LANGSUNG via PHP CLI (BUKAN 'fetch' HTTPS) - RCA nyata (ditemukan
# dari test hardware fisik): 'fetch --no-verify-peer' ke sertifikat
# self-signed GAGAL DIAM-DIAM (exit non-zero yang di-'|| true'-kan),
# webui-admin.json tetap tidak pernah tercipta. Panggil PHP langsung
# sepenuhnya menghindari urusan SSL/sertifikat - jauh lebih reliable.
# ============================================================
log "Triggering Web UI first-boot bootstrap (creates default admin account)..."
php -r 'require "/usr/local/www/ntpsense/lib/Auth.php"; Auth::ensureBootstrapped();' 2>&1 || true
if [ -f /usr/local/etc/ntpsense/webui/webui-admin.json ]; then
    log "CHECKPOINT 17b: Web UI admin account bootstrapped"
    # RCA NYATA (ditemukan dari test end-to-end - ganti password Web UI
    # gagal 'Permission denied'): panggilan PHP CLI di atas jalan SEBAGAI
    # ROOT (script ini sendiri jalan sebagai root via rc.local), jadi
    # webui-admin.json yang tercipta ownership-nya root, BUKAN www -
    # PHP-FPM (jalan sebagai www) kemudian TIDAK BISA menulis ulang file
    # itu sendiri (ganti password, dst) meski dia member grup
    # ntpsenseweb yang benar di direktorinya. Fix: paksa ownership balik
    # ke www:ntpsenseweb SETELAH bootstrap, sebelum Web UI genuinely
    # dipakai pertama kali.
    chown www:ntpsenseweb /usr/local/etc/ntpsense/webui/webui-admin.json
    chmod 640 /usr/local/etc/ntpsense/webui/webui-admin.json
    log "CHECKPOINT 17c: webui-admin.json ownership dikoreksi ke www:ntpsenseweb"
else
    log "WARNING: webui-admin.json still not present after bootstrap trigger - console account sync (next step) will be skipped."
fi

# ============================================================
# 18. Deploy console menu scripts + sync akun OS OTOMATIS - supaya
# console SIAP PAKAI begitu instalasi selesai, tidak perlu satu pun
# langkah manual (permintaan user langsung).
# ============================================================
log "Deploying console menu scripts..."
mkdir -p /mnt4
_media4_found=0
_retry4=0
while [ ${_retry4} -lt 3 ] && [ ${_media4_found} -eq 0 ]; do
    if mount -t cd9660 /dev/cd0 /mnt4 2>/dev/null || mount -t cd9660 /dev/da0 /mnt4 2>/dev/null || mount -t cd9660 /dev/da1 /mnt4 2>/dev/null; then
        _media4_found=1
    else
        _retry4=$((_retry4 + 1))
        sleep 2
    fi
done
if [ ${_media4_found} -eq 1 ]; then
    if [ -f /mnt4/root/ntpsense-console-menu.sh ]; then
        cp /mnt4/root/ntpsense-console-menu.sh /usr/local/sbin/ntpsense-console-menu.sh
        chmod 755 /usr/local/sbin/ntpsense-console-menu.sh
    fi
    if [ -f /mnt4/root/ntpsense-sync-os-accounts.sh ]; then
        cp /mnt4/root/ntpsense-sync-os-accounts.sh /usr/local/sbin/ntpsense-sync-os-accounts.sh
        chmod 755 /usr/local/sbin/ntpsense-sync-os-accounts.sh
    fi
    if [ -f /mnt4/root/console-set-password.php ] && [ -d /usr/local/www/ntpsense/lib ]; then
        cp /mnt4/root/console-set-password.php /usr/local/www/ntpsense/lib/console-set-password.php
        chown www:ntpsenseweb /usr/local/www/ntpsense/lib/console-set-password.php
        chmod 750 /usr/local/www/ntpsense/lib/console-set-password.php
    fi
    umount /mnt4 2>/dev/null || true
    log "CHECKPOINT 18: console menu scripts deployed from media"
else
    log "WARNING: could not mount install media for console menu scripts - deploy manually later."
fi

if [ -x /usr/local/sbin/ntpsense-sync-os-accounts.sh ] && [ -f /usr/local/etc/ntpsense/webui/webui-admin.json ]; then
    log "Running initial console account sync..."
    sh /usr/local/sbin/ntpsense-sync-os-accounts.sh || log "WARNING: console account sync failed - run it manually later."
    log "CHECKPOINT 19: console accounts synced - Administrator can log in via SSH/console using the same Web UI password"

    # Set password OS awal untuk 'admin' SAMA dengan default Web UI
    # ("admin") - satu-satunya password yang genuinely KITA TAHU
    # nilainya di titik ini (bootstrap SELALU pakai default itu) -
    # supaya console juga langsung bisa dipakai tanpa 'passwd' manual,
    # konsisten permintaan "sekali install sudah OK semua".
    if pw usershow admin > /dev/null 2>&1; then
        printf 'admin' | pw usermod admin -h 0
        log "CHECKPOINT 19b: initial console password for 'admin' set to match Web UI default (admin/admin)"
    fi
else
    log "Console account sync skipped (scripts or webui-admin.json not ready) - run manually later:"
    log "  sh /usr/local/sbin/ntpsense-sync-os-accounts.sh"
fi

date > "${INSTALL_MARKER}"
log "CHECKPOINT 20: install marker written"
log ""
log "WEB UI ACCESS: https://${LAN1_GATEWAY_IP}/ from a device connected to ${LAN1_IF}"
log "Default login: admin / admin (you will be required to change the password on first login)"
log "CONSOLE/SSH ACCESS: same 'admin' / 'admin' credentials - console menu shows"
log "the full Administrator menu automatically."
