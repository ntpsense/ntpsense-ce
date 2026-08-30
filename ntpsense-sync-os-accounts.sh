#!/bin/sh
#
# ntpsense-sync-os-accounts.sh
# Sinkronkan akun Web UI (webui-admin.json) ke akun OS FreeBSD dengan
# shell TERKUNCI ke ntpsense-console-menu.sh - supaya login SSH/console
# pakai username Web UI langsung jatuh ke menu ter-filter sesuai role,
# BUKAN shell mentah /bin/sh.
#
# Dijalankan SEBAGAI ROOT - baik manual, maupun (nanti) otomatis dari
# ntpsense-configd setiap kali user Web UI dibuat/diedit/dihapus.
#
# Password OS DISINKRONKAN dengan password Web UI (pola sama persis
# dengan pfSense - satu password untuk console dan Web UI, bukan dua
# kredensial terpisah yang bisa lupa salah satu).
#
# CATATAN JUJUR: script ini PARSING JSON via grep/sed sederhana (BUKAN
# jq - sengaja hindari dependency baru, konsisten prinsip project ini),
# jadi ASUMSI struktur webui-admin.json tetap format yang sudah
# terverifikasi sebelumnya (satu objek user per baris logic sederhana).
# Kalau struktur JSON berubah signifikan nanti, script ini perlu
# disesuaikan.
#
set -e

WEBUI_ADMIN_JSON="/usr/local/etc/ntpsense/webui/webui-admin.json"
CONSOLE_ROLES_FILE="/usr/local/etc/ntpsense/console-roles.conf"
CONSOLE_MENU_SHELL="/usr/local/sbin/ntpsense-console-menu.sh"

log() {
    echo ">>> $1"
}

if [ "$(id -u)" != "0" ]; then
    echo "FATAL: script ini harus dijalankan sebagai root." >&2
    exit 1
fi

if [ ! -f "${WEBUI_ADMIN_JSON}" ]; then
    echo "FATAL: ${WEBUI_ADMIN_JSON} tidak ditemukan - belum ada akun Web UI ter-bootstrap." >&2
    exit 1
fi

if [ ! -x "${CONSOLE_MENU_SHELL}" ]; then
    echo "FATAL: ${CONSOLE_MENU_SHELL} tidak ditemukan/tidak executable - deploy dulu sebelum sync akun." >&2
    exit 1
fi

log "Membaca daftar user dari ${WEBUI_ADMIN_JSON}..."

# ------------------------------------------------------------------
# Ekstrak daftar username - format JSON webui-admin.json sudah
# terverifikasi: setiap user punya baris '"username": "xxx"' sendiri
# di dalam array "users". grep+sed lebih aman dibanding parser JSON
# custom yang rawan bug untuk kasus sesederhana ini.
# ------------------------------------------------------------------
USERNAMES=$(grep -o '"username": *"[^"]*"' "${WEBUI_ADMIN_JSON}" | sed 's/.*"username": *"\([^"]*\)"/\1/')

if [ -z "${USERNAMES}" ]; then
    log "Tidak ada user ditemukan di webui-admin.json - tidak ada yang disinkronkan."
    exit 0
fi

# ------------------------------------------------------------------
# Ekstrak mapping username -> role. Admin account (role hardcoded
# "Administrator" di Auth::ensureBootstrapped() - lihat webui-admin.json
# itu sendiri) VS user tambahan yang role-nya eksplisit di field
# terpisah - kedua bentuk perlu ditangani. Untuk MVP ini, asumsikan
# SETIAP entry user punya field "role" sendiri (termasuk "admin" yang
# selalu "Administrator") - konsisten dengan struktur yang sudah
# diverifikasi sebelumnya.
# ------------------------------------------------------------------
: > "${CONSOLE_ROLES_FILE}.tmp"

echo "${USERNAMES}" | while IFS= read -r username; do
    [ -z "${username}" ] && continue

    # Ambil role user ini - cari blok JSON antara kemunculan username
    # ini dan kemunculan "role" berikutnya (asumsi urutan field
    # username lalu role dalam SATU objek user, sesuai format yang
    # sudah diverifikasi).
    role=$(awk -v u="\"username\": \"${username}\"" '
        $0 ~ u { found=1 }
        found && /"role":/ {
            gsub(/.*"role": *"/, "");
            gsub(/".*/, "");
            print;
            exit
        }
    ' "${WEBUI_ADMIN_JSON}")

    if [ -z "${role}" ]; then
        role="Auditor"
        log "  PERINGATAN: role untuk '${username}' tidak ditemukan, default ke Auditor (paling terbatas, aman)."
    fi

    echo "${username}:${role}" >> "${CONSOLE_ROLES_FILE}.tmp"
    log "  ${username} -> role: ${role}"

    # ------------------------------------------------------------------
    # Buat/update akun OS - shell dikunci ke menu, BUKAN /bin/sh. User
    # role Administrator (selain root sendiri) JUGA dimasukkan grup
    # 'wheel' - RCA nyata (ditemukan dari test user): sysrc/ifconfig
    # butuh root, akun OS biasa tidak punya privilege itu, jadi command
    # privileged di menu console gagal 'Permission denied'. Grup
    # ntpsenseweb TETAP wajib juga (baca console-roles.conf +
    # webui-admin.json), keduanya bukan pengganti satu sama lain.
    # ------------------------------------------------------------------
    extra_groups="ntpsenseweb"
    if [ "${role}" = "Administrator" ]; then
        extra_groups="ntpsenseweb,wheel"
    fi

    if pw usershow "${username}" > /dev/null 2>&1; then
        pw usermod "${username}" -s "${CONSOLE_MENU_SHELL}" -G "${extra_groups}"
        log "    akun OS sudah ada, shell dipastikan terkunci ke menu, grup (${extra_groups}) dipastikan"
    else
        pw useradd "${username}" -m -s "${CONSOLE_MENU_SHELL}" -G "${extra_groups}" -c "NTPSense console user - role ${role}"
        log "    akun OS baru dibuat, shell terkunci ke menu, grup (${extra_groups}) ter-set"
        log "    PENTING: set password awal manual - 'passwd ${username}' - lalu instruksikan"
        log "    user ganti lewat Web UI (password OS TIDAK otomatis tersinkron dari hash"
        log "    bcrypt Web UI - format hash beda, sinkronisasi password perlu langkah terpisah)"
    fi
done

# ------------------------------------------------------------------
# Setup sudoers - grup 'wheel' dapat NOPASSWD ALL (Administrator role
# console = akses PENUH, konsisten semantik yang sama di Web UI -
# tidak ada RBAC granular tambahan di level sudo, kalau sudah
# Administrator ya genuinely full access). Idempotent - aman
# dijalankan berkali-kali (overwrite file yang sama, bukan append).
# ------------------------------------------------------------------
if ! command -v sudo > /dev/null 2>&1; then
    log "Package 'sudo' belum terinstall, menginstall..."
    ASSUME_ALWAYS_YES=yes pkg install -y sudo
fi

mkdir -p /usr/local/etc/sudoers.d
cat > /usr/local/etc/sudoers.d/ntpsense-console << 'SUDOERSEOF'
# AUTO-GENERATED oleh ntpsense-sync-os-accounts.sh - JANGAN edit manual.
# Grup 'wheel' (user role Administrator console) dapat sudo TANPA
# password - dipakai ntpsense-console-menu.sh untuk command privileged
# (sysrc, ifconfig, reboot, dst). Role Network Operator/Auditor TIDAK
# masuk grup wheel sama sekali, jadi TIDAK dapat sudo ini.
%wheel ALL=(ALL) NOPASSWD: ALL
SUDOERSEOF
chmod 440 /usr/local/etc/sudoers.d/ntpsense-console

if visudo -c -f /usr/local/etc/sudoers.d/ntpsense-console > /dev/null 2>&1; then
    log "sudoers untuk grup wheel (Administrator console) siap dan tervalidasi."
else
    log "PERINGATAN: validasi sudoers GAGAL - hapus /usr/local/etc/sudoers.d/ntpsense-console manual dan cek ulang!"
fi

mv "${CONSOLE_ROLES_FILE}.tmp" "${CONSOLE_ROLES_FILE}"
chmod 640 "${CONSOLE_ROLES_FILE}"
chown root:ntpsenseweb "${CONSOLE_ROLES_FILE}" 2>/dev/null || chown root:wheel "${CONSOLE_ROLES_FILE}"

log ""
log "Sinkronisasi selesai. Role lookup tersimpan di ${CONSOLE_ROLES_FILE}"
log ""
log "STATUS SINKRONISASI PASSWORD (update - fitur di bawah SUDAH SELESAI,"
log "bukan lagi roadmap):"
log "  - Web UI -> OS: OTOMATIS. Setiap kali user ganti password lewat"
log "    Web UI, Auth::changePassword() panggil action Rust"
log "    system.sync_os_password yang set hash OS juga (pola 'pw ... -h 0'"
log "    sama seperti root recovery token)."
log "  - Console -> Web UI: OTOMATIS juga, TAPI HANYA kalau ganti password"
log "    lewat menu console opsi 3 ('Change password'), BUKAN 'passwd'"
log "    mentah (itu operasi OS murni, di luar jangkauan hook kita tanpa"
log "    modifikasi PAM yang lebih berisiko)."
log "  - SATU pengecualian genuinely masih manual: akun OS BARU yang baru"
log "    saja dibuat sync ini belum PERNAH punya password valid sama"
log "    sekali (belum ada apa pun untuk disinkronkan) - WAJIB 'passwd"
log "    <username>' SEKALI di awal, setelah itu kedua arah otomatis."
