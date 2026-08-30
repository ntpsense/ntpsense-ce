#!/bin/sh
#
# ntpsense-console-menu.sh
# NTPSense InetGateway CE main console menu - installed as LOGIN SHELL
# for OS accounts synced from Web UI (see ntpsense-sync-os-accounts.sh)
# - when the user logs in (physical console or SSH), this script runs
# instead of a normal shell. Menu is filtered by the Web UI role
# (Administrator/Network Operator/Auditor) read from
# /usr/local/etc/ntpsense/console-roles.conf.
#
# Riset dulu sebelum desain (pfSense console menu, 5 vendor rujukan
# RBAC CLI vs GUI) - lihat catatan lengkap keputusan desain di
# percakapan dengan user (bukan diulang di sini supaya tidak makin
# panjang file-nya).
#
# CATATAN BAHASA (permintaan user langsung): SEMUA teks yang tampil ke
# layar (echo/printf) pakai BAHASA INGGRIS - konsisten dengan Web UI
# yang sudah full English. Komentar kode TETAP Bahasa Indonesia -
# ikuti konvensi dokumentasi internal project ini di semua file lain.
#
# CATATAN PRIVILEGE (RCA nyata - 'sysrc'/'ifconfig' gagal 'Permission
# denied' waktu dites user role Administrator NON-root, mis. akun
# 'admin'): user OS biasa TIDAK punya privilege root untuk command
# sistem. Fix: user role Administrator (selain root sendiri)
# dimasukkan ke grup 'wheel' + sudoers NOPASSWD khusus grup itu (lihat
# ntpsense-sync-os-accounts.sh) - command privileged di sini di-prefix
# 'sudo' otomatis KECUALI kalau memang sudah login sebagai root
# (root tidak perlu sudo sama sekali).
#
set -e

CONSOLE_ROLES_FILE="/usr/local/etc/ntpsense/console-roles.conf"
PF_CONF="/etc/pf.conf"
MGMT_LOCK_FILE="/usr/local/etc/ntpsense/mgmt-interface.lock"

CURRENT_USER=$(id -un)

# ------------------------------------------------------------------
# Tentukan role user ini. 'root' dan 'admin' SELALU Administrator -
# pertahanan berlapis (konsisten proteksi 'admin' yang sudah ada di
# Web UI: tidak bisa dihapus/diganti role) - mencegah kegagalan lain
# (file permission, sync belum jalan, dst) diam-diam mengunci akun
# paling penting ini jadi Auditor.
# ------------------------------------------------------------------
if [ "${CURRENT_USER}" = "root" ] || [ "${CURRENT_USER}" = "admin" ]; then
    ROLE="Administrator"
elif [ -f "${CONSOLE_ROLES_FILE}" ]; then
    ROLE=$(grep "^${CURRENT_USER}:" "${CONSOLE_ROLES_FILE}" | cut -d: -f2)
    if [ -z "${ROLE}" ]; then
        ROLE="Auditor"
    fi
else
    ROLE="Auditor"
fi

# ------------------------------------------------------------------
# Prefix sudo untuk command privileged - kosong kalau sudah root
# (root tidak perlu sudo), 'sudo' untuk user lain (grup wheel +
# sudoers NOPASSWD sudah di-setup ntpsense-sync-os-accounts.sh untuk
# role Administrator).
# ------------------------------------------------------------------
if [ "${CURRENT_USER}" = "root" ]; then
    SUDO=""
else
    SUDO="sudo"
fi

# ------------------------------------------------------------------
# Deteksi apakah sesi ini SSH atau console lokal.
# ------------------------------------------------------------------
IS_SSH=0
if [ -n "${SSH_TTY:-}" ] || [ -n "${SSH_CONNECTION:-}" ]; then
    IS_SSH=1
fi

# ------------------------------------------------------------------
# Cek permission per opsi menu berdasar role.
# ------------------------------------------------------------------
option_allowed() {
    opt="$1"
    case "${ROLE}" in
        Administrator)
            return 0
            ;;
        "Network Operator")
            case "${opt}" in
                0|1|2|7|9|10|16) return 0 ;;
                *) return 1 ;;
            esac
            ;;
        Auditor)
            case "${opt}" in
                0|7|9|10|16) return 0 ;;
                *) return 1 ;;
            esac
            ;;
        *)
            case "${opt}" in
                0|7|9|10|16) return 0 ;;
                *) return 1 ;;
            esac
            ;;
    esac
}

OPTION_LABELS_0="Logout (SSH only)"
OPTION_LABELS_1="Assign Interfaces"
OPTION_LABELS_2="Set interface IP address"
OPTION_LABELS_3="Change password (Web UI + OS)"
OPTION_LABELS_4="Reset to factory defaults"
OPTION_LABELS_5="Reboot system"
OPTION_LABELS_6="Halt system"
OPTION_LABELS_7="Ping host"
OPTION_LABELS_8="Shell"
OPTION_LABELS_9="Show CPU / Memory / Disk usage"
OPTION_LABELS_10="Show Firewall log"
OPTION_LABELS_11="Restart Web UI (lighttpd+php-fpm)"
OPTION_LABELS_12="Restart ntpsense-configd"
OPTION_LABELS_13="Update packages (pkg upgrade)"
OPTION_LABELS_14="Disable Secure Shell (sshd)"
OPTION_LABELS_15="Restore configuration backup"
OPTION_LABELS_16="Show system information"

get_label() {
    eval "echo \"\${OPTION_LABELS_$1}\""
}

extract_pf_macro() {
    grep "^$1 = " "${PF_CONF}" 2>/dev/null | sed 's/^[a-z0-9_]* = "\(.*\)"$/\1/'
}

LAN1_IF=$(extract_pf_macro "lan1_if")
WAN1_IF=$(extract_pf_macro "wan1_if")
MGMT_IF=""
if [ -f "${MGMT_LOCK_FILE}" ]; then
    MGMT_IF=$(cat "${MGMT_LOCK_FILE}" 2>/dev/null | tr -d '[:space:]')
fi

get_iface_ip() {
    ifconfig "$1" 2>/dev/null | awk '/inet /{print $2; exit}'
}

print_interface_summary() {
    if [ -n "${MGMT_IF}" ]; then
        mgmt_ip=$(get_iface_ip "${MGMT_IF}")
        printf "  MGMT (%s)  -> %s\n" "${MGMT_IF}" "${mgmt_ip:-not configured}"
    fi
    if [ -n "${LAN1_IF}" ]; then
        lan1_ip=$(get_iface_ip "${LAN1_IF}")
        printf "  LAN1 (%s)  -> %s\n" "${LAN1_IF}" "${lan1_ip:-not configured}"
    fi
    if [ -n "${WAN1_IF}" ]; then
        wan1_ip=$(get_iface_ip "${WAN1_IF}")
        printf "  WAN1 (%s)  -> %s\n" "${WAN1_IF}" "${wan1_ip:-not configured}"
    fi
}

render_menu() {
    clear
    echo "*** NTPSense InetGateway CE ***"
    if [ "${CURRENT_USER}" != "root" ]; then
        echo "*** Logged in as: ${CURRENT_USER} (role: ${ROLE}) ***"
    fi
    echo ""
    print_interface_summary
    echo ""

    i=0
    while [ ${i} -le 8 ]; do
        right_i=$((i + 9))
        left_text=""
        right_text=""
        if option_allowed "${i}"; then
            left_text=$(printf "%2d) %s" "${i}" "$(get_label "${i}")")
        fi
        if [ ${right_i} -le 16 ] && option_allowed "${right_i}"; then
            right_text=$(printf "%2d) %s" "${right_i}" "$(get_label "${right_i}")")
        fi
        printf "%-33s%s\n" "${left_text}" "${right_text}"
        i=$((i + 1))
    done
    echo ""
}

action_logout() {
    echo "Logging out..."
    exit 0
}

action_assign_interfaces() {
    echo "Detected interfaces:"
    ifconfig -l
    echo ""
    echo "To reassign LAN1/WAN1, re-run the installer:"
    echo "  ${SUDO} sh /usr/local/sbin/install-gateway-2eth-v2.sh"
    echo "(WARNING: this resets network configuration - back up via Web UI first)"
}

action_set_interface_ip() {
    echo "Available interfaces:"
    ifconfig -l
    printf "Interface to change: "
    read -r target_if
    printf "New IP (CIDR format, e.g. 10.252.1.100/24): "
    read -r new_ip
    if [ -z "${target_if}" ] || [ -z "${new_ip}" ]; then
        echo "Cancelled - empty input."
        return
    fi
    printf "Confirm: set %s to %s? (y/N): " "${target_if}" "${new_ip}"
    read -r confirm
    if [ "${confirm}" = "y" ] || [ "${confirm}" = "Y" ]; then
        ${SUDO} sysrc "ifconfig_${target_if}=inet ${new_ip}"
        ${SUDO} ifconfig "${target_if}" inet "${new_ip}"
        echo "IP changed. Restart Web UI (option 11) if lighttpd needs to rebind."
    else
        echo "Cancelled."
    fi
}

action_change_password() {
    printf "Web UI username to change password for [%s]: " "${CURRENT_USER}"
    read -r target_user
    if [ -z "${target_user}" ]; then
        target_user="${CURRENT_USER}"
    fi

    printf "New password (min. 8 characters): "
    stty -echo
    read -r new_password
    stty echo
    echo ""
    printf "Confirm new password: "
    stty -echo
    read -r confirm_password
    stty echo
    echo ""

    if [ "${new_password}" != "${confirm_password}" ]; then
        echo "FAILED - password and confirmation do not match."
        return
    fi
    if [ ${#new_password} -lt 8 ]; then
        echo "FAILED - password must be at least 8 characters."
        return
    fi

    php_result=$(printf '%s' "${new_password}" | php /usr/local/www/ntpsense/lib/console-set-password.php "${target_user}" 2>&1)
    if ! echo "${php_result}" | grep -q "^OK$"; then
        echo "FAILED to update Web UI: ${php_result}"
        return
    fi
    echo "Web UI password for '${target_user}' updated successfully."

    if pw usershow "${target_user}" > /dev/null 2>&1; then
        printf '%s' "${new_password}" | ${SUDO} pw usermod "${target_user}" -h 0
        echo "OS password for '${target_user}' updated too - both sides in sync."
    else
        echo "(No OS account for '${target_user}' yet - run ntpsense-sync-os-accounts.sh"
        echo " first if this user needs console/SSH access.)"
    fi
}

action_factory_reset() {
    echo "!!! WARNING: this will ERASE ALL configuration !!!"
    printf "Type 'FACTORY RESET' exactly (uppercase) to confirm: "
    read -r confirm
    if [ "${confirm}" = "FACTORY RESET" ]; then
        ${SUDO} rm -f /var/db/ntpsense-install-complete
        echo "Install marker removed. Reboot now to re-run the installer from scratch."
        printf "Reboot now? (y/N): "
        read -r do_reboot
        if [ "${do_reboot}" = "y" ] || [ "${do_reboot}" = "Y" ]; then
            ${SUDO} reboot
        fi
    else
        echo "Cancelled - confirmation text did not match."
    fi
}

action_reboot() {
    printf "Reboot the system now? (y/N): "
    read -r confirm
    if [ "${confirm}" = "y" ] || [ "${confirm}" = "Y" ]; then
        ${SUDO} reboot
    fi
}

action_halt() {
    printf "Halt the system now? (y/N): "
    read -r confirm
    if [ "${confirm}" = "y" ] || [ "${confirm}" = "Y" ]; then
        ${SUDO} halt -p
    fi
}

action_ping() {
    printf "Target host/IP: "
    read -r target
    if [ -z "${target}" ]; then
        echo "Cancelled - empty input."
        return
    fi
    ping -c 5 "${target}"
}

action_shell() {
    echo "Entering a regular FreeBSD shell. Type 'exit' to return to this menu."
    if [ "${CURRENT_USER}" = "root" ]; then
        /bin/sh
    else
        ${SUDO} /bin/sh
    fi
}

action_system_usage() {
    echo "--- CPU per-core ---"
    top -b -P -n 1 | grep "^CPU"
    echo ""
    echo "--- Memory ---"
    top -b -n 1 | grep "^Mem:"
    echo ""
    echo "--- Swap ---"
    swapinfo -h 2>/dev/null || echo "(swap not active)"
    echo ""
    echo "--- Disk ---"
    df -h
}

action_firewall_log() {
    echo "Last 20 lines of the firewall log (pflog):"
    ${SUDO} tcpdump -n -e -ttt -r /var/log/pflog 2>/dev/null | tail -20
}

action_restart_webui() {
    echo "Restarting lighttpd + php-fpm..."
    ${SUDO} service php_fpm restart
    ${SUDO} service lighttpd restart
    echo "Done."
}

action_restart_daemon() {
    echo "Restarting ntpsense-configd..."
    ${SUDO} service ntpsense_configd restart
    echo "Done."
}

action_update_packages() {
    echo "Running pkg upgrade..."
    ${SUDO} pkg upgrade
}

action_disable_sshd() {
    echo "!!! WARNING: this will DISABLE SSH access completely !!!"
    echo "Future access will ONLY be possible via Web UI or a direct physical console."
    printf "Confirm? (y/N): "
    read -r confirm
    if [ "${confirm}" = "y" ] || [ "${confirm}" = "Y" ]; then
        ${SUDO} sysrc sshd_enable=NO
        ${SUDO} service sshd stop
        echo "SSH disabled."
    else
        echo "Cancelled."
    fi
}

action_restore_backup() {
    echo "Restoring a configuration backup must be done via the Web UI"
    echo "(System > Backup & Restore) - it needs a file upload, which isn't"
    echo "practical from the console. Go to https://<LAN1-IP>/system.php"
}

action_system_info() {
    echo "Hostname       : $(hostname)"
    echo "FreeBSD version: $(freebsd-version)"
    echo "Uptime         : $(uptime)"
    echo "CPU model      : $(sysctl -n hw.model)"
    echo "CPU cores      : $(sysctl -n hw.ncpu)"
}

dispatch_action() {
    opt="$1"
    if ! option_allowed "${opt}"; then
        echo "This option is not available for your role (${ROLE})."
        return
    fi
    case "${opt}" in
        0) action_logout ;;
        1) action_assign_interfaces ;;
        2) action_set_interface_ip ;;
        3) action_change_password ;;
        4) action_factory_reset ;;
        5) action_reboot ;;
        6) action_halt ;;
        7) action_ping ;;
        8) action_shell ;;
        9) action_system_usage ;;
        10) action_firewall_log ;;
        11) action_restart_webui ;;
        12) action_restart_daemon ;;
        13) action_update_packages ;;
        14) action_disable_sshd ;;
        15) action_restore_backup ;;
        16) action_system_info ;;
        *) echo "Unknown option." ;;
    esac
}

while true; do
    render_menu
    printf "Enter an option: "
    read -r choice
    echo ""
    case "${choice}" in
        ''|*[!0-9]*)
            echo "Invalid input - enter a number 0-16."
            ;;
        *)
            if [ "${choice}" -ge 0 ] && [ "${choice}" -le 16 ]; then
                dispatch_action "${choice}"
            else
                echo "Option out of range (0-16)."
            fi
            ;;
    esac
    echo ""
    printf "Press Enter to return to the menu..."
    read -r _
done
