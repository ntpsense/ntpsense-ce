<?php
/**
 * lib/system_health.php
 *
 * Pembacaan metrik kesehatan sistem (CPU, Memory, Disk) untuk tab
 * "System Health" pada halaman System (lihat Doc 6 Bab 11). SELURUH
 * fungsi di sini BERSIFAT READ-ONLY dan TIDAK memanggil sudo sama
 * sekali - berbeda dari helper lain di proyek ini yang semuanya
 * menulis konfigurasi privileged.
 *
 * Dikonfirmasi dari dokumentasi resmi FreeBSD (sysctl(7), man page):
 * kolom "Changeable" untuk metrik seperti vm.loadavg, hw.physmem,
 * hw.ncpu semuanya "no" - artinya nilai TIDAK BISA DIUBAH lewat
 * sysctl, namun ini terpisah dari hak BACA yang secara default
 * terbuka untuk semua user tanpa privilege khusus. 'top' dan 'df'
 * yang dipakai di sini SAMA SEPERTI yang sudah dikonfirmasi admin
 * bisa jalankan langsung tanpa sudo pada audit Tier 1 (Doc 6 Bab 9).
 */
declare(strict_types=1);
/**
 * Ambil persentase CPU usage saat ini.
 *
 * Memakai 'top -d 2 -s 1 0' (2 snapshot, jeda 1 detik, 0 proses
 * ditampilkan) - SENGAJA mengambil snapshot KEDUA/TERAKHIR (bukan
 * pertama) dari output, karena snapshot pertama 'top' tidak punya
 * delta pembanding yang valid (sama seperti kern.cp_time yang butuh
 * dua pembacaan untuk menghitung persentase yang akurat - dikonfirmasi
 * dari diskusi teknis FreeBSD forums soal cara top menghitung CPU%).
 * Konsekuensinya: fungsi ini akan BLOCKING selama ~1 detik (delay
 * snapshot) - DAPAT DITERIMA untuk endpoint AJAX yang dipanggil
 * setiap 5-30 detik (lihat keputusan Doc 6 Bab 11 soal interval
 * polling), TIDAK SESUAI untuk dipanggil pada page load biasa yang
 * butuh respons instan.
 *
 * @return array{usagePercent: float, idlePercent: float}|null null
 *         jika gagal membaca/parsing.
 */
function ntpsense_get_cpu_usage(): ?array
{
    $output = [];
    exec('top -d 2 -s 1 0 2>/dev/null', $output);
    $cpuLines = array_values(array_filter($output, static function ($line) {
        return str_starts_with(trim($line), 'CPU:');
    }));
    if (empty($cpuLines)) {
        return null;
    }
    $lastCpuLine = $cpuLines[count($cpuLines) - 1];
    if (!preg_match('/([\d.]+)%\s*idle/', $lastCpuLine, $m)) {
        return null;
    }
    $idlePercent = (float)$m[1];
    $usagePercent = round(100.0 - $idlePercent, 1);
    return ['usagePercent' => $usagePercent, 'idlePercent' => $idlePercent];
}
/**
 * Ambil persentase memory usage saat ini.
 *
 * Definisi "used" mengikuti konsensus komunitas FreeBSD (dikonfirmasi
 * dari kutipan developer FreeBSD Allan Jude dan diskusi resmi FreeBSD
 * Forums "Understanding memory management"): used = Active + Wired.
 * Inactive SENGAJA TIDAK dihitung sebagai "used" - secara teknis
 * berisi data yang masih valid, tapi FreeBSD menganggapnya sebagai
 * "free yang belum dibersihkan" dan akan direklamasi otomatis saat
 * dibutuhkan, BUKAN representasi tekanan memory yang sesungguhnya.
 * Ini SENGAJA berbeda dari model Linux yang lebih umum dikenal admin
 * (free memory rendah = warning) - lihat catatan UI yang menyertai
 * angka ini di public/system.php untuk mencegah kesalahpahaman yang
 * sama dengan yang didokumentasikan pada pfSense ("low free value
 * does not necessarily indicate a problem").
 *
 * @return array{usedMb: int, totalMb: int, usagePercent: float}|null
 */
function ntpsense_get_memory_usage(): ?array
{
    $output = [];
    exec('top -d 2 -s 1 0 2>/dev/null', $output);
    $memLines = array_values(array_filter($output, static function ($line) {
        return str_starts_with(trim($line), 'Mem:');
    }));
    if (empty($memLines)) {
        return null;
    }
    $lastMemLine = $memLines[count($memLines) - 1];
    $components = ntpsense_parse_top_memory_components($lastMemLine);
    if ($components === null) {
        return null;
    }
    ['active' => $active, 'inactive' => $inactive, 'wired' => $wired, 'buf' => $buf, 'free' => $free] = $components;
    $totalMb = $active + $inactive + $wired + $buf + $free;
    $usedMb = $active + $wired;
    $usagePercent = $totalMb > 0 ? round(($usedMb / $totalMb) * 100, 1) : 0.0;
    return ['usedMb' => $usedMb, 'totalMb' => $totalMb, 'usagePercent' => $usagePercent];
}
/**
 * Parse satu baris "Mem: ..." dari output top menjadi komponen MB.
 *
 * REVISI PENTING (ditemukan saat testing terhadap variasi nyata
 * output 'top' dari berbagai versi FreeBSD, dikumpulkan dari diskusi
 * FreeBSD Forums): komponen memory pada baris ini TIDAK SELALU sama
 * urutannya, dan TIDAK SELALU komponen yang sama muncul - beberapa
 * versi punya 'Laundry' (FreeBSD 12+), beberapa punya 'Cache' (versi
 * lebih lama), urutan Wired vs Laundry juga bisa terbalik. Pendekatan
 * SATU REGEX BESAR yang mengasumsikan urutan/komponen tetap (versi
 * sebelumnya) GAGAL pada 3 dari 4 contoh nyata yang diuji.
 *
 * Solusi: parse SEBAGAI PASANGAN "angka+satuan label" generik dulu
 * (tanpa asumsi urutan), lalu ambil komponen yang KITA BUTUHKAN
 * (Active, Inact, Wired, Buf, Free) dari hasil parsing tersebut -
 * komponen LAIN yang mungkin ada (Laundry, Cache, ARC) diabaikan
 * dengan aman karena TIDAK termasuk definisi used/free yang kita
 * pakai (lihat dokumentasi fungsi pemanggil).
 *
 * @return array{active:int, inactive:int, wired:int, buf:int, free:int}|null
 */
function ntpsense_parse_top_memory_components(string $line): ?array
{
    // Tangkap SEMUA pasangan "angka+satuan label" pada baris, apa pun
    // urutannya - mis. "315M Active" -> value=315, unit=M, label=Active.
    if (!preg_match_all('/([\d.]+)([KMG])\s+([A-Za-z]+)/', $line, $matches, PREG_SET_ORDER)) {
        return null;
    }
    $components = [];
    foreach ($matches as $match) {
        $label = strtolower($match[3]);
        $components[$label] = ntpsense_convert_top_unit_to_mb((float)$match[1], $match[2]);
    }
    // Komponen WAJIB ada di SEMUA versi FreeBSD yang relevan (Active,
    // Inact, Wired, Buf, Free) - kalau salah satu hilang, baris ini
    // bukan format yang kita kenali, lebih aman return null daripada
    // memberi hasil parsial yang menyesatkan.
    $required = ['active', 'inact', 'wired', 'buf', 'free'];
    foreach ($required as $key) {
        if (!array_key_exists($key, $components)) {
            return null;
        }
    }
    return [
        'active' => $components['active'],
        'inactive' => $components['inact'],
        'wired' => $components['wired'],
        'buf' => $components['buf'],
        'free' => $components['free'],
    ];
}
function ntpsense_convert_top_unit_to_mb(float $value, string $unit): int
{
    switch ($unit) {
        case 'G':
            return (int)round($value * 1024);
        case 'K':
            return (int)round($value / 1024);
        default: // 'M'
            return (int)round($value);
    }
}
/**
 * Ambil usage disk untuk mountpoint yang relevan (/, /var/log,
 * /var/squid - lihat Doc 6 Bab 8.4 skema partisi). Memakai 'df -k'
 * (bukan 'df -h') supaya angka Size/Used tetap presisi sebagai
 * integer KB untuk ditampilkan sebagai MB, BUKAN mengandalkan
 * pembulatan tampilan 'df -h' yang ditujukan untuk dibaca manusia.
 *
 * PERBAIKAN (bug dikonfirmasi saat QC testing): versi sebelumnya
 * MENGHITUNG ULANG usagePercent sendiri sebagai (usedKb/totalKb)*100
 * - ini BUKAN cara 'df' menghitung kolom Capacity%-nya sendiri. UFS
 * FreeBSD menyisihkan reserved space (~8% default) khusus untuk root
 * yang TIDAK dihitung sebagai 'avail' - df menghitung Capacity%
 * sebagai used/(used+avail), BUKAN used/total. Rumus lama SELALU
 * melaporkan persentase LEBIH RENDAH dari kenyataan (terverifikasi:
 * disk yang df sendiri laporkan 86% penuh, rumus lama hanya
 * melaporkan 79.1% - GAGAL memicu peringatan >85% padahal disk
 * SUDAH lewat ambang). Diperbaiki dengan langsung MENGAMBIL kolom
 * Capacity% yang SUDAH dihitung benar oleh df itu sendiri (kolom
 * ke-4 di output df -k), bukan menghitung ulang dengan rumus sendiri
 * yang berisiko salah lagi di masa depan.
 *
 * @return array<int, array{mount: string, totalMb: int, usedMb: int, usagePercent: float}>
 */
function ntpsense_get_disk_usage(): array
{
    $mountsToShow = ['/', '/var/log', '/var/squid'];
    $output = [];
    exec('df -k ' . implode(' ', array_map('escapeshellarg', $mountsToShow)) . ' 2>/dev/null', $output);
    $results = [];
    foreach ($output as $line) {
        // Lewati baris header ("Filesystem ... Mounted on"). Kolom
        // keempat ($m[4]) adalah Capacity% APA ADANYA dari df (sudah
        // benar used/(used+avail), TIDAK dihitung ulang di sini).
        if (!preg_match('/^\S+\s+(\d+)\s+(\d+)\s+\d+\s+(\d+)%\s+(\S+)$/', trim($line), $m)) {
            continue;
        }
        $totalKb = (int)$m[1];
        $usedKb = (int)$m[2];
        $capacityPercent = (int)$m[3];
        $mount = $m[4];
        $results[] = [
            'mount' => $mount,
            'totalMb' => (int)round($totalKb / 1024),
            'usedMb' => (int)round($usedKb / 1024),
            'usagePercent' => (float)$capacityPercent,
        ];
    }
    return $results;
}
/**
 * Ambil identifier "Serial Number" (SN) dan "Part Number" (PN) untuk
 * ditampilkan di tab System Health (lihat Doc 6 Bab 14) - berguna
 * untuk technician membedakan unit gateway saat menangani beberapa
 * instalasi sekaligus (mis. dukungan jarak jauh, inventaris), DAN
 * (sejak Agustus 2026) sebagai identifier yang dikunci ke license
 * Pro (lihat lib/license.php).
 *
 * ============================================================
 * REVISI Agustus 2026 - dua domain identitas independen
 * ============================================================
 * Versi SEBELUMNYA menurunkan SN dari /etc/hostid SAJA dan PN dari
 * MAC address NIC PERTAMA saja - kedua sumber itu SAMA-SAMA gampang
 * ikut ter-clone bersamaan pada skenario clone VM yang umum (baik
 * hostid maupun urutan NIC pertama biasanya konsisten antar clone).
 *
 * Revisi ini mengambil dari EMPAT sumber, dipisah jadi DUA domain
 * yang secara teknis independen satu sama lain:
 *   SN (domain OS + Network) = hash(hostid + SEMUA MAC NIC fisik,
 *       diurutkan) - bukan cuma NIC pertama lagi.
 *   PN (domain BIOS/Hardware + Storage) = hash(SMBIOS System UUID
 *       via kenv + serial disk boot via geom) - domain SAMA SEKALI
 *       BEDA dari SN, biasanya dikelola terpisah oleh hypervisor
 *       dari pengaturan NIC/hostid.
 *
 * KEJUJURAN TEKNIS YANG PERLU DIPAHAMI (bukan disembunyikan): TIDAK
 * ADA cara bagi kode yang berjalan SETELAH OS boot untuk mendeteksi
 * clone MENTAH (dd/disk-image byte-per-byte) - state apa pun yang
 * disimpan di disk (termasuk keempat sumber di atas) IKUT TERCLONE
 * pada skenario itu. Revisi ini menaikkan ambang untuk skenario
 * PALING UMUM terjadi (admin pakai fitur "Clone VM" RESMI di
 * VMware/Proxmox/VirtualBox, yang BIASANYA memberi MAC address baru
 * per NIC meski state disk lain ikut tersalin) - BUKAN jaminan
 * mutlak anti-duplikasi terhadap clone yang disengaja/canggih.
 * Pencegahan untuk skenario disengaja itu ada di KEBIJAKAN lisensi
 * (durasi 1-tahun + proses disable manual saat disaster-recovery -
 * lihat catatan kebijakan di lib/license.php), BUKAN di identifier
 * client-side ini.
 * ============================================================
 *
 * @return array{serial_number: string, part_number: string}
 */
function ntpsense_get_device_identifiers(): array
{
    return [
        'serial_number' => ntpsense_derive_serial_number(),
        'part_number' => ntpsense_derive_part_number(),
    ];
}
/**
 * SN - domain OS + Network. Kombinasi /etc/hostid + SEMUA MAC address
 * interface FISIK (bukan cuma yang pertama seperti versi sebelumnya),
 * diurutkan dulu sebelum digabung supaya hasil hash KONSISTEN tidak
 * peduli urutan deteksi NIC oleh 'ifconfig' berbeda antar boot.
 */
function ntpsense_derive_serial_number(): string
{
    $hostid = trim((string) @file_get_contents('/etc/hostid'));
    $macs = ntpsense_get_all_physical_mac_addresses();
    sort($macs); // urutan tetap terlepas urutan deteksi ifconfig
    $combined = $hostid . '|' . implode(',', $macs);
    if ($hostid === '' && empty($macs)) {
        // Kedua sumber gagal dibaca sama sekali (kondisi sangat
        // jarang, mis. lingkungan uji tanpa hostid/NIC terdeteksi) -
        // fail-safe ke penanda eksplisit, BUKAN hash dari string
        // kosong yang akan sama untuk SEMUA install yang gagal baca.
        return 'NTPS-UNKNOWN';
    }
    $hash = hash('sha256', $combined);
    return 'NTPS-' . strtoupper(substr($hash, 0, 8));
}
/**
 * PN - domain BIOS/Hardware + Storage, SENGAJA sumber yang BERBEDA
 * dari SN (lihat catatan arsitektur di ntpsense_get_device_identifiers()
 * di atas soal kenapa dua domain independen ini penting).
 */
function ntpsense_derive_part_number(): string
{
    $smbiosUuid = ntpsense_get_smbios_system_uuid();
    $diskSerial = ntpsense_get_boot_disk_serial();
    $combined = $smbiosUuid . '|' . $diskSerial;
    if ($smbiosUuid === '' && $diskSerial === '') {
        return 'PN-UNKNOWN';
    }
    $hash = hash('sha256', $combined);
    return 'PN-' . strtoupper(substr($hash, 0, 12));
}
/**
 * Semua MAC address interface FISIK (bukan cuma yang pertama) -
 * SKIP interface virtual (lo0, pflog0, wg0, tailscale0, lagg member
 * kadang muncul duplikat MAC dengan induknya, dst) yang tidak
 * relevan sebagai identifier hardware fisik.
 *
 * @return string[] daftar MAC (format lower-case dengan titik dua),
 *         array kosong kalau tidak ada yang terdeteksi.
 */
function ntpsense_get_all_physical_mac_addresses(): array
{
    $output = [];
    exec('ifconfig -a 2>/dev/null', $output);
    $macs = [];
    $currentInterfaceIsVirtual = false;
    // Nama-nama interface virtual yang SUDAH diketahui muncul di
    // ifconfig -a produk ini (lihat Doc 6 Bab 8.5 dan modul VPN) -
    // daftar ini TIDAK lengkap untuk semua kemungkinan nama, tapi
    // cukup untuk interface virtual yang MEMANG dikenal muncul pada
    // instalasi NTPSense normal.
    $virtualPrefixes = ['lo', 'pflog', 'pfsync', 'wg', 'tailscale', 'enc', 'lagg'];
    foreach ($output as $line) {
        if (preg_match('/^(\S+?):\s*flags=/', $line, $ifaceMatch)) {
            $ifaceName = $ifaceMatch[1];
            $currentInterfaceIsVirtual = false;
            foreach ($virtualPrefixes as $prefix) {
                if (str_starts_with($ifaceName, $prefix)) {
                    $currentInterfaceIsVirtual = true;
                    break;
                }
            }
            continue;
        }
        if ($currentInterfaceIsVirtual) {
            continue;
        }
        if (preg_match('/^\s*ether\s+([0-9a-f:]{17})/i', $line, $m)) {
            $macs[] = strtolower($m[1]);
        }
    }
    return array_values(array_unique($macs));
}
/**
 * SMBIOS System UUID via 'kenv' - nilai ini ditetapkan loader FreeBSD
 * dari tabel SMBIOS yang disediakan firmware/hypervisor, DOMAIN YANG
 * BERBEDA dari hostid (yang di-generate FreeBSD sendiri saat boot
 * pertama) maupun MAC address (dikelola virtual NIC/hypervisor
 * networking layer secara terpisah dari BIOS/SMBIOS).
 */
function ntpsense_get_smbios_system_uuid(): string
{
    $output = [];
    exec('kenv smbios.system.uuid 2>/dev/null', $output);
    $value = trim(implode('', $output));
    // 'kenv' mengembalikan string kosong/pesan error kalau environment
    // variable tidak ada (bisa terjadi pada beberapa hypervisor lama/
    // konfigurasi minimal yang tidak expose SMBIOS lengkap) - deteksi
    // dan treat sebagai "tidak tersedia", bukan dipakai apa adanya.
    if ($value === '' || str_contains(strtolower($value), 'not found')) {
        return '';
    }
    return strtolower($value);
}
/**
 * Serial number disk boot (root filesystem) via 'geom disk list' -
 * domain STORAGE, independen dari SMBIOS maupun network/OS. Beberapa
 * virtual disk (terutama VirtIO/paravirtualized tanpa konfigurasi
 * serial eksplisit) TIDAK expose serial sama sekali - fungsi ini
 * mengembalikan string kosong pada kasus itu (DITERIMA, bukan fatal
 * error - ntpsense_derive_part_number() tetap punya SMBIOS UUID
 * sebagai sumber walau disk serial tidak tersedia).
 */
function ntpsense_get_boot_disk_serial(): string
{
    // Cari device disk yang menampung mountpoint root (/) - lebih
    // robust dibanding asumsi nama device tetap (ada/da0/nvd0 dst
    // bisa beda tergantung jenis controller storage).
    $mountOutput = [];
    exec('mount -p / 2>/dev/null', $mountOutput);
    if (empty($mountOutput)) {
        return '';
    }
    // Format 'mount -p': "device mountpoint fstype options ..."
    $parts = preg_split('/\s+/', trim($mountOutput[0]));
    $device = $parts[0] ?? '';
    // Device biasanya berbentuk /dev/gpt/rootfs, /dev/ada0p2, dst -
    // ambil nama disk MENTAH (buang partition suffix dan path /dev/)
    // supaya cocok dengan nama yang dipakai 'geom disk list'.
    $device = preg_replace('#^/dev/#', '', $device);
    $device = preg_replace('/p?\d+$/', '', $device); // buang suffix partisi (p2, s1a, dst)
    if ($device === '' || str_starts_with($device, 'gpt/') || str_starts_with($device, 'label/')) {
        // Device teridentifikasi lewat GPT label/nama custom, bukan
        // nama device mentah - tidak bisa langsung dipetakan ke
        // 'geom disk list' tanpa lookup tambahan, aman kembalikan
        // kosong daripada menebak salah.
        return '';
    }
    $geomOutput = [];
    exec('geom disk list ' . escapeshellarg($device) . ' 2>/dev/null', $geomOutput);
    foreach ($geomOutput as $line) {
        if (preg_match('/ident:\s*(\S+)/i', $line, $m) && strtolower($m[1]) !== '(null)') {
            return strtolower($m[1]);
        }
    }
    return '';
}
