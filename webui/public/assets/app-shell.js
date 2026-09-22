(function () {
    'use strict';

    var COOKIE_NAME = 'ntpsense_sidebar_collapsed';
    var COOKIE_MAX_AGE_DAYS = 365;

    function setCookie(name, value) {
        var maxAge = COOKIE_MAX_AGE_DAYS * 24 * 60 * 60;
        document.cookie = name + '=' + value + '; path=/; max-age=' + maxAge + '; samesite=lax';
    }

    document.addEventListener('DOMContentLoaded', function () {
        var sidebar = document.getElementById('ntpSidebar');
        var btn = document.getElementById('ntpCollapseBtn');
        if (!sidebar || !btn) {
            return;
        }

        btn.addEventListener('click', function () {
            var isNarrow = window.matchMedia('(max-width: 900px)').matches;

            if (isNarrow) {
                // Di layar sempit, media query CSS yang biasanya memaksa
                // collapsed - tombol di sini berfungsi sebagai "buka
                // sementara" (force-expanded), BUKAN menyimpan preferensi
                // permanen ke cookie, supaya reload halaman berikutnya di
                // layar sempit tetap kembali ke default collapsed (bukan
                // kejebak dalam keadaan terbuka yang tidak muat).
                sidebar.classList.toggle('force-expanded');
                return;
            }

            var collapsed = sidebar.classList.toggle('collapsed');
            setCookie(COOKIE_NAME, collapsed ? '1' : '0');
        });
    });

    // Alert bell dropdown - klik di luar panel menutupnya. Toggle klik
    // pada tombol lonceng sendiri sudah ditangani via inline onclick di
    // layout_header.php (konsisten dengan pola tombol-tombol kecil lain
    // di project ini yang pakai inline onclick untuk aksi sederhana).
    //
    // RCA nyata (ditemukan bro langsung - badge tidak pernah hilang
    // meski sudah "dibuka/dibaca"): system.alerts_acknowledge sudah ada
    // di daemon dari awal, tapi TIDAK ADA satu pun tempat yang pernah
    // memanggilnya - fungsi global ini mengisi celah itu, dipanggil
    // LANGSUNG dari onclick tombol lonceng (bukan event listener
    // terpisah, supaya urutannya jelas: klik -> toggle panel -> kalau
    // baru DIBUKA, ack + sembunyikan badge).
    // RCA nyata KEDUA (ditemukan bro langsung - badge sempat hilang
    // tapi MUNCUL LAGI setelah klik salah satu item alert): fetch()
    // biasa itu ASYNCHRONOUS dan BISA DIBATALKAN BROWSER kalau halaman
    // keburu navigasi (persis skenario ini - admin buka lonceng, LANGSUNG
    // klik salah satu alert untuk investigasi) sebelum request ack
    // sempat terkirim tuntas ke server - ack-nya jadi tidak pernah
    // benar-benar tersimpan, jadi count penuh (atau sebagian) muncul
    // lagi di reload halaman berikutnya. navigator.sendBeacon() dibuat
    // KHUSUS untuk skenario "kirim lalu langsung pindah halaman" -
    // browser MENJAMIN request ini selesai terkirim, tidak akan
    // dibatalkan walau halaman langsung unload.
    window.ntpToggleAlertPanel = function () {
        var panel = document.getElementById('ntpAlertPanel');
        var badge = document.getElementById('ntpAlertBadge');
        if (!panel) {
            return;
        }
        var isOpening = !panel.classList.contains('open');
        panel.classList.toggle('open');
        if (!isOpening) {
            return; // ditutup, bukan dibuka - tidak perlu ack
        }
        // RCA nyata KETIGA (ditemukan bro langsung - teks alert hilang
        // SEKETIKA begitu panel dibuka, sebelum sempat diklik untuk
        // pindah ke tab tujuannya): versi sebelumnya mengosongkan isi
        // panel LANGSUNG saat dibuka - salah, karena admin justru butuh
        // teks & LINK itu tetap ada supaya bisa diklik untuk investigasi
        // (itu tujuan lonceng ini ada). Cuma ANGKA BADGE yang perlu
        // hilang optimis di sini - isi panel (daftar alert + link-nya)
        // TETAP UTUH sampai admin benar-benar pindah halaman sendiri.
        // Ack tetap terkirim di background (sendBeacon, andal walau
        // langsung navigasi) - pemuatan halaman BERIKUTNYA baru benar-
        // benar tidak menghitung alert yang sudah di-ack ini lagi,
        // karena system.alerts_summary cuma pernah mengembalikan yang
        // BELUM di-ack.
        if (badge) {
            badge.style.display = 'none';
        }
        if (navigator.sendBeacon) {
            navigator.sendBeacon('/alerts-ack.php');
        } else {
            fetch('/alerts-ack.php', { method: 'POST', credentials: 'same-origin', keepalive: true }).catch(function () {});
        }
    };

    document.addEventListener('click', function (event) {
        var panel = document.getElementById('ntpAlertPanel');
        var bell = document.getElementById('ntpAlertBell');
        if (!panel || !bell) {
            return;
        }
        if (!panel.classList.contains('open')) {
            return;
        }
        if (panel.contains(event.target) || bell.contains(event.target)) {
            return;
        }
        panel.classList.remove('open');
    });

    // Kolom tabel bisa di-drag resize - dipakai tabel dengan teks bebas/
    // panjang (mis. System Logs > Alerts) lewat class "ntp-table-resizable".
    // Reusable: cukup pasang class itu di <table> mana pun, tidak perlu
    // JS tambahan per halaman - fungsi ini otomatis jalan untuk SETIAP
    // tabel dengan class itu begitu halaman dimuat.
    function ntpInitResizableTables() {
        var tables = document.querySelectorAll('.ntp-table-resizable');
        tables.forEach(function (table) {
            var headerCells = table.querySelectorAll('thead th');
            headerCells.forEach(function (th, idx) {
                // Kolom TERAKHIR sengaja tidak dapat handle - menyisakan
                // sisa lebar mengalir alami ke situ, konsisten dengan pola
                // "kolom terakhir tidak butuh border-right" yang sudah
                // dipakai di tempat lain (.ntp-table-header-only th:last-child).
                if (idx === headerCells.length - 1) {
                    return;
                }
                var handle = document.createElement('span');
                handle.className = 'ntp-col-resize-handle';
                th.appendChild(handle);

                var startX = 0;
                var startWidth = 0;

                function onMouseMove(e) {
                    var delta = e.clientX - startX;
                    // 40px lebar minimum - cukup untuk header pendek macam
                    // "Time"/"Manage" tetap terbaca, mencegah admin tidak
                    // sengaja menyusutkan kolom sampai hilang total.
                    var newWidth = Math.max(40, startWidth + delta);
                    th.style.width = newWidth + 'px';
                }

                function onMouseUp() {
                    handle.classList.remove('resizing');
                    document.removeEventListener('mousemove', onMouseMove);
                    document.removeEventListener('mouseup', onMouseUp);
                }

                handle.addEventListener('mousedown', function (e) {
                    e.preventDefault();
                    startX = e.clientX;
                    startWidth = th.offsetWidth;
                    handle.classList.add('resizing');
                    document.addEventListener('mousemove', onMouseMove);
                    document.addEventListener('mouseup', onMouseUp);
                });
            });
        });
    }

    document.addEventListener('DOMContentLoaded', ntpInitResizableTables);

    // Filter search tabel - reusable (permintaan bro langsung: ke-13
    // tab System Logs butuh filter search). Input dengan
    // 'data-table-target="<id-tabel>"' otomatis menyaring baris tbody
    // tabel itu berdasarkan substring cocok DI MANA SAJA di baris
    // (case-insensitive) - client-side murni, tidak perlu round-trip
    // ke server, jadi terasa instan berapa pun panjang query-nya.
    function ntpInitTableSearch() {
        document.querySelectorAll('input[data-table-target]').forEach(function (input) {
            var tableId = input.getAttribute('data-table-target');
            var table = document.getElementById(tableId);
            if (!table) {
                return;
            }
            input.addEventListener('input', function () {
                var query = input.value.toLowerCase();
                var rows = table.querySelectorAll('tbody tr');
                rows.forEach(function (row) {
                    var text = row.textContent.toLowerCase();
                    row.style.display = text.includes(query) ? '' : 'none';
                });
            });
        });
    }

    document.addEventListener('DOMContentLoaded', ntpInitTableSearch);
})();
