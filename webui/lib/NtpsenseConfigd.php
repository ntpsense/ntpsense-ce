<?php
declare(strict_types=1);

/**
 * NtpsenseConfigd - PHP client for ntpsense-configd (privileged Rust daemon).
 *
 * Implementation follows the IPC spec exactly:
 *   - Unix domain socket, one-shot per request (connect -> 1 JSON line ->
 *     1 reply line -> close), NOT persistent/multiplexed.
 *   - NDJSON: one JSON object per line, request_id for tracing.
 *   - Peer credentials are verified on the DAEMON side (Rust), not here -
 *     if PHP-FPM isn't running as root or a member of the 'ntpsenseweb'
 *     group, the daemon will silently REJECT (close the connection with
 *     no response at all, fail-closed). This class detects that condition
 *     explicitly with a clear error message rather than a silent failure -
 *     but see the timeout note below: an empty response can ALSO happen
 *     if the daemon was simply slow (e.g. mid-way through a service
 *     restart with several subprocess calls) rather than actively
 *     rejecting the connection - the two are distinguished via
 *     stream_get_meta_data()['timed_out'].
 */
final class NtpsenseConfigdException extends \RuntimeException
{
}

final class NtpsenseConfigd
{
    private string $socketPath;
    private float $timeoutSeconds;

    public function __construct(
        string $socketPath = '/var/run/ntpsense-configd.sock',
        // 15s default (bukan 5s) - beberapa action (mis. proxy.set_config,
        // network.set_dhcp_config) menjalankan beberapa subprocess
        // berurutan (validasi config, restart service, verifikasi status)
        // yang bisa makan waktu nyata beberapa detik - 5s TERBUKTI terlalu
        // pendek dan menyebabkan false-positive "fail-closed" padahal
        // daemon cuma lagi sibuk, bukan menolak.
        float $timeoutSeconds = 15.0
    ) {
        $this->socketPath = $socketPath;
        $this->timeoutSeconds = $timeoutSeconds;
    }

    /**
     * @param array<string, mixed> $params
     * @param float|null $timeoutOverride Pakai timeout LEBIH PANJANG dari
     *   default untuk action yang DIKETAHUI berat (mis. proxy.blocklist_update
     *   - download+proses ratusan ribu baris domain, bisa genuinely >15s,
     *     BUKAN indikasi daemon macet). null = pakai default constructor.
     * @return array<string, mixed>
     * @throws NtpsenseConfigdException
     */
    public function call(string $action, array $params = [], ?float $timeoutOverride = null): array
    {
        $timeout = $timeoutOverride ?? $this->timeoutSeconds;
        $requestId = bin2hex(random_bytes(8));
        $request = [
            'request_id' => $requestId,
            'action' => $action,
            // (object) cast so empty params encode as '{}', NOT '[]' -
            // ntpsense-configd (serde_json::Value) can parse either, but
            // '{}' is semantically correct for a params object.
            'params' => (object) $params,
        ];

        $line = json_encode($request, JSON_UNESCAPED_SLASHES);
        if ($line === false) {
            throw new NtpsenseConfigdException(
                'Failed to encode request JSON: ' . json_last_error_msg()
            );
        }

        $errno = 0;
        $errstr = '';
        $socket = @stream_socket_client(
            'unix://' . $this->socketPath,
            $errno,
            $errstr,
            $timeout
        );

        if ($socket === false) {
            throw new NtpsenseConfigdException(
                "Failed to connect to ntpsense-configd ({$this->socketPath}): "
                . "[{$errno}] {$errstr}. Check whether the ntpsense_configd "
                . "service is running ('service ntpsense_configd status')."
            );
        }

        stream_set_timeout($socket, (int) ceil($timeout));

        if (fwrite($socket, $line . "\n") === false) {
            fclose($socket);
            throw new NtpsenseConfigdException('Failed to write request to socket.');
        }

        // RCA #1 (Firewall Log Viewer & DHCP Log Viewer gagal parse JSON,
        // response TERPOTONG persis di tengah string): fgets($socket,
        // 65536) membatasi baca ke MAKSIMAL 64KB per panggilan, TIDAK
        // PEDULI newline penutup baris sudah ditemukan atau belum -
        // response NDJSON manapun yang lebih panjang dari 64KB (mis. 500
        // entry firewall log) langsung terpotong di batas itu.
        //
        // RCA #2 (koreksi atas fix PERTAMA saya sendiri - fix itu SENDIRI
        // ternyata salah): sempat diganti ke
        // stream_get_line($socket, 0, "\n") dengan asumsi panjang 0
        // berarti "tanpa batas". SALAH - dikonfirmasi dari dokumentasi
        // resmi PHP, panjang 0 di stream_get_line() berarti "default
        // socket chunk size, i.e. 8192 bytes" - JUSTRU LEBIH KECIL dari
        // batas fgets(65536) yang coba diperbaiki. Pelajaran: seharusnya
        // verifikasi ke dokumentasi resmi dulu sebelum yakin, bukan
        // mengandalkan ingatan - disiplin yang sama yang sudah dipegang
        // di seluruh project ini untuk hal lain, sekarang diterapkan ke
        // diri sendiri.
        //
        // Fix final yang genuinely tidak terbatas: loop baca manual pakai
        // fread() per potongan (8KB per baca, jumlah baca tidak dibatasi),
        // digabung terus sampai newline BENAR-BENAR ditemukan di buffer -
        // tidak bergantung pada satu angka yang ditebak di awal, berapa
        // pun panjang response-nya.
        $response = '';
        $chunkSize = 8192;
        while (!feof($socket)) {
            $chunk = fread($socket, $chunkSize);
            if ($chunk === false) {
                break;
            }
            if ($chunk === '') {
                $meta = stream_get_meta_data($socket);
                if (!empty($meta['timed_out'])) {
                    break;
                }
                continue;
            }
            $response .= $chunk;
            if (str_contains($response, "\n")) {
                break;
            }
        }
        $newlinePos = strpos($response, "\n");
        if ($newlinePos !== false) {
            $response = substr($response, 0, $newlinePos);
        }
        $meta = stream_get_meta_data($socket);
        fclose($socket);

        if ($response === false || $response === '') {
            if (!empty($meta['timed_out'])) {
                // Koneksi diterima, tapi daemon tidak menjawab dalam batas
                // waktu - ini KEMUNGKINAN BESAR daemon sedang sibuk
                // menjalankan action yang lambat (restart service, dst),
                // BUKAN penolakan fail-closed. Beri saran yang sesuai:
                // tunggu sebentar lalu coba lagi, jangan langsung curiga
                // masalah permission.
                throw new NtpsenseConfigdException(
                    "No response from ntpsense-configd within {$timeout}s "
                    . '- the daemon may still be busy completing a slow operation '
                    . '(e.g. restarting a service). Wait a moment and try again '
                    . 'before assuming a permission issue.'
                );
            }
            // Koneksi DITUTUP SEGERA tanpa respons dan tanpa timeout - ini
            // pola KHAS penolakan fail-closed (peer credential ditolak),
            // BUKAN error JSON biasa dan BUKAN timeout.
            throw new NtpsenseConfigdException(
                'No response from ntpsense-configd (connection closed immediately) '
                . '- likely rejected fail-closed because this PHP-FPM process is not '
                . "running as root or a member of the ntpsenseweb group. Check: "
                . "'id' for the PHP-FPM process and 'pw groupshow ntpsenseweb'."
            );
        }

        $decoded = json_decode($response, true);
        if (!is_array($decoded)) {
            throw new NtpsenseConfigdException(
                'ntpsense-configd response is not valid JSON (length='
                . strlen($response) . '): '
                . substr($response, 0, 200)
            );
        }

        if (($decoded['status'] ?? null) === 'error') {
            $code = $decoded['error']['code'] ?? 'UNKNOWN_ERROR';
            $message = $decoded['error']['message'] ?? 'No error detail provided';
            throw new NtpsenseConfigdException("ntpsense-configd error [{$code}]: {$message}");
        }

        return is_array($decoded['data'] ?? null) ? $decoded['data'] : [];
    }
}
