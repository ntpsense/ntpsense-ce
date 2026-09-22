<?php
declare(strict_types=1);
// Halaman ini SENGAJA tidak lewat Auth::requireLogin() - harus bisa
// dibuka dari halaman login itu sendiri (target="_blank"), sebelum
// user punya sesi sama sekali.
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>End User License Agreement - NTPSense InetGateway</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="/assets/app.css">
<style>
  .ntp-eula-wrap { max-width: 720px; margin: 40px auto; padding: 0 20px; font-family: sans-serif; color: #1b1f24; }
  .ntp-eula-wrap h1 { font-size: 22px; }
  .ntp-eula-wrap h2 { font-size: 16px; margin-top: 24px; }
  .ntp-eula-wrap p { font-size: 14px; line-height: 1.6; color: #374151; }
  .ntp-eula-wrap ul { font-size: 14px; line-height: 1.6; color: #374151; margin: 0 0 14px 20px; }
  .ntp-eula-wrap li { margin-bottom: 6px; }
  .ntp-eula-meta { font-size: 12px; color: #6b7280; margin-bottom: 20px; }
  .ntp-eula-more {
    margin-top: 28px; padding: 16px 18px; background: #f6f8fc; border-radius: 6px;
    border-left: 3px solid #ff6a1a;
  }
  .ntp-eula-more p { margin: 0 0 8px; font-size: 13px; }
  .ntp-eula-more a { color: #14213d; font-weight: 600; }
</style>
</head>
<body>
<div class="ntp-eula-wrap">
  <h1>NTPSense InetGateway - End User License Agreement</h1>
  <p class="ntp-eula-meta">Last updated: 19 August 2026</p>

  <h2>1. Acceptance of terms</h2>
  <p>By checking the box on the login page and signing in, you ("you," "the operator") agree to be bound by this End User License Agreement ("EULA") on behalf of yourself and, if applicable, the organization deploying this NTPSense InetGateway appliance ("NTPRO TEKNOLOGI JAYA, a Perseroan Perorangan (Indonesian single-shareholder limited liability company registered under Ministry of Law Decree No. AHU-A114329.AH.01.30.Tahun 2026)," "we," "us"). If you do not agree, do not check the box - you will not be able to sign in.</p>

  <h2>2. License grant — NTPSense Community Edition (CE)</h2>
  <p>The edition of NTPSense InetGateway installed on this appliance is <strong>Community Edition (CE)</strong>,
  free and open-source software licensed under the <strong>Apache License 2.0</strong>. Its complete source
  code — the Rust control daemon, this web interface, the installer, and the console tooling — is published at
  <a href="https://github.com/ntpsense/ntpsense-ce" target="_blank" rel="noopener">https://github.com/ntpsense/ntpsense-ce</a>, including the full
  <code>LICENSE</code> file. Apache 2.0 grants you broad rights to use, copy, modify, and redistribute this
  Software — including commercially, and including as part of a competing product — without needing separate
  permission from NTPRO TEKNOLOGI JAYA. Checking the box below and signing in does not restrict any right
  Apache 2.0 already grants you.</p>

  <h2>3. What this EULA does <em>not</em> restrict</h2>
  <p>Unlike a proprietary EULA, this page does not impose additional restrictions on resale, redistribution, or
  building competing products — Apache 2.0 alone governs those questions for CE, and it is intentionally
  permissive. This page exists specifically to cover Sections 4 and 5 below: security expectations and
  liability, which apply to <strong>any</strong> deployment of this Software regardless of license.</p>
  <p style="font-size:12px; color:#6b7280;"><em>Note: NTPSense Pro is licensed separately under a commercial
  EULA, not Apache 2.0 — see <a href="https://ntpsense.com/license.html" target="_blank" rel="noopener">ntpsense.com/license.html</a>
  if you are evaluating Pro.</em></p>

  <h2>4. Warranty disclaimer</h2>
  <p style="text-transform:uppercase; font-weight:600; font-size:13px;">The software is provided "as is" and "as available," without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, non-infringement, or that the software will be uninterrupted, error-free, or fully secure against all forms of intrusion, malware, or attack.</p>
  <p>NTPSense InetGateway is designed to reduce network risk - it is not a guarantee against it. No firewall, proxy, or VPN product can guarantee protection against every current or future threat, misconfiguration, zero-day vulnerability, or social-engineering attack. Security depends heavily on correct deployment, configuration, and ongoing maintenance by the operator - factors outside NTPSense's control once the Software leaves our hands.</p>
  <p>As the operator, you are responsible for correct configuration of firewall, VPN, DHCP, and proxy settings; keeping the Software and underlying operating system updated with security patches; physical and administrative security of the hardware; compliance with data protection law for any traffic passing through your deployment; and maintaining your own backups and incident response plan.</p>

  <h2>5. Limitation of liability</h2>
  <p>To the maximum extent permitted under the laws of the Republic of Indonesia:</p>
  <ul>
    <li>NTPRO TEKNOLOGI JAYA, its directors, officers, and employees will not be liable for any indirect, incidental, special, consequential, or punitive damages - including lost profits, lost data, business interruption, or the cost of remediating a security incident - arising from or related to use of the Software, even if advised of the possibility of such damages.</li>
    <li>Our total aggregate liability for any claim arising from the Software, however framed, will not exceed the amount you actually paid NTPRO TEKNOLOGI JAYA for the Software or hardware in the twelve (12) months preceding the claim. There is no minimum liability floor: for low-value transactions, the cap is simply the amount paid, however small.</li>
    <li>Any claim arising from the Software must be brought within twelve (12) months of the date the incident giving rise to the claim occurred, or is permanently barred.</li>
    <li>You agree to indemnify and hold harmless NTPRO TEKNOLOGI JAYA, its directors, and its employees from any claim, loss, or damage arising from your misuse or misconfiguration of the Software, your violation of applicable law in how you deploy it, or any content or traffic that passes through a network you operate using it.</li>
    <li>Nothing in this section excludes liability that cannot be lawfully excluded, including liability for willful misconduct or gross negligence directly attributable to NTPRO TEKNOLOGI JAYA.</li>
  </ul>
  <p>This License is governed by the laws of the Republic of Indonesia, with exclusive jurisdiction in the courts of Jakarta, unless superseded by a separately signed commercial agreement.</p>

  <div class="ntp-eula-more">
    <p><strong>This page is a condensed summary.</strong> For the complete legal documentation - including our Privacy Policy (UU PDP compliance), full Terms of Service, and Open Source license notices (Squid/GPL, WireGuard, FreeBSD, and other bundled components) - see:</p>
    <p><a href="https://ntpsense.com/privacy.html" target="_blank" rel="noopener">Privacy Policy</a> &nbsp;·&nbsp;
       <a href="https://ntpsense.com/terms.html" target="_blank" rel="noopener">Terms of Service</a> &nbsp;·&nbsp;
       <a href="https://ntpsense.com/license.html" target="_blank" rel="noopener">Full Software License</a> &nbsp;·&nbsp;
       <a href="https://ntpsense.com/open-source.html" target="_blank" rel="noopener">Open Source Notices</a></p>
  </div>

  <p style="margin-top:24px;"><a href="/login.php">&larr; Back to login</a></p>
</div>
</body>
</html>
