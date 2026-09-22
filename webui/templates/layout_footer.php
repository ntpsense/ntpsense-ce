    </main>
  </div>

  <footer class="ntp-appfooter">
    <span>NTPSense InetGateway</span>
    <div class="ntp-appfooter-spacer"></div>
    <span>v0.1.0</span>
  </footer>

</div>
<?php $ntpAppShellJsVer = @filemtime(__DIR__ . '/../assets/app-shell.js') ?: time(); ?>
<script src="/assets/app-shell.js?v=<?= $ntpAppShellJsVer ?>"></script>
</body>
</html>
