-- gfx-hexagon.lua
-- Logo boot loader custom NTPSense InetGateway CE (posisi KANAN) -
-- heksagon dengan teks "NTP" (biru) + "sense" (kuning, pengganti
-- oranye - loader cuma dukung 8 warna ANSI dasar, tidak ada oranye
-- asli, dikonfirmasi langsung dari source /boot/lua/color.lua di
-- FreeBSD-Build, BUKAN tebakan). requires_color=true supaya loader
-- otomatis fallback ke logo default kalau console tidak dukung warna
-- (mis. serial console polos) - graceful degradation, bukan tampil
-- rusak berantakan kode escape ANSI mentah.

local color = require("color")

local hexagon_logo = {
	"      _________",
	"     /         \\",
	"    /           \\",
	"   /    " .. color.escapefg(color.BLUE) .. "NTP" .. color.resetfg() .. "      \\",
	"   \\    " .. color.escapefg(color.YELLOW) .. "sense" .. color.resetfg() .. "    /",
	"    \\           /",
	"     \\_________/",
}

return {
	logo = {
		graphic = hexagon_logo,
		requires_color = true,
	}
}
