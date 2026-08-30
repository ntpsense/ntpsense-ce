-- gfx-ntpsensebrand.lua
-- Brand boot loader custom NTPSense InetGateway CE (posisi KIRI,
-- menggantikan fbsd_brand default) - struktur terverifikasi dari
-- source asli /boot/lua/drawer.lua (FreeBSD 14.3, dicek live).

local ntpsense_brand = {
" _   _ _____ _____  ",
"| \\ | |_   _|  __ \\ ",
"|  \\| | | | | |__) |___  ___ _ __  ___  ___",
"| . ` | | | |  ___// __\\/ _ \\ '_ \\/ __|/ _ \\",
"| |\\  | | | | |    \\___\\  __/ | | \\__ \\  __/",
"|_| \\_| |_| |_|    |___/\\___|_| |_|___/\\___|",
"           InetGateway CE"
}

return {
	brand = {
		graphic = ntpsense_brand,
	}
}
