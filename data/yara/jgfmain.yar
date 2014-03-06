rule JGFsub
{
meta:
	date = "2014-02-21"
	description = "JGFmain"
	
strings:
	$string0 = "cmd.dll"
	$string1 = "cmd64.dll" wide
	$string2 = "sub.dll" wide
	$string3 = "servers.dat"
	$string4 = "subx.dll" wide
	$string5 = "drv32"
	$string6 = "config.ini" wide
	$string7 = "ldr16" wide
	$string8 = "ldr32"
	$string9 = "ldr64"
	$string10 = "NetworkService"
	$string11 = "subref" wide
	$string12 = ".bintoklet." wide
	$string13 = "servers.dat"
	$string14 = "analizesearch." wide
	$string15 = "dnsapi.dll"
	$string16 = "%S\\config.ini" wide
	$string17 = "qazxsw_" wide
	$string18 = "Query_Main"
	$string19 = "%s\\servers.dat"
	$string20 = "Global\\{3F2504E0-4F89-11D3-9A0C-0305E82C3301}"
condition:
	5 of them
}
