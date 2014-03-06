rule ie0day
{
meta:
	author = "Anonymous"
	date = "2014-02-20"
	description = "No Description Provided"
	hash0 = "bc99d3f41dfca74f2b40ce4d4f959af0"
	hash1 = "1d207b938ab3a049769a203de5a1e2b6"
	sample_filetype = "exe"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "secure ActiveX Control Module" wide
	$string1 = "120321000000Z"
	$string2 = "CompanyName" wide
	$string3 = "bj(t@w"
	$string4 = "cwPTX\\"
	$string5 = "Secure Control"
	$string6 = "TimeStamp-2048-20"
	$string7 = "SECURE.SecureCtrl.1"
	$string8 = "Geumcheon-gu1"
	$string9 = "image/gif0"
	$string10 = "http://logo.verisign.com/vslogo.gif04"
	$string11 = "dhl2222ptx"
	$string12 = "SEOUL1"
	$string13 = "4MB<60"
	$string14 = "Symantec Time Stamping Services Signer - G40"
	$string15 = "130813090112Z0"
	$string16 = "FileDescription" wide
	$string17 = "Translation" wide
condition:
	17 of them
}
