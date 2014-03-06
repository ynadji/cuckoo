rule Havex_Trojan : APT

{

    meta:

        id = 53

        revision = 1

        author = "CCIRC"

        description = " StupidSideGuards APT Havex Trojan Rule."

               reference = "MD5: 979464521c927226ac683ec4c88c6218"

    strings:

               $a = "fertger" wide ascii

               $b = "&v1" wide ascii

               $c = "&v2=" wide ascii

    condition:

        all of them

}
