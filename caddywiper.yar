rule Caddy_file_size {
    condition:
        filesize > 8KB and filesize < 10KB
}

rule Caddy_file_length {
    condition:
        filelength == 64
}

rule Caddy {
    meta:
        author = "Eliran Nissani"
        description = "Caddy Wiper Malware - Windows 32 Bit"
        date = "13.11.2024"
        reference = "https://bazaar.abuse.ch/sample/a294620543334a721a2ae8eaaf9680a0786f4b9a216d75b55cfd28f39e9430ea"
        sh1_hash = "98b3fb74b3e8b3f9b05a82473551c5a77b576d54"
        primary = true
    strings:
        $s1 = "DsRoleGetPrimaryDomainInformation" nocase
        $s2 = "NETAPI32.dll" nocase
        
        // Check for "DsRoleGetPrimaryDomainInformation" and "NETAPI32.dll" being close
        $s3 = { 44 73 52 6F 6C 65 47 65 74 50 72 69 6D 61 72 79 44 6F 6D 61 69 6E 49 6E 66 6F 72 6D 61 74 69 6F 6E [1-4] 4E 45 54 41 50 49 33 32 2E 64 6C 6C }

        /*
            Match for loading the "kernel32.dll" which is a concatenation of 1 byte at a time.
            Here the match of the string "kernel".
        */
        $s4 = { 6B C6 45 ?? 00 C6 45 ?? /* 'k' */
                65 C6 45 ?? 00 C6 45 ?? /* 'e' */
                72 C6 45 ?? 00 C6 45 ?? /* 'r' */
                6e C6 45 ?? 00 C6 45 ?? /* 'n' */ 
                65 C6 45 ?? 00 C6 45 ?? /* 'e' */ 
                6c C6 45 ?? 00 C6 45 ?? /* 'l' */ }
    condition:
        (2 of them or $s4) and Caddy_file_length and Caddy_file_size
}
