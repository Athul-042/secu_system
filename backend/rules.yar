rule SQL_Injection_Common {
    strings:
        $s1 = "UNION SELECT" nocase
        $s2 = "OR 1=1" nocase
        $s3 = "DROP TABLE" nocase
        $s4 = "information_schema" nocase
    condition:
        any of them
}

rule XSS_Common {
    strings:
        $s1 = "<script>" nocase
        $s2 = "javascript:" nocase
        $s3 = "onerror=" nocase
        $s4 = "onload=" nocase
    condition:
        any of them
}

rule Malware_Ports {
    strings:
        $p1 = "4444" // Metasploit
        $p2 = "6667" // IRC Botnets
        $p3 = "31337" // Back Orifice
    condition:
        any of them
}
