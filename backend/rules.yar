/* =========================================
   Hybrid IDS Signatures File
   Combines Web Exploits & Famous Malware
   ========================================= */

// --- CATEGORY: Core Web Exploits ---
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

// --- CATEGORY: Famous Malware Families (Senior's Rules) ---
rule MiraiBotnet { 
    strings: 
        $a = "Mirai" nocase 
        $b = "GET / HTTP/1.1" 
        $c = {00 01} 
    condition: 
        any of them 
}

rule WannaCry { 
    strings: 
        $a = "SMBv1" nocase 
        $b = "445" 
        $c = {FE ED} 
    condition: 
        any of them 
}

rule Zeus { 
    strings: 
        $a = "POST /gate.php" 
        $b = "Zeus" 
        $c = {FF EE} 
    condition: 
        any of them 
}

rule Emotet { 
    strings: 
        $a = "powershell" 
        $b = "Emotet" 
        $c = {DE AD} 
    condition: 
        any of them 
}

rule Qbot { 
    strings: 
        $a = "random_file_name" 
        $b = "Qbot" 
        $c = {BE EF} 
    condition: 
        any of them 
}

rule Conficker { 
    strings: 
        $a = "445/tcp" 
        $b = "rpc" 
        $c = {CA FE} 
    condition: 
        any of them 
}

rule NotPetya { 
    strings: 
        $a = "PsExec" 
        $b = "NotPetya" 
        $c = {BA BE} 
    condition: 
        any of them 
}

rule TrickBot { 
    strings: 
        $a = "banking" 
        $b = "inject" 
        $c = {AB CD} 
    condition: 
        any of them 
}

rule Ramnit { 
    strings: 
        $a = "worm" 
        $b = "445" 
        $c = {EF BE} 
    condition: 
        any of them 
}

// Detects unencrypted Windows executable files passing through the exact network layer
rule GenericExecutable { 
    strings: 
        $a = {4D 5A} // MZ Header signature
    condition: 
        $a 
}
