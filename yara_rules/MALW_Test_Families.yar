/* DEMO_Families_HighEntropy.yar
 * Safe demo rules for fake high-entropy samples.
 * These DO NOT match real malware, only your custom markers.
 */

/* ------------- RANSOMWARE – MALICIOUS ------------- */

rule DEMO_Ransomware_Critical
{
    meta:
        family      = "Ransomware"
        subtype     = "WannaCry-style (Demo)"
        description = "Demo ransomware sample with high entropy"
        severity    = "critical"   
        test_rule   = true

    strings:
        $marker = "SAFEFILE_DEMO_RANSOMWARE_CRITICAL"

    condition:
        $marker and filesize > 50000
}

/* ------------- TROJAN – MALICIOUS ------------- */

rule DEMO_Trojan_High
{
    meta:
        family      = "Trojan Horse"
        subtype     = "Banking Trojan (Demo)"
        description = "Demo trojan sample with high entropy"
        severity    = "high"       
        test_rule   = true

    strings:
        $marker = "SAFEFILE_DEMO_TROJAN_HIGH"

    condition:
        $marker and filesize > 40000
}

/* ------------- WORM – SUSPICIOUS ------------- */

rule DEMO_Worm_Medium
{
    meta:
        family      = "Worm"
        subtype     = "Network Worm (Demo)"
        description = "Demo worm sample – medium severity"
        severity    = "medium"    
        test_rule   = true

    strings:
        $marker = "SAFEFILE_DEMO_WORM_MEDIUM"

    condition:
        $marker and filesize > 30000
}

/* ------------- VIRUS – SUSPICIOUS ------------- */

rule DEMO_Virus_Medium
{
    meta:
        family      = "File Virus"
        subtype     = "Infecting EXE (Demo)"
        description = "Demo file-virus sample – medium severity"
        severity    = "medium"    
        test_rule   = true

    strings:
        $marker = "SAFEFILE_DEMO_VIRUS_MEDIUM"

    condition:
        $marker and filesize > 30000
}

/* ------------- BACKDOOR – MALICIOUS ------------- */

rule DEMO_Backdoor_High
{
    meta:
        family      = "Backdoor"
        subtype     = "Remote Access (Demo)"
        description = "Demo backdoor sample – high severity, high entropy"
        severity    = "high"      
        test_rule   = true

    strings:
        $marker = "SAFEFILE_DEMO_BACKDOOR_HIGH"

    condition:
        $marker and filesize > 40000
}
