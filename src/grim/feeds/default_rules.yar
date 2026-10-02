/*
 * GRIM default YARA ruleset.
 *
 * These rules cover the malware families GRIM can detect structurally in source
 * anyway, so that the YARA adapter is useful out of the box instead of inert until
 * the operator points GRIM_YARA_RULES somewhere. They are deliberately small and
 * high-precision: every rule here corresponds to a pattern the built-in engines
 * already act on, so a match is a second signal on the same finding, not a new
 * claim. Low-signal packer and miner rules live in the feed, not here.
 *
 * Set GRIM_YARA_RULES to override this file with your own ruleset.
 */

rule grim_webshell_php_eval
{
    meta:
        description = "PHP webshell executing request data through eval"
        author = "GRIM"
        severity = "critical"
        cwe = "CWE-95"
    strings:
        $php = "<?php" ascii nocase
        $eval1 = "eval(" ascii nocase
        $eval2 = "assert(" ascii nocase
        $src1 = "$_POST[" ascii
        $src2 = "$_GET[" ascii
        $src3 = "$_REQUEST[" ascii
        $src4 = "$_COOKIE[" ascii
    condition:
        $php and any of ($eval*) and any of ($src*)
}

rule grim_webshell_php_system
{
    meta:
        description = "PHP webshell passing request data to a process shell"
        author = "GRIM"
        severity = "critical"
        cwe = "CWE-78"
    strings:
        $php = "<?php" ascii nocase
        $shell1 = "system(" ascii nocase
        $shell2 = "shell_exec(" ascii nocase
        $shell3 = "passthru(" ascii nocase
        $shell4 = "proc_open(" ascii nocase
        $shell5 = "popen(" ascii nocase
        $src1 = "$_POST[" ascii
        $src2 = "$_GET[" ascii
        $src3 = "$_REQUEST[" ascii
    condition:
        $php and any of ($shell*) and any of ($src*)
}

rule grim_reverse_shell_bash
{
    meta:
        description = "Interactive reverse shell via bash"
        author = "GRIM"
        severity = "critical"
        cwe = "CWE-78"
    strings:
        $a = "bash -i" ascii nocase
        $b = ">& /dev/tcp/" ascii
        $c = "sh -i" ascii nocase
    condition:
        any of them
}

rule grim_reverse_shell_nc
{
    meta:
        description = "Netcat or /dev/tcp reverse shell with shell spawn"
        author = "GRIM"
        severity = "critical"
        cwe = "CWE-78"
    strings:
        $sh1 = "/bin/sh" ascii
        $sh2 = "/bin/bash" ascii
        $sh3 = "cmd.exe" ascii nocase
        $pipe1 = "nc " ascii nocase
        $pipe2 = "ncat " ascii nocase
        $pipe3 = "netcat" ascii nocase
        $devtcp = "/dev/tcp/" ascii
    condition:
        $devtcp or (any of ($sh*) and any of ($pipe*))
}

rule grim_powershell_download_execute
{
    meta:
        description = "PowerShell remote script download executed in memory"
        author = "GRIM"
        severity = "critical"
        cwe = "CWE-494"
    strings:
        $dl1 = "DownloadString" ascii nocase
        $dl2 = "DownloadFile" ascii nocase
        $dl3 = "Invoke-WebRequest" ascii nocase
        $dl4 = "iwr " ascii nocase
        $dl5 = "Net.WebClient" ascii nocase
        $ex1 = "IEX" ascii
        $ex2 = "Invoke-Expression" ascii nocase
        $ex3 = "| iex" ascii nocase
        $ex4 = "Start-Process" ascii nocase
    condition:
        any of ($dl*) and any of ($ex*)
}

rule grim_powershell_encoded_command
{
    meta:
        description = "Base64 encoded PowerShell command, a common evasion technique"
        author = "GRIM"
        severity = "high"
        cwe = "CWE-506"
    strings:
        $enc1 = "-EncodedCommand" ascii nocase
        $enc2 = "-enc " ascii nocase
        $enc3 = "-e " ascii nocase
        $b64 = /[A-Za-z0-9+/]{40,}={0,2}/
    condition:
        any of ($enc*) and $b64
}

rule grim_cryptominer_pool
{
    meta:
        description = "Mining pool protocol string or wallet configuration"
        author = "GRIM"
        severity = "high"
        cwe = "CWE-506"
    strings:
        $pool1 = "stratum+tcp://" ascii nocase
        $pool2 = "stratum+ssl://" ascii nocase
        $pool3 = "xmrig" ascii nocase
        $pool4 = "minerd" ascii nocase
        $pool5 = "ethminer" ascii nocase
        $pool6 = "cpuminer" ascii nocase
        $algo1 = "randomx" ascii nocase
        $algo2 = "cryptonight" ascii nocase
        $algo3 = "kawpow" ascii nocase
        $algo4 = "rx/0" ascii nocase
        $algo5 = "lyra2z" ascii nocase
        $wallet1 = "0x0000000000000000000000000000000000000000" ascii
    condition:
        2 of them
}

rule grim_ransomware_shadow_delete
{
    meta:
        description = "Shadow copy deletion paired with encryption, a ransomware pattern"
        author = "GRIM"
        severity = "critical"
        cwe = "CWE-506"
    strings:
        $shadow1 = "vssadmin delete shadows" ascii nocase
        $shadow2 = "wmic shadowcopy delete" ascii nocase
        $shadow3 = "bcdedit /set {default} recoveryenabled No" ascii nocase
        $shadow4 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii nocase
        $crypt1 = "BEGIN RSA PRIVATE KEY" ascii
        $crypt2 = "BEGIN ENCRYPTED PRIVATE KEY" ascii
        $crypt3 = "CryptEncrypt" ascii
        $crypt4 = "AES.GenerateKey" ascii
        $note1 = "your files have been encrypted" ascii nocase
        $note2 = "to decrypt your files" ascii nocase
        $note3 = "send bitcoin" ascii nocase
        $note4 = "readme.txt" ascii nocase
    condition:
        any of ($shadow*) or (any of ($crypt*) and any of ($note*))
}

rule grim_persistence_cron
{
    meta:
        description = "Persistence via crontab or systemd unit installation"
        author = "GRIM"
        severity = "high"
        cwe = "CWE-506"
    strings:
        $cron1 = "crontab -" ascii nocase
        $cron2 = "/etc/cron.d/" ascii
        $cron3 = "@reboot" ascii
        $sd1 = "systemctl enable" ascii nocase
        $sd2 = "/etc/systemd/system/" ascii
        $sd3 = "systemctl daemon-reload" ascii nocase
        $prof1 = ".bashrc" ascii nocase
        $prof2 = ".profile" ascii nocase
        $prof3 = "authorized_keys" ascii nocase
    condition:
        (any of ($cron*) or any of ($sd*)) and any of ($prof*)
}

rule grim_credential_harvest_form
{
    meta:
        description = "Form grabbing or credential capture markup"
        author = "GRIM"
        severity = "high"
        cwe = "CWE-522"
    strings:
        $post1 = "POST" ascii
        $grab1 = "type=\"password\"" ascii nocase
        $grab2 = "type='password'" ascii nocase
        $grab3 = "autocomplete=\"off\"" ascii nocase
        $exfil1 = "document.cookie" ascii nocase
        $exfil2 = "localStorage.getItem" ascii nocase
        $exfil3 = "addEventListener('keypress'" ascii nocase
        $exfil4 = "addEventListener(\"keypress\"" ascii nocase
    condition:
        $post1 and any of ($grab*) and any of ($exfil*)
}

rule grim_obfuscation_charcode_assembly
{
    meta:
        description = "String built from char codes at runtime, an evasion technique"
        author = "GRIM"
        severity = "medium"
        cwe = "CWE-506"
    strings:
        $js1 = "String.fromCharCode" ascii nocase
        $js2 = "atob(" ascii nocase
        $js3 = "unescape(" ascii nocase
        $js4 = "eval(atob(" ascii nocase
        $py1 = "chr(" ascii
        $py2 = "__import__('base64')" ascii
        $ps1 = "FromBase64String" ascii nocase
        $ps2 = "-EncodedCommand" ascii nocase
    condition:
        2 of them
}

rule grim_eicar_test_file
{
    meta:
        description = "EICAR anti-malware test file, not a real infection"
        author = "GRIM"
        severity = "info"
        cwe = "CWE-506"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}