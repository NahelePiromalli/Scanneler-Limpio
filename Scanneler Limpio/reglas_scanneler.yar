import "pe"

/*
===============================================================================
 SCANNELER – AAA ULTRA HIGH-PRECISION ANTI-CHEAT YARA RULESET (V10.0)
===============================================================================
 Scope: FPS Cheats, Internal Overlays, Memory Injectors, Reflective Loaders,
        Kernel BYOVD Drivers, HWID Spoofers, Anti-Forensics & Packers.
 Target: Maximum Detection Accuracy | Zero False Positives
===============================================================================
*/

rule SCN_Cheat_UI_Frameworks
{
    meta:
        description = "Cheat UI frameworks, MinHook, Kiero & Internal Overlays"
        severity = "medium"

    strings:
        $imgui1 = "ImGui" ascii
        $imgui2 = "ImVec2" ascii
        $imgui3 = "ImDrawList" ascii
        $hook1  = "kiero::init" ascii nocase
        $hook2  = "MH_CreateHook" ascii
        $hook3  = "MH_EnableHook" ascii
        $menu1  = "Cheat Menu" nocase
        $menu2  = "Hack Menu" nocase
        $menu3  = "Internal Overlay" nocase

    condition:
        2 of ($imgui*) and (1 of ($hook*) or 1 of ($menu*))
}

rule SCN_Cheat_Features_FPS
{
    meta:
        description = "FPS cheat feature strings & aimbot/ESP indicators"
        severity = "high"

    strings:
        $f1  = "Aimbot" nocase
        $f2  = "SilentAim" nocase
        $f3  = "Wallhack" nocase
        $f4  = "Triggerbot" nocase
        $f5  = "NoRecoil" nocase
        $f6  = "Spinbot" nocase
        $f7  = "FakeLag" nocase
        $f8  = "Chams" nocase
        $f9  = "EspBox" nocase
        $f10 = "Bhop" nocase
        $f11 = "AimSmoothing" nocase
        $f12 = "SkeletonEsp" nocase
        $f13 = "PredictionAim" nocase

    condition:
        3 of them
}

rule SCN_Memory_Injection_Techniques
{
    meta:
        description = "Advanced memory injection APIs and thread hijacking"
        severity = "critical"

    strings:
        $m1 = "WriteProcessMemory" ascii
        $m2 = "VirtualAllocEx" ascii
        $m3 = "CreateRemoteThread" ascii
        $m4 = "NtCreateThreadEx" ascii
        $m5 = "NtWriteVirtualMemory" ascii
        $m6 = "RtlCreateUserThread" ascii
        $m7 = "QueueUserAPC" ascii

    condition:
        ($m3 or $m4 or $m6 or $m7) and ($m1 or $m5) and $m2
}

rule SCN_Reflective_ManualMap_Loaders
{
    meta:
        description = "Reflective DLL & Manual Map loader indicators"
        severity = "critical"

    strings:
        $mm1 = "ManualMap" nocase
        $mm2 = "ReflectiveLoader" ascii
        $mm3 = "LdrLoadDll" ascii
        $mm4 = "NtMapViewOfSection" ascii
        $mm5 = "LoadLibraryR" ascii
        $mm6 = "GetProcAddressR" ascii

    condition:
        ($mm1 or $mm2 or $mm5 or $mm6) and 1 of ($mm3, $mm4)
}

rule SCN_Kernel_BYOVD_Vulnerable_Drivers
{
    meta:
        description = "BYOVD vulnerable drivers & KDMapper kernel exploits"
        severity = "critical"

    strings:
        $d1 = "iqvw64e.sys" nocase ascii
        $d2 = "capcom.sys" nocase ascii
        $d3 = "gdrv.sys" nocase ascii
        $d4 = "atszio.sys" nocase ascii
        $d5 = "winio.sys" nocase ascii
        $d6 = "msio64.sys" nocase ascii
        $d7 = "kdmapper" nocase ascii
        $d8 = "kdmpper" nocase ascii
        $d9 = "drvmap" nocase ascii

    condition:
        any of them
}

rule SCN_HWID_Spoofers_License_Loaders
{
    meta:
        description = "HWID spoofers, volume/MAC spoofers & key auth loaders"
        severity = "high"

    strings:
        $c1 = "hwid_spoofer" nocase
        $c2 = "volumeid_spoof" nocase
        $c3 = "smbios_spoof" nocase
        $c4 = "mac_spoof" nocase
        $c5 = "cheat_config" nocase
        $c6 = "license_key" nocase
        $c7 = "key_auth" nocase
        $c8 = "bypass_guard" nocase

    condition:
        2 of them
}

rule SCN_Anti_Forensic_Cleaners_Evasion
{
    meta:
        description = "Anti-forensics, USN/Prefetch wipers & PE header erasing"
        severity = "critical"

    strings:
        $e1 = "UnlinkModule" nocase
        $e2 = "HideModule" nocase
        $e3 = "ErasePEHeader" nocase
        $e4 = "AntiDump" nocase
        $e5 = "PEHeaderWipe" nocase
        $e6 = "WipePrefetch" nocase
        $e7 = "ClearUsnJournal" nocase
        $e8 = "HideThreadFromDebugger" ascii

    condition:
        1 of ($e1, $e2, $e3, $e5) or 2 of them
}

rule SCN_Internal_Game_Hooks_SDK
{
    meta:
        description = "Game SDK hooks, VMT / SwapBuffers & pattern scanner"
        severity = "medium"

    strings:
        $sdk1 = "VMTHook" ascii
        $sdk2 = "SwapBuffersHook" ascii
        $sdk3 = "PresentHook" ascii
        $sdk4 = "CreateInterface" ascii
        $sdk5 = "PatternScan" ascii
        $sdk6 = "GObjects" ascii
        $sdk7 = "GNames" ascii

    condition:
        3 of them
}

rule SCN_Known_Packers_Protectors
{
    meta:
        description = "Known packers and protectors often used by cheats"
        severity = "medium"

    strings:
        $p1 = ".vmp0" ascii
        $p2 = ".vmp1" ascii
        $p3 = "Themida" ascii
        $p4 = "VMProtect" ascii
        $p5 = "UPX0!" ascii

    condition:
        pe.is_pe and any of them
}
