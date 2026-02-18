import "pe"

/*
=====================================================
 SCANNELER – AAA Anti-Cheat Detection Ruleset
 COMPATIBLE / STABLE / NO CRASH
=====================================================
*/

rule SCN_Cheat_UI_Frameworks
{
    meta:
        description = "Cheat UI frameworks (ImGui / internal menus)"
        severity = "medium"

    strings:
        $imgui1 = "ImGui" ascii
        $imgui2 = "ImVec2" ascii
        $imgui3 = "ImDrawList" ascii
        $imgui4 = "ImGui_ImplDX9" ascii
        $imgui5 = "ImGui_ImplDX11" ascii

        $menu1 = "Cheat Menu" nocase
        $menu2 = "Hack Menu" nocase
        $menu3 = "Overlay Menu" nocase

    condition:
        2 of ($imgui*) and any of ($menu*)
}

rule SCN_Cheat_Features_FPS
{
    meta:
        description = "FPS cheat feature strings"
        severity = "high"

    strings:
        $f1 = "Aimbot" nocase
        $f2 = "SilentAim" nocase
        $f3 = "Wallhack" nocase
        $f4 = "Triggerbot" nocase
        $f5 = "NoRecoil" nocase
        $f6 = "Spinbot" nocase
        $f7 = "FakeLag" nocase
        $f8 = "Chams" nocase
        $f9 = "Skeleton" nocase

    condition:
        3 of them
}

rule SCN_Memory_Injection_APIs
{
    meta:
        description = "Classic memory injection APIs"
        severity = "critical"

    strings:
        $m1 = "WriteProcessMemory" ascii
        $m2 = "ReadProcessMemory" ascii
        $m3 = "VirtualAllocEx" ascii
        $m4 = "CreateRemoteThread" ascii
        $m5 = "NtCreateThreadEx" ascii
        $m6 = "NtWriteVirtualMemory" ascii
        $m7 = "NtReadVirtualMemory" ascii

    condition:
        2 of them
}

rule SCN_ManualMap_Indicators
{
    meta:
        description = "Manual map / reflective loader indicators"
        severity = "critical"

    strings:
        $mm1 = "ManualMap" nocase
        $mm2 = "ReflectiveLoader" ascii
        $mm3 = "LdrLoadDll" ascii
        $mm4 = "NtMapViewOfSection" ascii
        $mm5 = "ZwUnmapViewOfSection" ascii

    condition:
        2 of them
}

rule SCN_Anti_Forensic_Evasion
{
    meta:
        description = "Anti-forensic / anti-cheat evasion"
        severity = "high"

    strings:
        $e1 = "UnlinkModule" nocase
        $e2 = "HideModule" nocase
        $e3 = "ErasePEHeader" nocase
        $e4 = "AntiDump" nocase
        $e5 = "IsDebuggerPresent" ascii
        $e6 = "CheckRemoteDebuggerPresent" ascii

    condition:
        2 of them
}

rule SCN_Cheat_Config_Auth
{
    meta:
        description = "Cheat config / auth / HWID"
        severity = "medium"

    strings:
        $c1 = "Load Config" nocase
        $c2 = "Save Config" nocase
        $c3 = "profiles\\" nocase
        $c4 = "hwid" nocase
        $c5 = "license" nocase
        $c6 = "auth" nocase
        $c7 = "subscription" nocase

    condition:
        2 of them
}

rule SCN_Suspicious_DLL_Loader
{
    meta:
        description = "Suspicious DLL loader (userland)"
        severity = "high"

    condition:
        pe.is_dll() and
        filesize < 5242880 and
        pe.number_of_sections >= 4
}
