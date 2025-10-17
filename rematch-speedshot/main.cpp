// main.cpp
#include <Windows.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <iomanip>
#include <string>
#include <cstdint>
#include <atomic>
#include <sstream>
#include <process.h>
#include <cstdlib>
#include <vector>
#include <fstream>
#include <mutex>
#include <string>

inline void LogFast(const std::string& msg)
{
    static std::mutex mtx;
    static std::ofstream logFile("RematchHook.log", std::ios::app);
    std::lock_guard<std::mutex> lock(mtx);
    logFile << msg << '\n';
}

// MinHook
#include "libs/minhook/include/MinHook.h"

// SDK headers (adjust include path as needed)
#undef GetCurrentTime
#pragma warning(push)
#pragma warning(disable: 4309 4369)
#include "RematchLastedSDK/CppSDK/SDK.hpp"
//#pragma warning(pop)
#include "RematchLastedSDK/CppSDK/SDK/Runtime_parameters.hpp"
#include "RematchLastedSDK/CppSDK/SDK/Basic.hpp"
#pragma warning(pop)

// =========================================================
// Globals
// =========================================================



bool bSpeedHackEnabled = false;
float fSpeedMultiplier = 1.2f;

bool bUnstealable = false;

bool bPlayerSpeedEnabled = false;
float fPlayerSpeedMultiplier = 1.5f;

std::atomic<int> processEventCallCount{ 0 };

typedef void (*ProcessEvent_t)(SDK::UObject*, SDK::UFunction*, void*);
ProcessEvent_t OriginalProcessEvent = nullptr;

bool debugProcessEvent = false;

// Config file path (populated at runtime to DLL folder)
std::string g_ConfigPath = "";

// =========================================================
// Helpers
// =========================================================
static std::string PtrHex(void* p) {
    std::ostringstream ss;
    ss << "0x" << std::hex << reinterpret_cast<uintptr_t>(p);
    return ss.str();
}

static void DumpAsFloats(void* dataPtr, size_t maxBytes = 16) {
    if (!dataPtr || !debugProcessEvent) return;
    unsigned char* raw = reinterpret_cast<unsigned char*>(dataPtr);
    size_t limit = (maxBytes / 4) * 4;

    std::cout << std::fixed << std::setprecision(4);
    for (size_t i = 0; i < limit; i += 4) {
        float value = 0.f;
        memcpy(&value, raw + i, sizeof(float));
        std::cout << value << " ";
    }
    std::cout << std::endl;
}

static std::string GetDirectoryFromPath(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    if (pos == std::string::npos) return ".";
    return path.substr(0, pos);
}

static void SetConfigPathToDLLFolder(HMODULE module) {
    char modulePath[MAX_PATH] = { 0 };
    if (GetModuleFileNameA(module, modulePath, MAX_PATH) == 0) {
        // fallback to current directory
        g_ConfigPath = ".\\RematchCheat.ini";
        return;
    }
    std::string dir = GetDirectoryFromPath(std::string(modulePath));
    g_ConfigPath = dir + "\\RematchCheat.ini";
}

// =========================================================
// Config loader
// =========================================================
void LoadConfig() {
    if (g_ConfigPath.empty()) {
        // fallback
        g_ConfigPath = ".\\RematchCheat.ini";
    }

    char buf[128];

    GetPrivateProfileStringA("Cheat", "BallSpeedMultiplier", "1.2", buf, sizeof(buf), g_ConfigPath.c_str());
    fSpeedMultiplier = static_cast<float>(atof(buf));

    GetPrivateProfileStringA("Cheat", "PlayerSpeedMultiplier", "1.5", buf, sizeof(buf), g_ConfigPath.c_str());
    fPlayerSpeedMultiplier = static_cast<float>(atof(buf));

    bSpeedHackEnabled = GetPrivateProfileIntA("Cheat", "BallSpeedHack", 0, g_ConfigPath.c_str()) != 0;
    bPlayerSpeedEnabled = GetPrivateProfileIntA("Cheat", "PlayerSpeedHack", 0, g_ConfigPath.c_str()) != 0;
    bUnstealable = GetPrivateProfileIntA("Cheat", "Unstealable", 0, g_ConfigPath.c_str()) != 0;

    std::cout << "[CONFIG] Loaded from: " << g_ConfigPath << "\n";
    std::cout << "[CONFIG] BallSpeedMultiplier=" << fSpeedMultiplier
        << " PlayerSpeedMultiplier=" << fPlayerSpeedMultiplier
        << " BallSpeedHack=" << (bSpeedHackEnabled ? "ON" : "OFF")
        << " PlayerSpeedHack=" << (bPlayerSpeedEnabled ? "ON" : "OFF")
        << " Unstealable=" << (bUnstealable ? "ON" : "OFF") << "\n";
}

// =========================================================
// Param structs (as inferred from SDK dumps)
// =========================================================
struct BPF_GetShootForce_Params {
    SDK::AActor* _actor;
    SDK::FShootPrepTargetData _data;
    bool _bUseModifiers;
    float ReturnValue;
};

struct UBTTask_ShootAbility_UpdateShootForce_Params {
    SDK::FShootPrepTargetData _ShootData;
};

struct UShootModifier_BPE_ApplyMultiplierForce_Params {
    SDK::AActor* _actor;
    SDK::FShootPrepTargetData _ShootData;
    float ReturnValue;
};

// Player speed structs (layout inferred; matches common dumper output)
struct STT_Sprint_Params {
    int EntryPoint;
    float Speed;
};

struct LockMoveHasBall_SpeedDescriptionDB_Params {
    float BaseSpeed;
    float MaxSpeed;
};

struct FreeMove_SpeedDescriptionDB_Params {
    float WalkSpeed;
    float RunSpeed;
    float SprintSpeed;
};

struct ExtraEffort_SpeedDescriptionDB_Params {
    float EffortMultiplier;
};

// =========================================================
// Hooked ProcessEvent
// =========================================================
void HookedProcessEvent(SDK::UObject* Object, SDK::UFunction* Function, void* Parms) {
    if (!Function || !OriginalProcessEvent) return;

    std::string funcName = Function->GetName();

    if (debugProcessEvent) {
        LogFast("[DBG] Function: " + funcName);
        if (Parms) {
            DumpAsFloats(Parms, 32);   // this can stay; it doesn’t block much
        }
    }


    // === Prevent ball steals / possession loss (when enabled) ===
    if (bUnstealable && (
        funcName == "STT_BallSteal" ||
        funcName == "BP_Binder_BallAnyOwnerChanged" ||
        funcName == "BP_Binder_BallInterception" ||
        funcName == "GC_BallStealSuccess"))
    {
        if (debugProcessEvent) {
            LogFast("[DBG] Blocked possession change: " + funcName);
        }
        return; // skip calling original -> ownership won't change
    }

    // === Player speed modification ===
    if (bPlayerSpeedEnabled) {
        if (funcName.find("STT_Sprint") != std::string::npos && Parms) {
            auto* p = reinterpret_cast<STT_Sprint_Params*>(Parms);
            // sanity check: ensure speed is a reasonable float
            if (p && p->Speed > 0.f && p->Speed < 20000.f) {
                p->Speed *= fPlayerSpeedMultiplier;
                if (debugProcessEvent) {
                    LogFast("[DBG] Patched Sprint speed -> " + std::to_string(p->Speed));
                }
            }
        }
        else if (funcName.find("LockMoveHasBall_SpeedDescriptionDB") != std::string::npos && Parms) {
            auto* p = reinterpret_cast<LockMoveHasBall_SpeedDescriptionDB_Params*>(Parms);
            if (p) {
                if (p->BaseSpeed > 0.f && p->BaseSpeed < 20000.f)
                    p->BaseSpeed *= fPlayerSpeedMultiplier;
                if (p->MaxSpeed > 0.f && p->MaxSpeed < 20000.f)
                    p->MaxSpeed *= fPlayerSpeedMultiplier;
                if (debugProcessEvent) {
                    LogFast("[DBG] Patched LockMove Base=" + std::to_string(p->BaseSpeed) +
                        " Max=" + std::to_string(p->MaxSpeed));
                }
            }
        }
        else if (funcName.find("FreeMove_SpeedDescriptionDB") != std::string::npos && Parms) {
            auto* p = reinterpret_cast<FreeMove_SpeedDescriptionDB_Params*>(Parms);
            if (p) {
                if (p->WalkSpeed > 0.f && p->WalkSpeed < 20000.f)
                    p->WalkSpeed *= fPlayerSpeedMultiplier;
                if (p->RunSpeed > 0.f && p->RunSpeed < 20000.f)
                    p->RunSpeed *= fPlayerSpeedMultiplier;
                if (p->SprintSpeed > 0.f && p->SprintSpeed < 20000.f)
                    p->SprintSpeed *= fPlayerSpeedMultiplier;
                if (debugProcessEvent) {
                    LogFast("[DBG] Patched FreeMove Walk=" + std::to_string(p->WalkSpeed) +
                        " Run=" + std::to_string(p->RunSpeed) +
                        " Sprint=" + std::to_string(p->SprintSpeed));
                }
            }
        }
        else if (funcName.find("ExtraEffort_SpeedDescriptionDB") != std::string::npos && Parms) {
            auto* p = reinterpret_cast<ExtraEffort_SpeedDescriptionDB_Params*>(Parms);
            if (p) {
                if (p->EffortMultiplier > 0.f && p->EffortMultiplier < 100.f)
                    p->EffortMultiplier *= fPlayerSpeedMultiplier;
                if (debugProcessEvent) {
                    LogFast("[DBG] Patched ExtraEffort Mult=" + std::to_string(p->EffortMultiplier));
                }
            }
        }
    }

    // === Ball speed hack targets ===
    bool isTarget =
        (funcName == "BPF_GetShootForce") ||
        (funcName == "UpdateShootForce") ||
        (funcName == "BPE_ApplyMultiplierForce");

    if (isTarget) {
        // call original first so p->ReturnValue / _ShootData is filled
        OriginalProcessEvent(Object, Function, Parms);
        processEventCallCount++;

        if (funcName == "BPF_GetShootForce" && Parms) {
            auto* p = reinterpret_cast<BPF_GetShootForce_Params*>(Parms);
            if (bSpeedHackEnabled && p->ReturnValue > 0.f && p->ReturnValue < 1e6f) {
                p->ReturnValue *= fSpeedMultiplier;
            }
            if (debugProcessEvent && (processEventCallCount % 50 == 0)) {
                LogFast("[DBG] BPF_GetShootForce Return=" + std::to_string(p->ReturnValue));
                DumpAsFloats(&p->_data, 32);
            }
        }
        else if (funcName == "UpdateShootForce" && Parms) {
            auto* p = reinterpret_cast<UBTTask_ShootAbility_UpdateShootForce_Params*>(Parms);
            if (bSpeedHackEnabled && p) {
                unsigned char* raw = reinterpret_cast<unsigned char*>(&p->_ShootData);
                for (int offset = 0; offset < 16; offset += 4) {
                    float candidate;
                    memcpy(&candidate, raw + offset, sizeof(float));
                    if (candidate > 0.01f && candidate < 10000.f) {
                        float newVal = candidate * fSpeedMultiplier;
                        memcpy(raw + offset, &newVal, sizeof(float));
                    }
                }
            }
            if (debugProcessEvent && (processEventCallCount % 100 == 0)) {
                LogFast("[DBG] UpdateShootForce");
                DumpAsFloats(&p->_ShootData, 32);
            }
        }
        else if (funcName == "BPE_ApplyMultiplierForce" && Parms) {
            auto* p = reinterpret_cast<UShootModifier_BPE_ApplyMultiplierForce_Params*>(Parms);
            if (bSpeedHackEnabled && p->ReturnValue > 0.f && p->ReturnValue < 1e6f) {
                p->ReturnValue *= fSpeedMultiplier;
            }
            if (debugProcessEvent && (processEventCallCount % 100 == 0)) {
                LogFast("[DBG] BPE_ApplyMultiplierForce Return=" + std::to_string(p->ReturnValue));
                DumpAsFloats(&p->_ShootData, 32);
            }
        }
        return;
    }


    // Default passthrough
    OriginalProcessEvent(Object, Function, Parms);
}

/// =========================================================
// Hook setup & cleanup
// =========================================================
bool FindAndHookProcessEvent() {
    // try to get UWorld
    SDK::UWorld* World = SDK::UWorld::GetWorld();
    if (!World) {
        LogFast("[ERR] No UWorld");
        return false;
    }

    void** vtable = *reinterpret_cast<void***>(World);
    if (!vtable) {
        LogFast("[ERR] No vtable from UWorld");
        return false;
    }

    // Using SDK::Offsets::ProcessEventIdx as your index holder
    void* processEventAddress = vtable[SDK::Offsets::ProcessEventIdx];

    if (MH_Initialize() != MH_OK) {
        LogFast("[ERR] MH_Initialize failed");
        return false;
    }

    // Create the hook first
    if (MH_CreateHook(
        processEventAddress,
        &HookedProcessEvent,
        reinterpret_cast<void**>(&OriginalProcessEvent)
    ) != MH_OK)
    {
        LogFast("[ERR] MH_CreateHook failed");
        return false;
    }

    // Then enable it
    if (MH_EnableHook(processEventAddress) != MH_OK) {
        LogFast("[ERR] MH_EnableHook failed at " + PtrHex(processEventAddress));
        return false;
    }


    LogFast("[OK] Hooked ProcessEvent @" + PtrHex(processEventAddress));
    return true;
}

void CleanupHooks() {
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    OriginalProcessEvent = nullptr;
    LogFast("[CLEANUP] Hooks removed");
}

// =========================================================
// Console loop / main thread
// =========================================================
void DisplayInfo() {
    LogFast("=== CHEAT INFO ===");
    LogFast(std::string("Ball Speed Hack: ") + (bSpeedHackEnabled ? "ENABLED" : "DISABLED") + " (" + std::to_string(fSpeedMultiplier) + "x)");
    LogFast(std::string("Player Speed: ") + (bPlayerSpeedEnabled ? "ENABLED" : "DISABLED") + " (" + std::to_string(fPlayerSpeedMultiplier) + "x)");
    LogFast(std::string("Unstealable: ") + (bUnstealable ? "ENABLED" : "DISABLED"));
    LogFast(std::string("Calls: ") + std::to_string(processEventCallCount.load()));
    LogFast("==================");
}

unsigned int __stdcall MainThread(void* param) {
    HMODULE Module = static_cast<HMODULE>(param);

    // Optional: comment out AllocConsole to avoid blocking console I/O on the game thread.
    // AllocConsole();
    // FILE* f; freopen_s(&f, "CONOUT$", "w", stdout);

    // Set config path to DLL folder
    SetConfigPathToDLLFolder(Module);

    LogFast("[INFO] DLL injected");
    LoadConfig(); // load settings from DLL folder ini

    if (!FindAndHookProcessEvent()) {
        LogFast("[ERR] Hook failed");
        // If you opened a console earlier, close it here.
        // FreeConsole();
        FreeLibraryAndExitThread(Module, 1);
        return 1;
    }

    // Input loop
    while (!(GetAsyncKeyState(VK_END) & 1)) {
        if (GetAsyncKeyState(VK_F2) & 1) {
            bSpeedHackEnabled = !bSpeedHackEnabled;
            LogFast(std::string("[CHEAT] Ball SpeedHack ") + (bSpeedHackEnabled ? "ENABLED" : "DISABLED"));
        }
        if (GetAsyncKeyState(VK_F3) & 1) {
            fSpeedMultiplier = (fSpeedMultiplier >= 5.f) ? 1.f : fSpeedMultiplier + 0.5f;
            LogFast(std::string("[INFO] Ball Speed Multiplier=") + std::to_string(fSpeedMultiplier) + "x");
        }
        if (GetAsyncKeyState(VK_F4) & 1) DisplayInfo();
        if (GetAsyncKeyState(VK_F5) & 1) {
            debugProcessEvent = !debugProcessEvent;
            LogFast(std::string("[DEBUG] ") + (debugProcessEvent ? "ON" : "OFF"));
        }
        if (GetAsyncKeyState(VK_F6) & 1) {
            bUnstealable = !bUnstealable;
            LogFast(std::string("[CHEAT] Unstealable possession ") + (bUnstealable ? "ENABLED" : "DISABLED"));
        }
        if (GetAsyncKeyState(VK_F7) & 1) {
            bPlayerSpeedEnabled = !bPlayerSpeedEnabled;
            LogFast(std::string("[CHEAT] Player Speed ") + (bPlayerSpeedEnabled ? "ENABLED" : "DISABLED"));
        }
        if (GetAsyncKeyState(VK_F8) & 1) {
            fPlayerSpeedMultiplier = (fPlayerSpeedMultiplier >= 5.f) ? 1.f : fPlayerSpeedMultiplier + 0.5f;
            LogFast(std::string("[INFO] Player Speed Multiplier=") + std::to_string(fPlayerSpeedMultiplier) + "x");
        }
        if (GetAsyncKeyState(VK_F9) & 1) {
            LoadConfig();
            LogFast("[CONFIG] Reloaded from INI");
        }

        // reduce polling frequency to reduce CPU and minimize risk of tick delays
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    // cleanup and exit
    CleanupHooks();
    FreeConsole();
    FreeLibraryAndExitThread(Module, 0);
    return 0;
}

// =========================================================
// DLL entry
// =========================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        // create thread to avoid blocking loader
        _beginthreadex(nullptr, 0, MainThread, hModule, 0, nullptr);
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        CleanupHooks();
    }
    return TRUE;
}
