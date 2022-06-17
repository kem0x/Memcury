#include "framework.h"
#include "memcury.h"

#define DefineNative(address, ret, name, params) inline ret(*name) params = (ret(*) params)(address);
DefineNative(reinterpret_cast<uintptr_t>(GetModuleHandleA("GameAssembly.dll")) + 0x0104D670, int32_t, ThrowDiceTurnDecisionFormatter_Serialize, (void* __this, void** bytes, int32_t offset, void* value, void* formatterResolver, void* method));

constexpr const wchar_t* test = L"%s %s SetTimer passed a negative or zero time. The associated timer may fail to be created/fire! If using InitialStartDelayVariance, be sure it is smaller than (Time + InitialStartDelay).";

int32_t ThrowDiceTurnDecisionFormatter_SerializeHook(void* __this, void** bytes, int32_t offset, void* value, void* formatterResolver, void* method)
{
    printf("Return address from %s: %p\n", __FUNCTION__, _ReturnAddress());

    return ThrowDiceTurnDecisionFormatter_Serialize(__this, bytes, offset, value, formatterResolver, method);
}

static void Main(HMODULE hModule)
{
    if constexpr (Memcury::Globals::bLogging)
    {
        AllocConsole();

        FILE* pFile;
        freopen_s(&pFile, "CONOUT$", "w", stdout);
    }

    Memcury::Scanner::SetTargetModule("GameAssembly");

    auto scanner = Memcury::Scanner::FindPattern("40 ? 55 56 41 ? 48 83 EC ? 80 3D 05 F7 8E 01");

    /*
    auto scanner = Memcury::Scanner::FindStringRef(test)
                       .ScanFor({ Memcury::ASM::Mnemonic("CALL") }, false)
                       .RelativeOffset(1);
                       .FindFunctionBoundary();
    */

    printf("%p\n", scanner.GetAs<void*>());

    Memcury::TrampolineHook detour(&(void*&)ThrowDiceTurnDecisionFormatter_Serialize, ThrowDiceTurnDecisionFormatter_SerializeHook);
    detour.Commit();
}

bool DllMain(HMODULE hModule, DWORD ulReason, LPVOID lpReserved)
{
    if (ulReason == DLL_PROCESS_ATTACH)
    {
        CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(&Main), hModule, 0, nullptr);
    }

    return true;
}