#include "framework.h"
#include "memcury.h"

#define DefineNative(address, ret, name, params) inline ret(*name) params = (ret(*) params)(address);

DefineNative(reinterpret_cast<uintptr_t>(GetModuleHandleA("GameAssembly.dll")) + 0x0104D670, int32_t, TestFunc, (void* __this, void** bytes, int32_t offset, void* value, void* formatterResolver, void* method));

constexpr const wchar_t* testStringRef = L"%s %s SetTimer passed a negative or zero time. The associated timer may fail to be created/fire! If using InitialStartDelayVariance, be sure it is smaller than (Time + InitialStartDelay).";

static void Main(HMODULE hModule)
{
    if constexpr (Memcury::Globals::bLogging)
    {
        AllocConsole();

        FILE* pFile;
        freopen_s(&pFile, "CONOUT$", "w", stdout);
    }

    Memcury::Safety::SetExceptionMode<Memcury::Safety::ExceptionMode::CatchDllExceptionsOnly>();
    //*((unsigned int*)0) = 0xDEAD;

    auto scanner = Memcury::Scanner::FindStringRef(testStringRef)
                       .ScanFor({ Memcury::ASM::Mnemonic("CALL") }, false)
                       .RelativeOffset(1);

    printf("%p\n", scanner.GetAs<void*>());
}

bool DllMain(HMODULE hModule, DWORD ulReason, LPVOID lpReserved)
{
    if (ulReason == DLL_PROCESS_ATTACH)
    {
        CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(&Main), hModule, 0, nullptr);
    }

    return true;
}