#include "framework.h"
#include "memcury.h"

#define DefineNative(address, ret, name, params) inline ret(*name) params = (ret(*) params)(address);

DefineNative(reinterpret_cast<uintptr_t>(GetModuleHandleA("GameAssembly.dll")) + 0x0104D670, int32_t, TestFunc, (void* __this, void** bytes, int32_t offset, void* value, void* formatterResolver, void* method));

constexpr const wchar_t* testStringRef = L"%s %s SetTimer passed a negative or zero time. The associated timer may fail to be created/fire! If using InitialStartDelayVariance, be sure it is smaller than (Time + InitialStartDelay).";

constexpr const char* jumpPatternExample = "74 05 E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 89 5C 24 ??";

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

    //Jump example
    auto scanner2 = Memcury::Scanner::FindPattern(jumpPatternExample)
                        .Jump()
                        .RelativeOffset(3);

    printf("%p\n%p\n", scanner.GetAs<void*>(), scanner2.GetAs<void*>());
}

bool DllMain(HMODULE hModule, DWORD ulReason, LPVOID lpReserved)
{
    if (ulReason == DLL_PROCESS_ATTACH)
    {
        CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(&Main), hModule, 0, nullptr);
    }

    return true;
}