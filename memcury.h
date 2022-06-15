#pragma once

#include <string>
#include <format>
#include <vector>
#include <stdexcept>
#include <type_traits>
#include <intrin.h>
#include <Windows.h>

namespace Memcury
{
    class Safety
    {
        static void FreezeCurrentThread()
        {
            static auto currentThread = GetCurrentThread();

            SuspendThread(currentThread);
        }

    public:
        static void Assert(bool condition, std::string message)
        {
            if (!condition)
            {
                MessageBoxA(nullptr, (std::format("{}\nLine: {}", message, __LINE__)).c_str(), "Error", MB_OK | MB_ICONERROR);
                FreezeCurrentThread();
            }
        }

        /*static void Assertf(bool condition, std::string& message, std::initializer_list<std::string&> format)
        {
            if (condition)
            {
                MessageBoxA(nullptr, (std::format(fmt, format)).c_str(), "Error", MB_OK | MB_ICONERROR);
                FreezeCurrentThread();
            }
        }*/

        static void Throw(std::string message)
        {
            throw std::runtime_error(message);
        }
    };

    namespace Util
    {
        constexpr unsigned int strhash(const char* str, int h = 0)
        {
            return !str[h] ? 5381 : (strhash(str, h + 1) * 33) ^ str[h];
        }
    }

    namespace Globals
    {
        constexpr const bool bLogging = true;

        const char* moduleName = nullptr;
    }

    namespace ASM
    {
        //@todo: this whole namespace needs a rework, should somehow make this more modern and less ugly.
        enum MNEMONIC : uint8_t
        {
            JMP_REL8 = 0xEB,
            JMP_REL32 = 0xE9,
            JMP_EAX = 0xE0,
            CALL = 0xE8,
            LEA = 0x8D,
            CDQ = 0x99,
            CMOVL = 0x4C,
            CMOVS = 0x48,
            CMOVNS = 0x49,
            NOP = 0x90,
            INT3 = 0xCC,
            RETN_REL8 = 0xC2,
            RETN = 0xC3,
            NONE = 0x00
        };

        constexpr int SIZE_OF_JMP_INSTRUCTION = 5;

        constexpr const char* MnemonicToString(MNEMONIC e) throw()
        {
            switch (e)
            {
            case JMP_REL8:
                return "JMP_REL8";
            case JMP_REL32:
                return "JMP_REL32";
            case JMP_EAX:
                return "JMP_EAX";
            case CALL:
                return "CALL";
            case LEA:
                return "LEA";
            case CDQ:
                return "CDQ";
            case CMOVL:
                return "CMOVL";
            case CMOVS:
                return "CMOVS";
            case CMOVNS:
                return "CMOVNS";
            case NOP:
                return "NOP";
            case INT3:
                return "INT3";
            case RETN_REL8:
                return "RETN_REL8";
            case RETN:
                return "RETN";
            case NONE:
                return "NONE";
            default:
                return "UNKNOWN";
            }
        }

        constexpr MNEMONIC Mnemonic(const char* s) throw()
        {
            switch (Util::strhash(s))
            {
            case Util::strhash("JMP_REL8"):
                return JMP_REL8;
            case Util::strhash("JMP_REL32"):
                return JMP_REL32;
            case Util::strhash("JMP_EAX"):
                return JMP_EAX;
            case Util::strhash("CALL"):
                return CALL;
            case Util::strhash("LEA"):
                return LEA;
            case Util::strhash("CDQ"):
                return CDQ;
            case Util::strhash("CMOVL"):
                return CMOVL;
            case Util::strhash("CMOVS"):
                return CMOVS;
            case Util::strhash("CMOVNS"):
                return CMOVNS;
            case Util::strhash("NOP"):
                return NOP;
            case Util::strhash("INT3"):
                return INT3;
            case Util::strhash("RETN_REL8"):
                return RETN_REL8;
            case Util::strhash("RETN"):
                return RETN;
            default:
                return NONE;
            }
        }

        auto byteIsA(uint8_t byte, MNEMONIC opcode)
        {
            return byte == opcode;
        }

        auto byteIsAscii(uint8_t byte)
        {
            static constexpr bool isAscii[0x100] = { false, false, false, false, false, false, false, false, false, true, true, false, false, true, false, false,
                                                     false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
                                                     true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
                                                     true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
                                                     true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
                                                     true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
                                                     true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
                                                     true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, false,
                                                     false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
                                                     false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
                                                     false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
                                                     false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
                                                     false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
                                                     false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
                                                     false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
                                                     false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false };

            return isAscii[byte];
        }

        auto pattern2bytes(const char* pattern)
        {
            auto bytes = std::vector<int> {};
            const auto start = const_cast<char*>(pattern);
            const auto end = const_cast<char*>(pattern) + strlen(pattern);

            for (auto current = start; current < end; ++current)
            {
                if (*current == '?')
                {
                    ++current;
                    if (*current == '?')
                        ++current;
                    bytes.push_back(-1);
                }
                else
                {
                    bytes.push_back(strtoul(current, &current, 16));
                }
            }
            return bytes;
        }
    }

    namespace PE
    {
        inline auto SetCurrentModule(const char* moduleName)
        {
            Globals::moduleName = moduleName;
        }

        inline auto GetModuleBase()
        {
            return reinterpret_cast<uintptr_t>(GetModuleHandleA(Globals::moduleName));
        }

        inline auto GetDOSHeader()
        {
            return reinterpret_cast<PIMAGE_DOS_HEADER>(GetModuleBase());
        }

        inline auto GetNTHeaders()
        {
            return reinterpret_cast<PIMAGE_NT_HEADERS>(GetModuleBase() + GetDOSHeader()->e_lfanew);
        }

        class Address
        {
            uintptr_t _address;

        public:
            Address()
            {
                _address = 0;
            }

            Address(uintptr_t address)
                : _address(address)
            {
            }

            Address(void* address)
                : _address(reinterpret_cast<uintptr_t>(address))
            {
            }

            auto operator=(uintptr_t address) -> Address
            {
                _address = address;
                return *this;
            }

            auto operator=(void* address) -> Address
            {
                _address = reinterpret_cast<uintptr_t>(address);
                return *this;
            }

            auto operator+(uintptr_t offset) -> Address
            {
                return Address(_address + offset);
            }

            bool operator>(uintptr_t offset)
            {
                return _address > offset;
            }

            bool operator>(Address address)
            {
                return _address > address._address;
            }

            bool operator<(uintptr_t offset)
            {
                return _address < offset;
            }

            bool operator<(Address address)
            {
                return _address < address._address;
            }

            bool operator>=(uintptr_t offset)
            {
                return _address >= offset;
            }

            bool operator>=(Address address)
            {
                return _address >= address._address;
            }

            bool operator<=(uintptr_t offset)
            {
                return _address <= offset;
            }

            bool operator<=(Address address)
            {
                return _address <= address._address;
            }

            bool operator==(uintptr_t offset)
            {
                return _address == offset;
            }

            bool operator==(Address address)
            {
                return _address == address._address;
            }

            bool operator!=(uintptr_t offset)
            {
                return _address != offset;
            }

            bool operator!=(Address address)
            {
                return _address != address._address;
            }

            auto RelativeOffset(uint32_t offset)
            {
                _address = ((_address + offset + 4) + *(int32_t*)(_address + offset));
                return *this;
            }

            auto AbsoluteOffset(uint32_t offset)
            {
                _address = _address + offset;
                return *this;
            }

            auto Get() -> uintptr_t
            {
                return _address;
            }

            template <typename T>
            auto GetAs() -> T
            {
                return reinterpret_cast<T>(_address);
            }
        };

        class Section
        {
        public:
            std::string sectionName;
            IMAGE_SECTION_HEADER rawSection;

            static std::vector<Section> GetAllSections()
            {
                std::vector<Section> sections;

                auto sectionsSize = GetNTHeaders()->FileHeader.NumberOfSections;
                auto section = IMAGE_FIRST_SECTION(GetNTHeaders());

                for (WORD i = 0; i < sectionsSize; i++, section++)
                {
                    auto secName = std::string((char*)section->Name);

                    sections.push_back({ secName, *section });
                }

                return sections;
            }

            static auto GetSection(std::string sectionName)
            {
                for (auto& section : GetAllSections())
                {
                    if (section.sectionName == sectionName)
                    {
                        return section;
                    }
                }

                Safety::Throw("Section not found");
                return Section {};
            }

            auto GetSectionSize() -> uint32_t
            {
                return rawSection.Misc.VirtualSize;
            }

            auto GetSectionStart()
            {
                return Address(GetModuleBase() + rawSection.VirtualAddress);
            }

            auto GetSectionEnd()
            {
                return Address(GetSectionStart() + GetSectionSize());
            }

            auto isInSection(Address address)
            {
                return address >= GetSectionStart() && address < GetSectionEnd();
            }
        };
    }

    class Scanner
    {
        PE::Address _address;

    public:
        Scanner(PE::Address address)
            : _address(address)
        {
        }

        static auto SetTargetModule(const char* moduleName)
        {
            PE::SetCurrentModule(moduleName);
        }

        static auto FindPattern(const char* signature)
        {
            PE::Address add { nullptr };

            const auto sizeOfImage = PE::GetNTHeaders()->OptionalHeader.SizeOfImage;
            auto patternBytes = ASM::pattern2bytes(signature);
            const auto scanBytes = reinterpret_cast<std::uint8_t*>(PE::GetModuleBase());

            const auto s = patternBytes.size();
            const auto d = patternBytes.data();

            for (auto i = 0ul; i < sizeOfImage - s; ++i)
            {
                bool found = true;
                for (auto j = 0ul; j < s; ++j)
                {
                    if (scanBytes[i + j] != d[j] && d[j] != -1)
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    add = reinterpret_cast<uintptr_t>(&scanBytes[i]);
                }
            }

            return Scanner(add);
        }

        // Supports wide and normal strings both std and pointers
        template <typename T = const wchar_t*>
        static auto FindStringRef(T string)
        {
            PE::Address add { nullptr };

            constexpr auto bIsWide = std::is_same<T, const wchar_t*>::value;
            constexpr auto bIsChar = std::is_same<T, const char*>::value;

            constexpr auto bIsPtr = bIsWide || bIsChar;

            auto textSection = PE::Section::GetSection(".text");
            auto rdataSection = PE::Section::GetSection(".rdata");

            const auto scanBytes = reinterpret_cast<std::uint8_t*>(textSection.GetSectionStart().Get());

            // scan only text section
            for (DWORD i = 0x0; i < textSection.GetSectionSize(); i++)
            {
                if ((scanBytes[i] == ASM::CMOVL || scanBytes[i] == ASM::CMOVS) && scanBytes[i + 1] == ASM::LEA)
                {
                    auto stringAdd = PE::Address(&scanBytes[i]).RelativeOffset(3);

                    // Check if the string is in the .rdata section
                    if (rdataSection.isInSection(stringAdd))
                    {
                        auto strBytes = stringAdd.GetAs<std::uint8_t*>();

                        // Check if the first char is printable
                        if (ASM::byteIsAscii(strBytes[0]))
                        {
                            if constexpr (!bIsPtr)
                            {
                                typedef T::value_type char_type;

                                auto lea = stringAdd.GetAs<char_type*>();

                                T leaT(lea);

                                if (leaT == string)
                                {
                                    add = PE::Address(&scanBytes[i]);
                                }
                            }
                            else
                            {
                                auto lea = stringAdd.GetAs<T>();

                                if constexpr (bIsWide)
                                {
                                    if (wcscmp(string, lea) == 0)
                                    {
                                        add = PE::Address(&scanBytes[i]);
                                    }
                                }
                                else
                                {
                                    if (strcmp(string, lea) == 0)
                                    {
                                        add = PE::Address(&scanBytes[i]);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return Scanner(add);
        }

        auto ScanFor(std::vector<uint8_t> opcodesToFind, bool forward = true)
        {
            const auto scanBytes = _address.GetAs<std::uint8_t*>();

            const auto s = opcodesToFind.size();
            const auto d = opcodesToFind.data();

            for (auto i = 0; forward ? (i < 2048) : (i > -2048); forward ? i++ : i--)
            {
                for (auto j = 0ul; j < s; ++j)
                {
                    if (scanBytes[i + j] != d[j] && d[j] != -1)
                    {
                        _address = &scanBytes[i];
                        break;
                    }
                }
            }

            return *this;
        }

        auto FindFunctionBoundary(bool forward = false)
        {
            const auto scanBytes = _address.GetAs<std::uint8_t*>();

            for (auto i = 0; forward ? (i < 2048) : (i > -2048); forward ? i++ : i--)
            {
                if ( // ASM::byteIsA(scanBytes[i], ASM::MNEMONIC::JMP_REL8) ||
                     // ASM::byteIsA(scanBytes[i], ASM::MNEMONIC::JMP_REL32) ||
                     // ASM::byteIsA(scanBytes[i], ASM::MNEMONIC::JMP_EAX) ||
                    ASM::byteIsA(scanBytes[i], ASM::MNEMONIC::RETN_REL8) || ASM::byteIsA(scanBytes[i], ASM::MNEMONIC::RETN) || ASM::byteIsA(scanBytes[i], ASM::MNEMONIC::INT3))
                {
                    _address = (uintptr_t)&scanBytes[i + 1];
                }
            }

            return *this;
        }

        auto RelativeOffset(uint32_t offset)
        {
            _address.RelativeOffset(offset);

            return *this;
        }

        auto AbsoluteOffset(uint32_t offset)
        {
            _address.AbsoluteOffset(offset);

            return *this;
        }

        template <typename T>
        auto GetAs() -> T
        {
            return _address.GetAs<T>();
        }

        auto Get()
        {
            return _address.Get();
        }
    };

    // Based on http://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html
    class Hook
    {
        PE::Address originalFunction;
        PE::Address hookFunction;
        std::vector<uint8_t> restore;

        void* AllocatePageNearAddress(void* targetAddr)
        {
            SYSTEM_INFO sysInfo;
            GetSystemInfo(&sysInfo);
            const uint64_t PAGE_SIZE = sysInfo.dwPageSize;

            uint64_t startAddr = (uint64_t(targetAddr) & ~(PAGE_SIZE - 1)); // round down to nearest page boundary
            uint64_t minAddr = min(startAddr - 0x7FFFFF00, (uint64_t)sysInfo.lpMinimumApplicationAddress);
            uint64_t maxAddr = max(startAddr + 0x7FFFFF00, (uint64_t)sysInfo.lpMaximumApplicationAddress);

            uint64_t startPage = (startAddr - (startAddr % PAGE_SIZE));

            for (uint64_t pageOffset = 1; pageOffset; pageOffset++)
            {
                uint64_t byteOffset = pageOffset * PAGE_SIZE;
                uint64_t highAddr = startPage + byteOffset;
                uint64_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

                bool needsExit = highAddr > maxAddr && lowAddr < minAddr;

                if (highAddr < maxAddr)
                {
                    void* outAddr = VirtualAlloc((void*)highAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (outAddr)
                        return outAddr;
                }

                if (lowAddr > minAddr)
                {
                    void* outAddr = VirtualAlloc((void*)lowAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (outAddr != nullptr)
                        return outAddr;
                }

                if (needsExit)
                {
                    break;
                }
            }

            return nullptr;
        }

        void WriteAbsoluteJump(void* jumpLocation, void* destination)
        {
            uint8_t absJumpInstructions[] = {
                ASM::Mnemonic("CMOVNS"), 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, addr
                0x41, 0xFF, 0xE2 // jmp r10
            };

            auto destination64 = (uint64_t)destination;
            memcpy(&absJumpInstructions[2], &destination64, sizeof(destination64));

            printf("jumpLocation: %p\n", jumpLocation);
            memcpy(jumpLocation, restore.data(), restore.size());
            memcpy((void*)(__int64(jumpLocation) + restore.size()), absJumpInstructions, sizeof(absJumpInstructions));

            // memcpy(jumpLocation, absJumpInstructions, sizeof(absJumpInstructions));
        }

        auto PrepareRestore()
        {
            Scanner scanner(originalFunction);
            scanner.ScanFor({ 0x48, 0x83, 0xEC }); // sub rsp

            printf("ScanFor: %p\n", scanner.GetAs<void*>());

            auto restoreSize = 6; // scanner.Get() - originalFunction.Get();

            Safety::Assert(restoreSize > 0 && restoreSize < 0x100, "Could not find sub rsp");

            restore.reserve(restoreSize);
            for (auto i = 0; i < restoreSize; i++)
            {
                restore.push_back(originalFunction.GetAs<uint8_t*>()[i]);
            }

            printf("restoreSize: %i %i\n", restoreSize, restore.size());

            memcpy(restore.data(), originalFunction.GetAs<void*>(), ASM::SIZE_OF_JMP_INSTRUCTION);

            return restoreSize;
        }

        auto PrepareJMPInstruction(uint64_t dst)
        {
            uint8_t bytes[5] = { ASM::Mnemonic("JMP_REL32"), 0x0, 0x0, 0x0, 0x0 };

            const uint64_t relAddr = dst - (originalFunction.Get() + ASM::SIZE_OF_JMP_INSTRUCTION);
            memcpy(bytes + 1, &relAddr, 4);

            return bytes;
        }

    public:
        Hook(void* originalFunction, void* hookFunction)
        {
            this->originalFunction = originalFunction;
            this->hookFunction = hookFunction;
        };

        auto Commit()
        {
            auto fnStart = originalFunction.GetAs<void*>();

            auto restoreSize = PrepareRestore();

            void* relayFuncMemory = AllocatePageNearAddress(fnStart);

            WriteAbsoluteJump(relayFuncMemory, hookFunction.GetAs<void*>());

            DWORD oldProtect;
            VirtualProtect(fnStart, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);

            auto jmpInstruction = PrepareJMPInstruction((uint64_t)relayFuncMemory);

            memset(fnStart, ASM::MNEMONIC::INT3, restoreSize);
            memcpy(fnStart, jmpInstruction, ASM::SIZE_OF_JMP_INSTRUCTION);
        }
    };
}