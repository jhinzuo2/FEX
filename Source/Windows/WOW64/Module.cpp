// SPDX-License-Identifier: MIT
/*
$info$
tags: Bin|WOW64
desc: Implements the WOW64 BT module API using FEXCore
$end_info$
*/

// Thanks to André Zwing, whose ideas from https://github.com/AndreRH/hangover this code is based upon

#include <FEXCore/fextl/fmt.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Config/Config.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/Threads.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/Utils/SHMStats.h>
#include <FEXCore/Utils/EnumOperators.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/FPState.h>
#include <FEXCore/Utils/ArchHelpers/Arm64.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/Utils/SignalScopeGuards.h>

#include "Windows/Common/Allocator.h"
#include "Windows/Common/EnvironmentVariablesHandling.h"
#include "Common/CallRetStack.h"
#include "Common/JITGuardPage.h"
#include "Common/Config.h"
#include "Common/Exception.h"
#include "Common/TSOHandlerConfig.h"
#include "Common/ImageTracker.h"
#include "Common/InvalidationTracker.h"
#include "Common/OvercommitTracker.h"
#include "Common/CPUFeatures.h"
#include "Common/Logging.h"
#include "Common/Module.h"
#include "Common/CRT/CRT.h"
#include "Common/PortabilityInfo.h"
#include "Common/Handle.h"
#include "DummyHandlers.h"
#include "BTInterface.h"
#include "Windows/Common/SHMStats.h"

#include <cstdint>
#include <algorithm>
#include <type_traits>
#include <atomic>
#include <mutex>
#include <utility>
#include <unordered_map>
#include <ntstatus.h>
#include <windef.h>
#include <memoryapi.h>
#include <winternl.h>
#include <wine/debug.h>
#include <wine/unixlib.h>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <string_view>

extern "C" void* WINAPI RtlFindExportedRoutineByName(HMODULE, const char*);

namespace ControlBits {
// When this is unset, a thread can be safely interrupted and have its context recovered
// IMPORTANT: This can only safely be written by the owning thread
static constexpr uint32_t IN_JIT {1U << 0};

// JIT entry polls this bit until it is unset, at which point CONTROL_IN_JIT will be set
static constexpr uint32_t PAUSED {1U << 1};

// When this is set, the CPU context stored in the CPU area has not yet been flushed to the FEX TLS
static constexpr uint32_t WOW_CPU_AREA_DIRTY {1U << 2};
}; // namespace ControlBits

struct TLS {
  enum class Slot : size_t {
    ENTRY_CONTEXT = WOW64_TLS_MAX_NUMBER - 1,
    CONTROL_WORD = WOW64_TLS_MAX_NUMBER - 2,
    THREAD_STATE = WOW64_TLS_MAX_NUMBER - 3,
    CACHED_CALLRET_SP = WOW64_TLS_MAX_NUMBER - 4,
  };

  _TEB* TEB;

  explicit TLS(_TEB* TEB)
    : TEB(TEB) {}

  WOW64INFO& Wow64Info() const {
    return *reinterpret_cast<WOW64INFO*>(TEB->TlsSlots[WOW64_TLS_WOW64INFO]);
  }

  std::atomic<uint32_t>& ControlWord() const {
    // TODO: Change this when libc++ gains std::atomic_ref support
    return reinterpret_cast<std::atomic<uint32_t>&>(TEB->TlsSlots[FEXCore::ToUnderlying(Slot::CONTROL_WORD)]);
  }

  CONTEXT*& EntryContext() const {
    return reinterpret_cast<CONTEXT*&>(TEB->TlsSlots[FEXCore::ToUnderlying(Slot::ENTRY_CONTEXT)]);
  }

  FEXCore::Core::InternalThreadState*& ThreadState() const {
    return reinterpret_cast<FEXCore::Core::InternalThreadState*&>(TEB->TlsSlots[FEXCore::ToUnderlying(Slot::THREAD_STATE)]);
  }

  // This is used to work around user callback handling (see Wow64KiUserCallbackDispatcher in wine) unbalancing the
  // call-ret stace since user callbacks are returned from using a syscall that we can't really intercept.
  uint64_t& CachedCallRetSp() const {
    return reinterpret_cast<uint64_t&>(TEB->TlsSlots[FEXCore::ToUnderlying(Slot::CACHED_CALLRET_SP)]);
  }
};

struct FrontendThreadData {
  bool InLockedRWXRead {};
};

class WowSyscallHandler;

namespace {
namespace BridgeInstrs {
  // These directly jumped to by the guest to make system calls
  void* Syscall {};
  void* UnixCall {};
} // namespace BridgeInstrs

struct BNetSyscallIDs {
  std::optional<uint32_t> NtQuerySystemInformation;
  std::optional<uint32_t> NtQuerySystemInformationEx;
  std::optional<uint32_t> NtQueryInformationProcess;
};

// Cached per-process decision, computed at BTCpuProcessInit time.
static bool BNetLogEnabled {};
static bool BNetForceX86Enabled {};
static bool BNetForceX86TargetProcess {};
static bool BNetForceX86Ready {};
static uint32_t BNetLogBudget {400}; // Avoid log storms. Enough to capture detection sequence.
static BNetSyscallIDs BNetIDs;

template<typename... Args>
static void BNetLog(const char* Format, Args&&... args) {
  if (!BNetLogEnabled || BNetLogBudget == 0) {
    return;
  }

  --BNetLogBudget;
  LogMan::Msg::DFmt(Format, std::forward<Args>(args)...);
}

static const char* BNetProcessInfoClassHint(uint32_t Class) {
  switch (Class) {
  case 26:
    return "ProcessWow64Information(IsWow64Process)";
  case 88:
    return "ProcessMachineInformation(IsWow64Process2)";
  default:
    return nullptr;
  }
}

static const char* BNetSystemInfoClassHint(uint32_t Class) {
  switch (Class) {
  case 1:
    return "SystemCpuInformation(GetSystemInfo/GetNativeSystemInfo)";
  case 0xB5:
    return "SystemSupportedProcessorArchitectures(IsWow64Process2/GetNativeSystemInfo)";
  default:
    return nullptr;
  }
}

static char AsciiToLower(char C) {
  return static_cast<char>(std::tolower(static_cast<unsigned char>(C)));
}

static bool EqualsIgnoreCaseASCII(std::string_view LHS, std::string_view RHS) {
  if (LHS.size() != RHS.size()) {
    return false;
  }

  for (size_t i = 0; i < LHS.size(); ++i) {
    if (AsciiToLower(LHS[i]) != AsciiToLower(RHS[i])) {
      return false;
    }
  }

  return true;
}

static bool IsBNetForceX86TargetProcess(std::string_view ProcessName) {
  // Restrict mock scope to Agent-side processes only.
  return EqualsIgnoreCaseASCII(ProcessName, "agent.exe") || EqualsIgnoreCaseASCII(ProcessName, "agenthelper.exe");
}

static bool ForceX86PatchSystemInfo(uint32_t Class, uint32_t OutPtr, uint32_t Len) {
  constexpr uint32_t SystemCpuInformation = 1;
  if (Class != SystemCpuInformation || !OutPtr || !Len) {
    return false;
  }

  // Short process-layout queries should look like x86. Native-layout queries
  // should look like an AMD64 host, matching an ordinary x86-on-AMD64 process.
  const uint16_t TargetArch = Len >= 64 ? PROCESSOR_ARCHITECTURE_AMD64 : PROCESSOR_ARCHITECTURE_INTEL;
  bool Changed {};

  if (Len >= sizeof(SYSTEM_CPU_INFORMATION)) {
    auto* Out = reinterpret_cast<SYSTEM_CPU_INFORMATION*>(static_cast<uintptr_t>(OutPtr));
    if (Out->ProcessorArchitecture != TargetArch) {
      Out->ProcessorArchitecture = TargetArch;
      Changed = true;
    }
  }

  if (Len >= sizeof(uint16_t)) {
    auto* FirstWord = reinterpret_cast<uint16_t*>(static_cast<uintptr_t>(OutPtr));
    if (*FirstWord != TargetArch) {
      *FirstWord = TargetArch;
      Changed = true;
    }
  }

  return Changed;
}

static bool ForceX86PatchSystemInfoEx(uint32_t Class, uint32_t OutPtr, uint32_t Len) {
  // SYSTEM_INFORMATION_CLASS::SystemSupportedProcessorArchitectures.
  constexpr uint32_t SystemSupportedProcessorArchitectures = 0xB5;
  if (Class != SystemSupportedProcessorArchitectures || !OutPtr || Len < sizeof(uint16_t)) {
    return false;
  }

  auto* Words = reinterpret_cast<uint16_t*>(static_cast<uintptr_t>(OutPtr));
  const size_t WordCount = Len / sizeof(uint16_t);
  bool Changed {};
  for (size_t i = 0; i < WordCount; ++i) {
    switch (Words[i]) {
    case IMAGE_FILE_MACHINE_ARM64:
      Words[i] = IMAGE_FILE_MACHINE_AMD64;
      Changed = true;
      break;
    case PROCESSOR_ARCHITECTURE_ARM64:
      Words[i] = PROCESSOR_ARCHITECTURE_AMD64;
      Changed = true;
      break;
    default:
      break;
    }
  }

  return Changed;
}

struct NtQuerySystemInformationExArgs {
  uint32_t Class {};
  uint32_t InputPtr {};
  uint32_t InputLen {};
  uint32_t OutputPtr {};
  uint32_t OutputLen {};
};

static bool DecodeNtQuerySystemInformationExMachineProbe(const uint32_t* SysArgs32, NtQuerySystemInformationExArgs* Out) {
  if (!SysArgs32 || !Out) {
    return false;
  }

  // NtQuerySystemInformationEx canonical signature:
  //   (class, input, input_len, output, output_len, return_len)
  //
  // In WOW64 we can also observe variants where one/both pointers are split
  // to low/high dwords before the scalar lengths:
  //   (class, in_lo, in_hi, input_len, output, output_len, return_len)
  //   (class, in_lo, in_hi, input_len, out_lo, out_hi, output_len, return_len)
  //
  // Some call sites may add one leading slot before class, so try base 0/1.
  constexpr uint32_t SystemSupportedProcessorArchitectures = 0xB5;
  const auto IsLikelyInputLen = [](uint32_t Len) {
    return Len > 0 && Len <= 0x100;
  };
  const auto IsLikelyOutputLen = [](uint32_t Len) {
    return Len >= sizeof(uint16_t) && Len <= 0x1000;
  };
  const auto Fill = [&](uint32_t Base, uint32_t InputPtrIdx, uint32_t InputLenIdx, uint32_t OutputPtrIdx, uint32_t OutputLenIdx) {
    if (SysArgs32[Base + 0] != SystemSupportedProcessorArchitectures) {
      return false;
    }

    const uint32_t InputLen = SysArgs32[Base + InputLenIdx];
    const uint32_t OutputPtr = SysArgs32[Base + OutputPtrIdx];
    const uint32_t OutputLen = SysArgs32[Base + OutputLenIdx];
    if (!IsLikelyInputLen(InputLen) || OutputPtr == 0 || !IsLikelyOutputLen(OutputLen)) {
      return false;
    }

    Out->Class = SysArgs32[Base + 0];
    Out->InputPtr = SysArgs32[Base + InputPtrIdx];
    Out->InputLen = InputLen;
    Out->OutputPtr = OutputPtr;
    Out->OutputLen = OutputLen;
    return true;
  };

  for (uint32_t Base = 0; Base <= 1; ++Base) {
    // class, in, in_len, out, out_len, ret_len
    if (Fill(Base, 1, 2, 3, 4)) {
      return true;
    }
    // class, in_lo, in_hi, in_len, out, out_len, ret_len
    if (Fill(Base, 1, 3, 4, 5)) {
      return true;
    }
    // class, in_lo, in_hi, in_len, out_lo, out_hi, out_len, ret_len
    if (Fill(Base, 1, 3, 4, 6)) {
      return true;
    }
  }

  return false;
}

static bool ForceX86WriteProcessMachineTuple(uint32_t OutPtr, uint32_t Len) {
  if (!OutPtr || Len < sizeof(uint16_t) * 2) {
    return false;
  }

  auto* Words = reinterpret_cast<uint16_t*>(static_cast<uintptr_t>(OutPtr));
  bool Changed {};
  if (Words[0] != IMAGE_FILE_MACHINE_I386) {
    Words[0] = IMAGE_FILE_MACHINE_I386;
    Changed = true;
  }
  if (Words[1] != IMAGE_FILE_MACHINE_AMD64) {
    Words[1] = IMAGE_FILE_MACHINE_AMD64;
    Changed = true;
  }
  return Changed;
}

static bool IsReadablePtr(const void* Ptr, size_t Size) {
  if (!Ptr || Size == 0) {
    return false;
  }

  MEMORY_BASIC_INFORMATION mbi {};
  if (VirtualQuery(Ptr, &mbi, sizeof(mbi)) == 0) {
    return false;
  }

  if (mbi.State != MEM_COMMIT) {
    return false;
  }

  if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD)) {
    return false;
  }

  const auto Begin = reinterpret_cast<uintptr_t>(Ptr);
  const auto End = Begin + Size;
  const auto RegionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
  return End <= RegionEnd;
}

static std::optional<uint32_t> ExtractX86SyscallIdAt(const uint8_t* Code, size_t Size) {
  if (!Code || Size < 5) {
    return std::nullopt;
  }

  // Wine's 32-bit ntdll syscall thunks are expected to contain `mov eax, imm32` near the start.
  // We'll scan a small prefix for robustness across Wine builds.
  const size_t ScanSize = std::min<size_t>(Size, 32);
  for (size_t i = 0; i + 4 < ScanSize; ++i) {
    if (Code[i] == 0xB8 /* mov eax, imm32 */) {
      uint32_t id {};
      std::memcpy(&id, Code + i + 1, sizeof(id));
      return id;
    }
  }
  return std::nullopt;
}

static const uint8_t* FollowX86JmpThunk(const uint8_t* Code) {
  if (!Code) {
    return nullptr;
  }

  // jmp rel32
  if (Code[0] == 0xE9) {
    int32_t Disp {};
    std::memcpy(&Disp, Code + 1, sizeof(Disp));
    return Code + 5 + Disp;
  }

  // jmp rel8
  if (Code[0] == 0xEB) {
    int8_t Disp {};
    std::memcpy(&Disp, Code + 1, sizeof(Disp));
    return Code + 2 + Disp;
  }

  return nullptr;
}

static std::optional<uint32_t> ExtractX86SyscallId(const void* Func) {
  if (!Func) {
    return std::nullopt;
  }

  const auto* Code = reinterpret_cast<const uint8_t*>(Func);

  if (IsReadablePtr(Code, 32)) {
    if (auto ID = ExtractX86SyscallIdAt(Code, 32)) {
      return ID;
    }
  }

  // Wine stubs may trampoline before the immediate syscall ID load.
  const auto* JumpTarget = FollowX86JmpThunk(Code);
  if (!JumpTarget) {
    return std::nullopt;
  }

  if (!IsReadablePtr(JumpTarget, 32)) {
    return std::nullopt;
  }

  return ExtractX86SyscallIdAt(JumpTarget, 32);
}

static void InitBNetLoggingAndIDs(HMODULE NtDllNative, uint64_t NtDllX86Handle) {
  const char* ForceLog = std::getenv("FEX_BNET_DETECT_LOG");
  const char* ForceX86 = std::getenv("FEX_BNET_FORCE_X86");
  BNetLogEnabled = ForceLog && ForceLog[0] == '1';
  BNetForceX86Enabled = ForceX86 && ForceX86[0] == '1';
  // Avoid log storms while still capturing the architecture probes.
  BNetLogBudget = 200;

  // In this file we often treat module handles as raw 64-bit values.
  // HMODULE is effectively the image base in Windows, so this is safe.
  const auto NtDllX86 = reinterpret_cast<HMODULE>(static_cast<uintptr_t>(NtDllX86Handle));
  // Always initialize syscall IDs so logging/spoofing can be enabled later without re-init.
  const auto InitOne = [&](const char* Name, std::optional<uint32_t>* Out) {
    const void* Sym {};
    if (NtDllX86) {
      // GetProcAddress follows the native loader view and does not resolve
      // exports from Wine's mapped i386 ntdll.  The ntdll helper parses the
      // supplied PE export table directly and therefore returns the real x86
      // syscall thunk whose mov-eax immediate we need.
      Sym = reinterpret_cast<const void*>(RtlFindExportedRoutineByName(NtDllX86, Name));
    }
    if (!Sym && NtDllNative) {
      Sym = reinterpret_cast<const void*>(GetProcAddress(NtDllNative, Name));
    }
    *Out = ExtractX86SyscallId(Sym);
  };

  InitOne("NtQuerySystemInformation", &BNetIDs.NtQuerySystemInformation);
  InitOne("NtQuerySystemInformationEx", &BNetIDs.NtQuerySystemInformationEx);
  InitOne("NtQueryInformationProcess", &BNetIDs.NtQueryInformationProcess);

  BNetForceX86Ready = BNetIDs.NtQuerySystemInformation && BNetIDs.NtQuerySystemInformationEx && BNetIDs.NtQueryInformationProcess;

  if (BNetLogEnabled) {
    BNetLog("FEX_BNET_DETECT: enabled force_x86={} scope_match={} ready={} ids(sys={},sysex={},proc={})",
            BNetForceX86Enabled ? 1U : 0U, BNetForceX86TargetProcess ? 1U : 0U, BNetForceX86Ready ? 1U : 0U,
            BNetIDs.NtQuerySystemInformation ? "ok" : "missing", BNetIDs.NtQuerySystemInformationEx ? "ok" : "missing",
            BNetIDs.NtQueryInformationProcess ? "ok" : "missing");
  }
}

fextl::unique_ptr<FEXCore::Context::Context> CTX;
fextl::unique_ptr<FEX::DummyHandlers::DummySignalDelegator> SignalDelegator;
fextl::unique_ptr<WowSyscallHandler> SyscallHandler;
fextl::unique_ptr<FEX::Windows::StatAlloc> StatAllocHandler;

std::optional<FEX::Windows::InvalidationTracker> InvalidationTracker;
std::optional<FEX::Windows::CPUFeatures> CPUFeatures;
std::optional<FEX::Windows::OvercommitTracker> OvercommitTracker;
std::optional<FEX::Windows::ImageTracker> ImageTracker;

std::mutex ThreadCreationMutex;
// Map of TIDs to their FEX thread state, `ThreadCreationMutex` must be locked when accessing
std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*> Threads;

decltype(__wine_unix_call_dispatcher) WineUnixCall;

std::pair<NTSTATUS, TLS> GetThreadTLS(HANDLE Thread) {
  THREAD_BASIC_INFORMATION Info;
  const NTSTATUS Err = NtQueryInformationThread(Thread, ThreadBasicInformation, &Info, sizeof(Info), nullptr);
  return {Err, TLS {reinterpret_cast<_TEB*>(Info.TebBaseAddress)}};
}

TLS GetTLS() {
  return TLS {NtCurrentTeb()};
}

FrontendThreadData* GetFrontendThreadData(FEXCore::Core::InternalThreadState* Thread) {
  return static_cast<FrontendThreadData*>(Thread->FrontendPtr);
}

uint64_t GetWowTEB(void* TEB) {
  static constexpr size_t WowTEBOffsetMemberOffset {0x180c};
  return static_cast<uint64_t>(
    *reinterpret_cast<LONG*>(reinterpret_cast<uintptr_t>(TEB) + WowTEBOffsetMemberOffset) + reinterpret_cast<uint64_t>(TEB));
}

bool IsDispatcherAddress(uint64_t Address) {
  const auto& Config = SignalDelegator->GetConfig();
  return Address >= Config.DispatcherBegin && Address < Config.DispatcherEnd;
}

bool IsAddressInJit(uint64_t Address) {
  if (IsDispatcherAddress(Address)) {
    return true;
  }

  auto Thread = GetTLS().ThreadState();
  return Thread->CTX->IsAddressInCodeBuffer(Thread, Address);
}

void HandleImageMap(uint64_t Address, bool MainImage = false) {
  fextl::string ModulePath = FEX::Windows::GetSectionFilePath(Address);
  fextl::string ModuleName = fextl::string {FEX::Windows::BaseName(ModulePath)};
  InvalidationTracker->HandleImageMap(ModuleName, Address);
  ImageTracker->HandleImageMap(ModulePath, Address, MainImage);
}

void HandleImageUnmap(uint64_t Address, uint64_t Size) {
  ImageTracker->HandleImageUnmap(Address, Size);
}
} // namespace

namespace Context {
void LoadStateFromWowContext(FEXCore::Core::InternalThreadState* Thread, uint64_t WowTEB, WOW64_CONTEXT* Context) {
  auto& State = Thread->CurrentFrame->State;

  // General register state

  State.gregs[FEXCore::X86State::REG_RAX] = Context->Eax;
  State.gregs[FEXCore::X86State::REG_RBX] = Context->Ebx;
  State.gregs[FEXCore::X86State::REG_RCX] = Context->Ecx;
  State.gregs[FEXCore::X86State::REG_RDX] = Context->Edx;
  State.gregs[FEXCore::X86State::REG_RSI] = Context->Esi;
  State.gregs[FEXCore::X86State::REG_RDI] = Context->Edi;
  State.gregs[FEXCore::X86State::REG_RBP] = Context->Ebp;
  State.gregs[FEXCore::X86State::REG_RSP] = Context->Esp;

  State.rip = Context->Eip;
  CTX->SetFlagsFromCompactedEFLAGS(Thread, Context->EFlags);

  State.es_idx = Context->SegEs & 0xffff;
  State.cs_idx = Context->SegCs & 0xffff;
  State.ss_idx = Context->SegSs & 0xffff;
  State.ds_idx = Context->SegDs & 0xffff;
  State.fs_idx = Context->SegFs & 0xffff;
  State.gs_idx = Context->SegGs & 0xffff;

  // The TEB is the only populated GDT entry by default
  auto GDT = State.GetSegmentFromIndex(State, (Context->SegFs & 0xffff));
  State.SetGDTBase(GDT, WowTEB);
  State.SetGDTLimit(GDT, 0xF'FFFFU);
  State.fs_cached = WowTEB;
  State.es_cached = 0;
  State.cs_cached = 0;
  State.ss_cached = 0;
  State.ds_cached = 0;

  // Floating-point register state
  const auto* XSave = reinterpret_cast<XSAVE_FORMAT*>(Context->ExtendedRegisters);

  CTX->SetXMMRegistersFromState(Thread, reinterpret_cast<const __uint128_t*>(XSave->XmmRegisters), nullptr);
  memcpy(State.mm, XSave->FloatRegisters, sizeof(State.mm));

  State.FCW = XSave->ControlWord;
  State.flags[FEXCore::X86State::X87FLAG_IE_LOC] = XSave->StatusWord & 1;
  State.flags[FEXCore::X86State::X87FLAG_C0_LOC] = (XSave->StatusWord >> 8) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C1_LOC] = (XSave->StatusWord >> 9) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C2_LOC] = (XSave->StatusWord >> 10) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C3_LOC] = (XSave->StatusWord >> 14) & 1;
  State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] = (XSave->StatusWord >> 11) & 0b111;
  State.AbridgedFTW = XSave->TagWord;
}

void StoreWowContextFromState(FEXCore::Core::InternalThreadState* Thread, WOW64_CONTEXT* Context) {
  auto& State = Thread->CurrentFrame->State;

  // General register state

  Context->Eax = State.gregs[FEXCore::X86State::REG_RAX];
  Context->Ebx = State.gregs[FEXCore::X86State::REG_RBX];
  Context->Ecx = State.gregs[FEXCore::X86State::REG_RCX];
  Context->Edx = State.gregs[FEXCore::X86State::REG_RDX];
  Context->Esi = State.gregs[FEXCore::X86State::REG_RSI];
  Context->Edi = State.gregs[FEXCore::X86State::REG_RDI];
  Context->Ebp = State.gregs[FEXCore::X86State::REG_RBP];
  Context->Esp = State.gregs[FEXCore::X86State::REG_RSP];

  Context->Eip = State.rip;
  Context->EFlags = CTX->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0);

  Context->SegEs = State.es_idx;
  Context->SegCs = State.cs_idx;
  Context->SegSs = State.ss_idx;
  Context->SegDs = State.ds_idx;
  Context->SegFs = State.fs_idx;
  Context->SegGs = State.gs_idx;

  // Floating-point register state

  auto* XSave = reinterpret_cast<XSAVE_FORMAT*>(Context->ExtendedRegisters);

  CTX->ReconstructXMMRegisters(Thread, reinterpret_cast<__uint128_t*>(XSave->XmmRegisters), nullptr);
  memcpy(XSave->FloatRegisters, State.mm, sizeof(State.mm));

  XSave->ControlWord = State.FCW;
  XSave->StatusWord = (State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] << 11) | (State.flags[FEXCore::X86State::X87FLAG_C0_LOC] << 8) |
                      (State.flags[FEXCore::X86State::X87FLAG_C1_LOC] << 9) | (State.flags[FEXCore::X86State::X87FLAG_C2_LOC] << 10) |
                      (State.flags[FEXCore::X86State::X87FLAG_C3_LOC] << 14) | State.flags[FEXCore::X86State::X87FLAG_IE_LOC];
  XSave->TagWord = State.AbridgedFTW;

  Context->FloatSave.ControlWord = XSave->ControlWord;
  Context->FloatSave.StatusWord = XSave->StatusWord;
  Context->FloatSave.TagWord = FEXCore::FPState::ConvertFromAbridgedFTW(XSave->StatusWord, State.mm, XSave->TagWord);
  Context->FloatSave.ErrorOffset = XSave->ErrorOffset;
  Context->FloatSave.ErrorSelector = XSave->ErrorSelector | (XSave->ErrorOpcode << 16);
  Context->FloatSave.DataOffset = XSave->DataOffset;
  Context->FloatSave.DataSelector = XSave->DataSelector;
  Context->FloatSave.Cr0NpxState = XSave->StatusWord | 0xffff0000;
}

NTSTATUS FlushThreadStateContext(HANDLE Thread) {
  const auto [Err, TLS] = GetThreadTLS(Thread);
  if (Err) {
    return Err;
  }

  WOW64_CONTEXT TmpWowContext {.ContextFlags = WOW64_CONTEXT_FULL | WOW64_CONTEXT_EXTENDED_REGISTERS};

  Context::StoreWowContextFromState(TLS.ThreadState(), &TmpWowContext);
  return RtlWow64SetThreadContext(Thread, &TmpWowContext);
}

void ReconstructThreadState(TLS TLS, CONTEXT* Context) {
  const auto& Config = SignalDelegator->GetConfig();
  auto* Thread = TLS.ThreadState();
  auto& State = Thread->CurrentFrame->State;

  State.rip = CTX->RestoreRIPFromHostPC(Thread, Context->Pc);

  // Spill all SRA GPRs
  for (size_t i = 0; i < Config.SRAGPRCount; i++) {
    State.gregs[i] = Context->X[Config.SRAGPRMapping[i]];
  }

  // Spill all SRA FPRs
  for (size_t i = 0; i < Config.SRAFPRCount; i++) {
    memcpy(State.xmm.sse.data[i], &Context->V[Config.SRAFPRMapping[i]], sizeof(__uint128_t));
  }

  // Spill EFlags
  uint32_t EFlags = CTX->ReconstructCompactedEFLAGS(Thread, true, Context->X, Context->Cpsr);
  CTX->SetFlagsFromCompactedEFLAGS(Thread, EFlags);
}

WOW64_CONTEXT ReconstructWowContext(TLS TLS, CONTEXT* Context) {
  if (!IsDispatcherAddress(Context->Pc)) {
    ReconstructThreadState(TLS, Context);
  }

  WOW64_CONTEXT WowContext {
    .ContextFlags = WOW64_CONTEXT_ALL,
  };

  auto* XSave = reinterpret_cast<XSAVE_FORMAT*>(WowContext.ExtendedRegisters);
  XSave->ControlWord = 0x27f;
  XSave->MxCsr = 0x1f80;

  Context::StoreWowContextFromState(TLS.ThreadState(), &WowContext);
  return WowContext;
}

static std::optional<FEX::Windows::TSOHandlerConfig> HandlerConfig;

bool HandleUnalignedAccess(TLS TLS, CONTEXT* Context) {
  auto Thread = TLS.ThreadState();
  if (!Thread->CTX->IsAddressInCodeBuffer(Thread, Context->Pc)) {
    return false;
  }

  const auto Result =
    FEXCore::ArchHelpers::Arm64::HandleUnalignedAccess(Thread, HandlerConfig->GetUnalignedHandlerType(), Context->Pc, &Context->X0);
  Context->Pc += Result.value_or(0);
  return Result.has_value();
}

void LockJITContext(TLS TLS) {
  uint32_t Expected = TLS.ControlWord().load(), New;

  // Spin until PAUSED is unset, setting IN_JIT when that occurs
  do {
    Expected = Expected & ~ControlBits::PAUSED;
    New = (Expected | ControlBits::IN_JIT) & ~ControlBits::WOW_CPU_AREA_DIRTY;
  } while (!TLS.ControlWord().compare_exchange_weak(Expected, New, std::memory_order::relaxed));
  std::atomic_signal_fence(std::memory_order::seq_cst);

  // If the CPU area is dirty, flush it to the JIT context before reentry
  if (Expected & ControlBits::WOW_CPU_AREA_DIRTY) {
    WOW64_CONTEXT* WowContext;
    RtlWow64GetCurrentCpuArea(nullptr, reinterpret_cast<void**>(&WowContext), nullptr);
    Context::LoadStateFromWowContext(TLS.ThreadState(), GetWowTEB(NtCurrentTeb()), WowContext);
  }
}

void UnlockJITContext(TLS TLS) {
  std::atomic_signal_fence(std::memory_order::seq_cst);
  TLS.ControlWord().fetch_and(~ControlBits::IN_JIT, std::memory_order::relaxed);
}

class ScopedJITContextLock {
private:
  TLS TLSData;

public:
  ScopedJITContextLock(TLS TLSData)
    : TLSData {TLSData} {
    LockJITContext(TLSData);
  }

  ~ScopedJITContextLock() {
    UnlockJITContext(TLSData);
  }
};

bool HandleSuspendInterrupt(TLS TLS, CONTEXT* Context, uint64_t FaultAddress) {
  if (FaultAddress != reinterpret_cast<uint64_t>(&TLS.ThreadState()->InterruptFaultPage)) {
    return false;
  }

  void* TmpAddress = reinterpret_cast<void*>(FaultAddress);
  SIZE_T TmpSize = FEXCore::Utils::FEX_PAGE_SIZE;
  ULONG TmpProt;
  NtProtectVirtualMemory(NtCurrentProcess(), &TmpAddress, &TmpSize, PAGE_READWRITE, &TmpProt);

  // Since interrupts only happen at the start of blocks, the reconstructed state should be entirely accurate
  ReconstructThreadState(TLS, Context);

  // Yield to the suspender
  UnlockJITContext(TLS);
  LockJITContext(TLS);

  // Adjust context to return to the dispatcher, reloading SRA from thread state
  const auto& Config = SignalDelegator->GetConfig();
  Context->Pc = Config.AbsoluteLoopTopAddressFillSRA;
  Context->X1 = 0; // Set ENTRY_FILL_SRA_SINGLE_INST_REG
  return true;
}
} // namespace Context

// Calls a 2-argument function `Func` setting the parent unwind frame information to the given SP and PC
__attribute__((naked)) extern "C" uint64_t SEHFrameTrampoline2Args(void* Arg0, void* Arg1, void* Func, uint64_t Sp, uint64_t Pc) {
  asm(".seh_proc SEHFrameTrampoline2Args;"
      "stp x3, x4, [sp, #-0x10]!;"
      ".seh_pushframe;"
      "stp x29, x30, [sp, #-0x10]!;"
      ".seh_save_fplr_x 16;"
      ".seh_endprologue;"
      "blr x2;"
      "ldp x29, x30, [sp], 0x20;"
      "ret;"
      ".seh_endproc;");
}

class WowSyscallHandler : public FEXCore::HLE::SyscallHandler, public FEXCore::Allocator::FEXAllocOperators {
public:
  WowSyscallHandler() {
    OSABI = FEXCore::HLE::SyscallOSABI::OS_GENERIC;
  }

  static uint64_t HandleSyscallImpl(FEXCore::Core::CpuStateFrame* Frame, FEXCore::HLE::SyscallArguments* Args) {
    const uint64_t ReturnRIP = *(uint32_t*)(Frame->State.gregs[FEXCore::X86State::REG_RSP]); // Return address from the stack
    uint64_t ReturnRSP = Frame->State.gregs[FEXCore::X86State::REG_RSP] + 4;                 // Stack pointer after popping return address
    uint64_t ReturnRAX = 0;

    if (Frame->State.rip == (uint64_t)BridgeInstrs::UnixCall) {
      struct StackLayout {
        unixlib_handle_t Handle;
        UINT32 ID;
        ULONG32 Args;
      }* StackArgs = reinterpret_cast<StackLayout*>(ReturnRSP);

      ReturnRSP += sizeof(StackLayout);

      const auto TLS = GetTLS();
      Context::UnlockJITContext(TLS);
      ReturnRAX = static_cast<uint64_t>(WineUnixCall(StackArgs->Handle, StackArgs->ID, ULongToPtr(StackArgs->Args)));
      Context::LockJITContext(TLS);
    } else if (Frame->State.rip == (uint64_t)BridgeInstrs::Syscall) {
      const uint64_t EntryRAX = Frame->State.gregs[FEXCore::X86State::REG_RAX];
      auto* SysArgs32 = reinterpret_cast<uint32_t*>(ReturnRSP + 4);

      // Minimal, targeted syscall logging for Battle.net architecture detection.
      if (BNetLogEnabled) {
        auto LogNtQuerySystemInformation = [&]() {
          if (!BNetIDs.NtQuerySystemInformation || EntryRAX != *BNetIDs.NtQuerySystemInformation) {
            return;
          }
          // (class, out, len, retlen)
          if (const char* Hint = BNetSystemInfoClassHint(SysArgs32[0])) {
            BNetLog("FEX_BNET_DETECT: NtQuerySystemInformation(class={} {} out=0x{:08x} len={})", SysArgs32[0], Hint, SysArgs32[1],
                    SysArgs32[2]);
          }
        };
        auto LogNtQuerySystemInformationEx = [&]() {
          if (!BNetIDs.NtQuerySystemInformationEx || EntryRAX != *BNetIDs.NtQuerySystemInformationEx) {
            return;
          }
          NtQuerySystemInformationExArgs Args {};
          if (DecodeNtQuerySystemInformationExMachineProbe(SysArgs32, &Args)) {
            if (const char* Hint = BNetSystemInfoClassHint(Args.Class)) {
              BNetLog("FEX_BNET_DETECT: NtQuerySystemInformationEx(class={} {} out=0x{:08x} len={})", Args.Class, Hint, Args.OutputPtr,
                      Args.OutputLen);
            }
            return;
          }

          // Fallback to canonical field order when not recognized as machine-probe shape.
          if (const char* Hint = BNetSystemInfoClassHint(SysArgs32[0])) {
            BNetLog("FEX_BNET_DETECT: NtQuerySystemInformationEx(class={} {} out=0x{:08x} len={})", SysArgs32[0], Hint, SysArgs32[3], SysArgs32[4]);
          }
        };
        auto LogNtQueryInformationProcess = [&]() {
          if (!BNetIDs.NtQueryInformationProcess || EntryRAX != *BNetIDs.NtQueryInformationProcess) {
            return;
          }
          // (handle, class, out, len, retlen)
          if (const char* Hint = BNetProcessInfoClassHint(SysArgs32[1])) {
            BNetLog("FEX_BNET_DETECT: NtQueryInformationProcess(h=0x{:08x} class={} {} out=0x{:08x} len={})", SysArgs32[0], SysArgs32[1], Hint,
                    SysArgs32[2], SysArgs32[3]);
          }
        };

        LogNtQuerySystemInformation();
        LogNtQuerySystemInformationEx();
        LogNtQueryInformationProcess();
      }

      const auto TLS = GetTLS();
      Context::UnlockJITContext(TLS);
      Wow64ProcessPendingCrossProcessItems();
      ReturnRAX = static_cast<uint64_t>(Wow64SystemServiceEx(static_cast<UINT>(EntryRAX), reinterpret_cast<UINT*>(ReturnRSP + 4)));
      Context::LockJITContext(TLS);

      if (BNetForceX86Enabled && BNetForceX86TargetProcess && BNetForceX86Ready) {
        constexpr uint32_t ProcessMachineInformation = 88;

        // Hard fallback for IsWow64Process2 path: if ProcessMachineInformation
        // probing fails, synthesize a successful x86/amd64 tuple.
        if (BNetIDs.NtQueryInformationProcess && EntryRAX == *BNetIDs.NtQueryInformationProcess &&
            SysArgs32[1] == ProcessMachineInformation) {
          const bool ForcedTuple = ForceX86WriteProcessMachineTuple(SysArgs32[2], SysArgs32[3]);
          if (ForcedTuple && ReturnRAX != 0) {
            BNetLog("FEX_BNET_DETECT: force_x86 NtQueryInformationProcess(class={}) synthesized_success status=0x{:08x}", SysArgs32[1],
                    static_cast<uint32_t>(ReturnRAX));
            ReturnRAX = 0;
          } else if (ForcedTuple) {
            BNetLog("FEX_BNET_DETECT: force_x86 NtQueryInformationProcess(class={}) patched", SysArgs32[1]);
          }
        }

        if (ReturnRAX == 0) {
          bool Patched {};
          if (BNetIDs.NtQuerySystemInformation && EntryRAX == *BNetIDs.NtQuerySystemInformation) {
            Patched = ForceX86PatchSystemInfo(SysArgs32[0], SysArgs32[1], SysArgs32[2]);
            if (Patched) {
              BNetLog("FEX_BNET_DETECT: force_x86 NtQuerySystemInformation(class={}) patched", SysArgs32[0]);
            }
          } else if (BNetIDs.NtQuerySystemInformationEx && EntryRAX == *BNetIDs.NtQuerySystemInformationEx) {
            NtQuerySystemInformationExArgs Args {};
            uint32_t PatchedClass {};
            if (DecodeNtQuerySystemInformationExMachineProbe(SysArgs32, &Args)) {
              Patched = ForceX86PatchSystemInfoEx(Args.Class, Args.OutputPtr, Args.OutputLen);
              PatchedClass = Args.Class;
            } else {
              Patched = ForceX86PatchSystemInfoEx(SysArgs32[0], SysArgs32[3], SysArgs32[4]);
              PatchedClass = SysArgs32[0];
            }
            if (Patched) {
              BNetLog("FEX_BNET_DETECT: force_x86 NtQuerySystemInformationEx(class={}) patched", PatchedClass);
            }
          }
        }
      }

      if (BNetLogEnabled) {
        const char* Name {nullptr};
        uint32_t Class {0};
        uint32_t OutPtr {0};
        uint32_t Len {0};
        const char* Hint {nullptr};
        if (BNetIDs.NtQuerySystemInformation && EntryRAX == *BNetIDs.NtQuerySystemInformation) {
          Name = "NtQuerySystemInformation";
          Class = SysArgs32[0];
          OutPtr = SysArgs32[1];
          Len = SysArgs32[2];
          Hint = BNetSystemInfoClassHint(Class);
        } else if (BNetIDs.NtQuerySystemInformationEx && EntryRAX == *BNetIDs.NtQuerySystemInformationEx) {
          NtQuerySystemInformationExArgs Args {};
          Name = "NtQuerySystemInformationEx";
          if (DecodeNtQuerySystemInformationExMachineProbe(SysArgs32, &Args)) {
            Class = Args.Class;
            OutPtr = Args.OutputPtr;
            Len = Args.OutputLen;
          } else {
            Class = SysArgs32[0];
            OutPtr = SysArgs32[3];
            Len = SysArgs32[4];
          }
          Hint = BNetSystemInfoClassHint(Class);
        } else if (BNetIDs.NtQueryInformationProcess && EntryRAX == *BNetIDs.NtQueryInformationProcess) {
          Name = "NtQueryInformationProcess";
          Class = SysArgs32[1];
          OutPtr = SysArgs32[2];
          Len = SysArgs32[3];
          Hint = BNetProcessInfoClassHint(Class);
        }
        if (Name && Hint) {
          if (ReturnRAX == 0 && OutPtr && Len >= sizeof(uint16_t)) {
            const auto* Words = reinterpret_cast<const uint16_t*>(static_cast<uintptr_t>(OutPtr));
            if (IsReadablePtr(Words, sizeof(uint16_t))) {
              const auto First = Words[0];
              if (Len >= sizeof(uint16_t) * 2 && IsReadablePtr(Words, sizeof(uint16_t) * 2)) {
                BNetLog("FEX_BNET_DETECT: {} {} -> status=0x{:08x} out=[0x{:04x},0x{:04x}]",
                        Name, Hint, static_cast<uint32_t>(ReturnRAX), First, Words[1]);
              } else {
                BNetLog("FEX_BNET_DETECT: {} {} -> status=0x{:08x} out=[0x{:04x}]",
                        Name, Hint, static_cast<uint32_t>(ReturnRAX), First);
              }
            } else {
              BNetLog("FEX_BNET_DETECT: {} {} -> status=0x{:08x} out=unreadable", Name, Hint, static_cast<uint32_t>(ReturnRAX));
            }
          } else {
            BNetLog("FEX_BNET_DETECT: {} {} -> status=0x{:08x}", Name, Hint, static_cast<uint32_t>(ReturnRAX));
          }
        }
      }
    }
    // If a new context has been set, use it directly and don't return to the syscall caller
    if (Frame->State.rip == (uint64_t)BridgeInstrs::Syscall || Frame->State.rip == (uint64_t)BridgeInstrs::UnixCall) {
      Frame->State.gregs[FEXCore::X86State::REG_RAX] = ReturnRAX;
      Frame->State.gregs[FEXCore::X86State::REG_RSP] = ReturnRSP;
      Frame->State.rip = ReturnRIP;
    }

    // NORETURNEDRESULT causes this result to be ignored since we restore all registers back from memory after a syscall anyway
    return 0;
  }

  uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame* Frame, FEXCore::HLE::SyscallArguments* Args) override {
    const auto TLS = GetTLS();
    // Stash the the context pointer on the stack, as Simulate can be called from this syscall handler which would overwrite it
    CONTEXT* EntryContext = TLS.EntryContext();
    // Call the syscall handler with unwind information pointing to Simulate as its caller
    uint64_t Ret = SEHFrameTrampoline2Args(reinterpret_cast<void*>(Frame), reinterpret_cast<void*>(Args),
                                           reinterpret_cast<void*>(&HandleSyscallImpl), EntryContext->Sp, EntryContext->Pc);
    TLS.EntryContext() = EntryContext;
    return Ret;
  }

  std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(FEXCore::Core::InternalThreadState*, uint64_t Address) override {
    return ImageTracker->LookupExecutableFileSection(Address);
  }

  void MarkGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) override {
    InvalidationTracker->ReprotectRWXIntervals(Start, Length);
  }

  void InvalidateGuestCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) override {
    InvalidationTracker->InvalidateAlignedInterval(Start, Length, false);
  }

  void MarkOvercommitRange(uint64_t Start, uint64_t Length) override {
    OvercommitTracker->MarkRange(Start, Length);
  }

  void UnmarkOvercommitRange(uint64_t Start, uint64_t Length) override {
    OvercommitTracker->UnmarkRange(Start, Length);
  }

  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Address) override {
    return InvalidationTracker->QueryExecutableRange(Address);
  }

  void PreCompile() override {
    Wow64ProcessPendingCrossProcessItems();
  }
};

void BTCpuProcessInit() {
  FEX::Windows::InitCRTProcess();
  const auto ExecutableName = FEX::Windows::BaseName(FEX::Windows::GetExecutableFilePath());
  BNetForceX86TargetProcess = IsBNetForceX86TargetProcess(ExecutableName);
  FEX::Config::LoadConfig(fextl::string {ExecutableName}, _environ, FEX::ReadPortabilityInformation());
  FEXCore::Config::ReloadMetaLayer();
  FEX::Windows::Logging::Init();

  FEXCore::Config::Set(FEXCore::Config::CONFIG_INTERPRETER_INSTALLED, "0");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "0");

  FEXCore::Profiler::Init("", "");

  SignalDelegator = fextl::make_unique<FEX::DummyHandlers::DummySignalDelegator>();
  SyscallHandler = fextl::make_unique<WowSyscallHandler>();
  const auto NtDll = GetModuleHandle("ntdll.dll");
  const bool IsWine = !!GetProcAddress(NtDll, "wine_get_version");
  OvercommitTracker.emplace(IsWine);

  FEX::Windows::Allocator::SetupHooks(NtDll);

  {
    auto HostFeatures = FEX::Windows::CPUFeatures::FetchHostFeatures(IsWine);
    // AVX is unsupported for WOW64
    HostFeatures.SupportsAVX = false;
    CTX = FEXCore::Context::Context::CreateNewContext(HostFeatures);
  }

  CTX->SetSignalDelegator(SignalDelegator.get());
  CTX->SetSyscallHandler(SyscallHandler.get());
  CTX->InitCore();
  Context::HandlerConfig.emplace(*CTX);
  InvalidationTracker.emplace(*CTX, Threads);
  ImageTracker.emplace(*CTX, false);

  auto MainModule = reinterpret_cast<__TEB*>(NtCurrentTeb())->Peb->ImageBaseAddress;
  HandleImageMap(reinterpret_cast<uint64_t>(MainModule), true);

  auto NtDllX86 = reinterpret_cast<SYSTEM_DLL_INIT_BLOCK*>(GetProcAddress(NtDll, "LdrSystemDllInitBlock"))->ntdll_handle;
  HandleImageMap(NtDllX86);
  InitBNetLoggingAndIDs(NtDll, NtDllX86);

  CPUFeatures.emplace(*CTX);

  // Allocate the syscall/unixcall trampolines in the lower 2GB of the address space
  SIZE_T Size = 4;
  void* Addr = nullptr;
  NtAllocateVirtualMemory(NtCurrentProcess(), &Addr, (1U << 31) - 1, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(Addr), Size, PAGE_EXECUTE);
  *reinterpret_cast<uint32_t*>(Addr) = 0x2ecd2ecd;
  BridgeInstrs::Syscall = Addr;
  BridgeInstrs::UnixCall = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(Addr) + 2);

  const auto Sym = GetProcAddress(NtDll, "__wine_unix_call_dispatcher");
  if (Sym) {
    WineUnixCall = *reinterpret_cast<decltype(WineUnixCall)*>(Sym);
  }

  FEX::Windows::SetupEnvironmentVariableValues(NtDll);

  // wow64.dll will only initialise the cross-process queue if this is set
  GetTLS().Wow64Info().CpuFlags = WOW64_CPUFLAGS_SOFTWARE;

  FEX_CONFIG_OPT(TSOEnabled, TSOENABLED);
  if (TSOEnabled()) {
    BOOL Enable = TRUE;
    NTSTATUS Status = NtSetInformationProcess(NtCurrentProcess(), ProcessFexHardwareTso, &Enable, sizeof(Enable));
    if (Status == STATUS_SUCCESS) {
      CTX->SetHardwareTSOSupport(true);
    }
  }

  FEX_CONFIG_OPT(ProfileStats, PROFILESTATS);
  FEX_CONFIG_OPT(StartupSleep, STARTUPSLEEP);
  FEX_CONFIG_OPT(StartupSleepProcName, STARTUPSLEEPPROCNAME);

  if (IsWine && ProfileStats()) {
    StatAllocHandler = fextl::make_unique<FEX::Windows::StatAlloc>(FEXCore::SHMStats::AppType::WIN_WOW64);
  }

  if (StartupSleep() && (StartupSleepProcName().empty() || ExecutableName == StartupSleepProcName())) {
    LogMan::Msg::IFmt("[{}][{}] Sleeping for {} seconds", GetCurrentProcessId(), ExecutableName, StartupSleep());
    std::this_thread::sleep_for(std::chrono::seconds(StartupSleep()));
  }
}

void BTCpuProcessTerm(HANDLE Handle, BOOL After, ULONG Status) {}

void BTCpuThreadInit() {
  static constexpr size_t DefaultWow64CS {4};
  std::scoped_lock Lock(ThreadCreationMutex);
  FEX::Windows::InitCRTThread();
  auto* Thread = CTX->CreateThread(0, 0);

  // Default segment setup.
  auto Frame = Thread->CurrentFrame;
  auto NewSegments = new FEXCore::Core::CPUState::gdt_segment[32]();

  // Setup initial code-segment GDT
  auto& GDT = NewSegments[DefaultWow64CS];
  FEXCore::Core::CPUState::SetGDTBase(&GDT, 0);
  FEXCore::Core::CPUState::SetGDTLimit(&GDT, 0xF'FFFFU);
  GDT.L = 0; // L = Long Mode = 32-bit
  GDT.D = 1; // D = Default Operand Size = 32-bit

  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = &NewSegments[0];
  // TODO: LDTs are currently unsupported, mirror them to GDT.
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = &NewSegments[0];

  Frame->State.cs_idx = DefaultWow64CS << 3;
  Frame->State.cs_cached = FEXCore::Core::CPUState::CalculateGDTBase(GDT);

  FEX::Windows::CallRetStack::InitializeThread(Thread);

  const auto TLS = GetTLS();
  TLS.ThreadState() = Thread;
  TLS.ControlWord().fetch_or(ControlBits::WOW_CPU_AREA_DIRTY, std::memory_order::relaxed);

  Thread->FrontendPtr = new FrontendThreadData();

  auto ThreadTID = GetCurrentThreadId();
  Threads.emplace(ThreadTID, Thread);
  if (StatAllocHandler) {
    Thread->ThreadStats = StatAllocHandler->AllocateSlot(ThreadTID);
  }
}

void BTCpuThreadTerm(HANDLE Thread, LONG ExitCode) {
  if (!FEX::Windows::ValidateHandleAccess(Thread, THREAD_TERMINATE)) {
    return;
  }

  auto ThreadDup = FEX::Windows::DupHandle(Thread, THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME);

  THREAD_BASIC_INFORMATION Info;
  if (auto Err = NtQueryInformationThread(*ThreadDup, ThreadBasicInformation, &Info, sizeof(Info), nullptr); Err) {
    return;
  }

  const auto ThreadTID = reinterpret_cast<uint64_t>(Info.ClientId.UniqueThread);
  bool Self = ThreadTID == GetCurrentThreadId();
  if (!Self) {
    // If we are suspending a thread that isn't ourselves, try to suspend it first so we know internal JIT locks aren't being held.
    RtlWow64SuspendThread(*ThreadDup, NULL);
  }

  auto [Err, TLS] = GetThreadTLS(*ThreadDup);
  if (Err) {
    return;
  }

  {
    std::scoped_lock Lock(ThreadCreationMutex);
    auto it = Threads.find(ThreadTID);
    if (it == Threads.end()) {
      // Thread already terminated
      return;
    }

    Threads.erase(it);
    if (StatAllocHandler) {
      StatAllocHandler->DeallocateSlot(TLS.ThreadState()->ThreadStats);
    }
  }
  auto ThreadState = TLS.ThreadState();

  delete GetFrontendThreadData(ThreadState);

  // GDT and LDT are mirrored, only free one.
  delete[] ThreadState->CurrentFrame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT];

  FEX::Windows::CallRetStack::DestroyThread(ThreadState);
  CTX->DestroyThread(ThreadState);
  if (Self) {
    FEX::Windows::DeinitCRTThread();
  }
}

void* BTCpuGetBopCode() {
  return BridgeInstrs::Syscall;
}

void* __wine_get_unix_opcode() {
  return BridgeInstrs::UnixCall;
}

NTSTATUS BTCpuGetContext(HANDLE Thread, HANDLE Process, void* Unknown, WOW64_CONTEXT* Context) {
  if (!FEX::Windows::ValidateHandleAccess(Thread, THREAD_GET_CONTEXT)) {
    return STATUS_ACCESS_DENIED;
  }

  auto ThreadDup = FEX::Windows::DupHandle(Thread, THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT);
  auto [Err, TLS] = GetThreadTLS(*ThreadDup);
  if (Err) {
    return Err;
  }

  Context::ScopedJITContextLock Lk {TLS};
  if (Err = Context::FlushThreadStateContext(*ThreadDup); Err) {
    return Err;
  }

  return RtlWow64GetThreadContext(*ThreadDup, Context);
}

NTSTATUS BTCpuSetContext(HANDLE Thread, HANDLE Process, void* Unknown, WOW64_CONTEXT* Context) {
  if (!FEX::Windows::ValidateHandleAccess(Thread, THREAD_SET_CONTEXT)) {
    return STATUS_ACCESS_DENIED;
  }

  auto ThreadDup = FEX::Windows::DupHandle(Thread, THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT);
  auto [Err, TLS] = GetThreadTLS(*ThreadDup);
  if (Err) {
    return Err;
  }

  // Back-up the input context incase we've been passed the CPU area (the flush below would wipe it out otherwise)
  WOW64_CONTEXT TmpContext = *Context;

  Context::ScopedJITContextLock Lk {TLS};
  if (Err = Context::FlushThreadStateContext(*ThreadDup); Err) {
    return Err;
  }

  // Merge the input context into the CPU area then pass the full context into the JIT
  if (Err = RtlWow64SetThreadContext(*ThreadDup, &TmpContext); Err) {
    return Err;
  }

  TmpContext.ContextFlags = WOW64_CONTEXT_FULL | WOW64_CONTEXT_EXTENDED_REGISTERS;

  if (Err = RtlWow64GetThreadContext(*ThreadDup, &TmpContext); Err) {
    return Err;
  }

  if (Thread == GetCurrentThread() && TLS.CachedCallRetSp()) {
    TLS.ThreadState()->CurrentFrame->State.callret_sp = TLS.CachedCallRetSp();
  }

  Context::LoadStateFromWowContext(TLS.ThreadState(), GetWowTEB(TLS.TEB), &TmpContext);
  return STATUS_SUCCESS;
}

// .seh_pushframe doesn't restore the frame pointer, so if when unwinding from RtlCaptureContext an operation is used
// that sets SP from FP, the unwound SP value will be incorrect. Wrap RtlCaptureContext so the correct FP is immediately
// restored from the stack to prevent this.
__attribute__((naked)) void BTCpuSimulate() {
  asm(".seh_proc BTCpuSimulate;"
      "sub sp, sp, #0x390;"
      ".seh_stackalloc 0x390;"
      "stp x29, x30, [sp, #-0x10]!;"
      ".seh_save_fplr_x 16;"
      ".seh_endprologue;"
      "add x0, sp, #0x10;"
      "bl RtlCaptureContext;"
      "add x0, sp, #0x10;"
      "bl BTCpuSimulateImpl;"
      "ldp x29, x30, [sp], 0x10;"
      "add sp, sp, #0x390;"
      "ret;"
      ".seh_endproc;");
}

extern "C" void BTCpuSimulateImpl(CONTEXT* entry_context) {
  const auto TLS = GetTLS();
  TLS.EntryContext() = entry_context;
  TLS.CachedCallRetSp() = TLS.ThreadState()->CurrentFrame->State.callret_sp;

  Context::ScopedJITContextLock Lk {TLS};
  CTX->ExecuteThread(TLS.ThreadState());
}

NTSTATUS BTCpuSuspendLocalThread(HANDLE Thread, ULONG* Count) {
  if (!FEX::Windows::ValidateHandleAccess(Thread, THREAD_SUSPEND_RESUME)) {
    return STATUS_ACCESS_DENIED;
  }

  auto ThreadDup = FEX::Windows::DupHandle(Thread, THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT);
  THREAD_BASIC_INFORMATION Info;
  if (NTSTATUS Err = NtQueryInformationThread(*ThreadDup, ThreadBasicInformation, &Info, sizeof(Info), nullptr); Err) {
    return Err;
  }

  const auto ThreadTID = reinterpret_cast<uint64_t>(Info.ClientId.UniqueThread);
  if (ThreadTID == GetCurrentThreadId()) {
    LogMan::Msg::DFmt("Suspending self");
    // Mark the CPU area as dirty, to force the JIT context to be restored from it on entry as it may be changed using
    // SetThreadContext (which doesn't use the BTCpu API)
    if (!(GetTLS().ControlWord().fetch_or(ControlBits::WOW_CPU_AREA_DIRTY, std::memory_order::relaxed) & ControlBits::WOW_CPU_AREA_DIRTY)) {
      if (NTSTATUS Err = Context::FlushThreadStateContext(*ThreadDup); Err) {
        return Err;
      }
    }

    return NtSuspendThread(*ThreadDup, Count);
  }

  LogMan::Msg::DFmt("Suspending thread: {:X}", ThreadTID);

  auto [Err, TLS] = GetThreadTLS(*ThreadDup);
  if (Err) {
    return Err;
  }

  std::scoped_lock Lock(ThreadCreationMutex);

  // If the thread hasn't yet been initialized, suspend it without special handling as it wont yet have entered the JIT
  if (!Threads.contains(ThreadTID)) {
    LogMan::Msg::DFmt("Thread suspended: {:X}", ThreadTID);
    return NtSuspendThread(*ThreadDup, Count);
  }

  // If CONTROL_IN_JIT is unset at this point, then it can never be set (and thus the JIT cannot be reentered) as
  // CONTROL_PAUSED has been set, as such, while this may redundantly request interrupts in rare cases it will never
  // miss them
  if (TLS.ControlWord().fetch_or(ControlBits::PAUSED, std::memory_order::relaxed) & ControlBits::IN_JIT) {
    LogMan::Msg::DFmt("Thread {:X} is in JIT, polling for interrupt", ThreadTID);

    ULONG TmpProt;
    void* TmpAddress = &TLS.ThreadState()->InterruptFaultPage;
    SIZE_T TmpSize = FEXCore::Utils::FEX_PAGE_SIZE;
    NtProtectVirtualMemory(NtCurrentProcess(), &TmpAddress, &TmpSize, PAGE_READONLY, &TmpProt);
  }

  // Spin until the JIT is interrupted
  while (TLS.ControlWord().load() & ControlBits::IN_JIT)
    ;

  // The JIT has now been interrupted and the context stored in the thread's CPU area is up-to-date
  if (Err = NtSuspendThread(*ThreadDup, Count); Err) {
    TLS.ControlWord().fetch_and(~ControlBits::PAUSED, std::memory_order::relaxed);
    return Err;
  }

  CONTEXT TmpContext {
    .ContextFlags = CONTEXT_INTEGER,
  };

  // NtSuspendThread may return before the thread is actually suspended, so a sync operation like NtGetContextThread
  // needs to be called to ensure it is before we unset CONTROL_PAUSED
  std::ignore = NtGetContextThread(*ThreadDup, &TmpContext);

  // Mark the CPU area as dirty, to force the JIT context to be restored from it on entry as it may be changed using
  // SetThreadContext (which doesn't use the BTCpu API)
  if (!(TLS.ControlWord().fetch_or(ControlBits::WOW_CPU_AREA_DIRTY, std::memory_order::relaxed) & ControlBits::WOW_CPU_AREA_DIRTY)) {
    if (Err = Context::FlushThreadStateContext(*ThreadDup); Err) {
      return Err;
    }
  }

  LogMan::Msg::DFmt("Thread suspended: {:X}", ThreadTID);

  // Now the thread is suspended on the host, unset CONTROL_PAUSED so that NtResumeThread will
  // continue execution in the JIT
  TLS.ControlWord().fetch_and(~ControlBits::PAUSED, std::memory_order::relaxed);

  return Err;
}

// Returns true if exception dispatch should be halted and the execution context restored to Ptrs->Context
bool BTCpuResetToConsistentStateImpl(EXCEPTION_POINTERS* Ptrs) {
  auto* Context = Ptrs->ContextRecord;
  auto* Exception = Ptrs->ExceptionRecord;
  auto TLS = GetTLS();
  auto Thread = TLS.ThreadState();
  FEXCORE_PROFILE_ACCUMULATION(Thread, AccumulatedSignalTime);

  if (Exception->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
    const auto FaultAddress = static_cast<uint64_t>(Exception->ExceptionInformation[1]);

    if (FEX::Windows::CallRetStack::HandleAccessViolation(Thread, FaultAddress, Context->X25)) {
      return true;
    }

    if (OvercommitTracker && OvercommitTracker->HandleAccessViolation(FaultAddress)) {
      return true;
    }

    if (Context::HandleSuspendInterrupt(TLS, Context, FaultAddress)) {
      LogMan::Msg::DFmt("Resumed from suspend");
      return true;
    }

    if (FEX::Windows::JITGuardPage::HandleJITGuardPage(Thread, reinterpret_cast<void*>(FaultAddress), Context->X,
                                                       reinterpret_cast<__uint128_t*>(Context->V), &Context->Pc)) {
      return true;
    }

    if (Thread) {
      std::scoped_lock Lock(ThreadCreationMutex);
      FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSMCCount, 1);
      if (InvalidationTracker->HandleRWXAccessViolation(Thread, Context->Pc, FaultAddress)) {
        if (CTX->IsAddressInCodeBuffer(Thread, Context->Pc) && !CTX->IsCurrentBlockSingleInst(Thread) &&
            CTX->IsAddressInCurrentBlock(Thread, FaultAddress & FEXCore::Utils::FEX_PAGE_MASK, FEXCore::Utils::FEX_PAGE_SIZE)) {
          Context::ReconstructThreadState(TLS, Context);
          LogMan::Msg::DFmt("Handled inline self-modifying code: pc: {:X} rip: {:X} fault: {:X}", Context->Pc,
                            Thread->CurrentFrame->State.rip, FaultAddress);

          // Adjust context to return to the dispatcher, reloading SRA from thread state
          const auto& Config = SignalDelegator->GetConfig();
          Context->Pc = Config.AbsoluteLoopTopAddressFillSRA;
          Context->X1 = 1; // Set ENTRY_FILL_SRA_SINGLE_INST_REG to force a single step
        } else {
          LogMan::Msg::DFmt("Handled self-modifying code: pc: {:X} fault: {:X}", Context->Pc, FaultAddress);
        }
        return true;
      }
    }
  }

  if (!Thread || !IsAddressInJit(Context->Pc)) {
    return false;
  }

  FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSIGBUSCount, 1);
  if (Exception->ExceptionCode == EXCEPTION_DATATYPE_MISALIGNMENT && Context::HandleUnalignedAccess(TLS, Context)) {
    LogMan::Msg::DFmt("Handled unaligned atomic: new pc: {:X}", Context->Pc);
    return true;
  }

  LogMan::Msg::DFmt("Reconstructing context");

  WOW64_CONTEXT WowContext = Context::ReconstructWowContext(TLS, Context);
  LogMan::Msg::DFmt("pc: {:X} eip: {:X}", Context->Pc, WowContext.Eip);

  auto& Fault = Thread->CurrentFrame->SynchronousFaultData;
  *Exception = FEX::Windows::
    HandleGuestException(Fault, Thread->CurrentFrame->SynchronousFaultAddress, *Exception, WowContext.Eip, WowContext.Eax);
  if (Exception->ExceptionCode == EXCEPTION_SINGLE_STEP) {
    WowContext.EFlags &= ~(1 << FEXCore::X86State::RFLAG_TF_RAW_LOC);
  }
  // wow64.dll will handle adjusting PC in the dispatched context after a breakpoint

  BTCpuSetContext(GetCurrentThread(), GetCurrentProcess(), nullptr, &WowContext);
  Context::UnlockJITContext(TLS);

  // Replace the host context with one captured before JIT entry so host code can unwind
  memcpy(Context, TLS.EntryContext(), sizeof(*Context));

  return false;
}

NTSTATUS BTCpuResetToConsistentState(EXCEPTION_POINTERS* Ptrs) {
  if (BTCpuResetToConsistentStateImpl(Ptrs)) {
    NtContinue(Ptrs->ContextRecord, FALSE);
  }

  return STATUS_SUCCESS;
}

void BTCpuFlushInstructionCache2(const void* Address, SIZE_T Size) {
  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
}

void BTCpuFlushInstructionCacheHeavy(const void* Address, SIZE_T Size) {
  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
}

void BTCpuNotifyMemoryDirty(void* Address, SIZE_T Size) {
  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
}

void BTCpuNotifyMemoryAlloc(void* Address, SIZE_T Size, ULONG Type, ULONG Prot, BOOL After, ULONG Status) {
  if (!After) {
    ThreadCreationMutex.lock();
  } else {
    // MEM_RESET(_UNDO) ignores the passed permissions
    if (!Status && !(Type & (MEM_RESET | MEM_RESET_UNDO))) {
      InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), Prot);
    }
    ThreadCreationMutex.unlock();
  }
}

void BTCpuNotifyMemoryProtect(void* Address, SIZE_T Size, ULONG NewProt, BOOL After, ULONG Status) {
  if (!After) {
    ThreadCreationMutex.lock();
  } else {
    if (!Status) {
      InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), NewProt);
    }
    ThreadCreationMutex.unlock();
  }
}

void BTCpuNotifyMemoryFree(void* Address, SIZE_T Size, ULONG FreeType, BOOL After, ULONG Status) {
  if (!After) {
    ThreadCreationMutex.lock();
  } else {
    if (!Status) {
      InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), true);
    }
    ThreadCreationMutex.unlock();
  }
}

NTSTATUS BTCpuNotifyMapViewOfSection(void* Unk1, void* Address, void* Unk2, SIZE_T Size, ULONG AllocType, ULONG Prot) {
  std::scoped_lock Lock(ThreadCreationMutex);
  HandleImageMap(reinterpret_cast<uint64_t>(Address));
  return STATUS_SUCCESS;
}

void BTCpuNotifyUnmapViewOfSection(void* Address, BOOL After, ULONG Status) {
  if (!After) {
    ThreadCreationMutex.lock();
    auto [Start, Size] = InvalidationTracker->InvalidateContainingSection(reinterpret_cast<uint64_t>(Address), true);
    if (Size) {
      HandleImageUnmap(Start, Size);
    }
  } else {
    ThreadCreationMutex.unlock();
  }
}

void BTCpuNotifyReadFile(HANDLE Handle, void* Address, SIZE_T Size, BOOL After, NTSTATUS Status) {
  auto& InLockedRWXRead = GetFrontendThreadData(GetTLS().ThreadState())->InLockedRWXRead;
  if (!After) {
    ThreadCreationMutex.lock();
    CTX->GetCodeInvalidationMutex().lock();
    if (InvalidationTracker->BeginUntrackedWriteLocked(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size))) {
      InLockedRWXRead = true;
    } else {
      CTX->GetCodeInvalidationMutex().unlock();
      ThreadCreationMutex.unlock();
    }
  } else {
    if (InLockedRWXRead) {
      InLockedRWXRead = false;
      CTX->GetCodeInvalidationMutex().unlock();
      ThreadCreationMutex.unlock();
    }
  }
}

void BTCpuNotifyProcessExecuteFlagsChange(ULONG Flags) {
  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->HandleProcessExecuteFlagsChange(Flags);
}

BOOLEAN WINAPI BTCpuIsProcessorFeaturePresent(UINT Feature) {
  return CPUFeatures->IsFeaturePresent(Feature) ? TRUE : FALSE;
}

void BTCpuUpdateProcessorInformation(SYSTEM_CPU_INFORMATION* Info) {
  CPUFeatures->UpdateInformation(Info);
}
