// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Utils/IntervalList.h>
#include <FEXCore/fextl/set.h>

#include <cstdint>
#include <optional>

namespace FEXCore::Core {
struct ForceTSOBlockInfo {
  bool InValidRange {};
  std::optional<uint64_t> FirstForceTSOInstruction;
};

struct TSOWhitelistInfo {
  bool InWhitelistedModule {};
  bool ForceEnabled {};
};

enum class TSOPolicyOverride {
  NoOverride,
  ForceDisabled,
  ForceEnabled,
};

inline ForceTSOBlockInfo GetForceTSOBlockInfo(const IntervalList<uint64_t>& ValidRanges, const fextl::set<uint64_t>& Instructions,
                                              uint64_t BlockEntry, uint64_t BlockSize) {
  const bool RangeContainsBlock = ValidRanges.Contains({BlockEntry, BlockEntry + BlockSize});
  if (!RangeContainsBlock) {
    return {};
  }

  const auto It = Instructions.lower_bound(BlockEntry);
  if (It != Instructions.end() && *It < BlockEntry + BlockSize) {
    return {
      .InValidRange = true,
      .FirstForceTSOInstruction = *It,
    };
  }

  return {
    .InValidRange = true,
  };
}

inline TSOWhitelistInfo GetTSOWhitelistInfo(const IntervalList<uint64_t>& ModuleRanges, const IntervalList<uint64_t>& EnabledRanges,
                                            const fextl::set<uint64_t>& Instructions, uint64_t InstructionAddress) {
  const bool InWhitelistedModule = ModuleRanges.Query(InstructionAddress).Enclosed;
  const bool ForceEnabled = InWhitelistedModule &&
                            (EnabledRanges.Query(InstructionAddress).Enclosed || Instructions.contains(InstructionAddress));
  return {.InWhitelistedModule = InWhitelistedModule, .ForceEnabled = ForceEnabled};
}

inline TSOPolicyOverride ResolveTSOPolicy(bool ExplicitForceTSO, bool InstructionForceTSO, const TSOWhitelistInfo& Whitelist,
                                          bool InExtendedMetadataRange) {
  if (ExplicitForceTSO || InstructionForceTSO || Whitelist.ForceEnabled) {
    return TSOPolicyOverride::ForceEnabled;
  }
  if (Whitelist.InWhitelistedModule || InExtendedMetadataRange) {
    return TSOPolicyOverride::ForceDisabled;
  }
  return TSOPolicyOverride::NoOverride;
}

inline void RemoveTSOWhitelistInformation(IntervalList<uint64_t>& ModuleRanges, IntervalList<uint64_t>& EnabledRanges,
                                          fextl::set<uint64_t>& Instructions, uint64_t Address, uint64_t Size) {
  ModuleRanges.Remove({Address, Address + Size});
  EnabledRanges.Remove({Address, Address + Size});
  Instructions.erase(Instructions.lower_bound(Address), Instructions.lower_bound(Address + Size));
}
} // namespace FEXCore::Core
