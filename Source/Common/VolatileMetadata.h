// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Utils/IntervalList.h>
#include <FEXCore/fextl/unordered_map.h>
#include <FEXCore/fextl/set.h>
#include <FEXCore/fextl/string.h>

#include <string_view>

namespace FEX::VolatileMetadata {
struct ExtendedVolatileMetadata {
  FEXCore::IntervalList<uint64_t> VolatileValidRanges;
  fextl::set<uint64_t> VolatileInstructions;
  bool ModuleTSODisabled;
};

struct TSOWhitelistMetadata {
  FEXCore::IntervalList<uint64_t> EnabledRanges;
  fextl::set<uint64_t> EnabledInstructions;
};

struct TSOWhitelistConfig {
  bool Valid {true};
  fextl::unordered_map<fextl::string, TSOWhitelistMetadata> Modules;
};

fextl::unordered_map<fextl::string, ExtendedVolatileMetadata> ParseExtendedVolatileMetadata(std::string_view ListOfDescriptors);
TSOWhitelistConfig ParseTSOWhitelist(std::string_view ListOfDescriptors);

inline void ApplyFEXExtendedVolatileMetadata(FEX::VolatileMetadata::ExtendedVolatileMetadata& ExtendedMetaData,
                                             fextl::set<uint64_t>& VolatileInstructions, FEXCore::IntervalList<uint64_t>& VolatileValidRanges,
                                             uint64_t Address, uint64_t EndAddress, uint64_t FileOffset = 0, uint64_t FileOffsetEnd = ~0ULL) {
  // Load FEX extended volatile metadata.
  // Walk the volatile instructions first if they exist.
  for (const auto it_inst : ExtendedMetaData.VolatileInstructions) {
    const auto inst_address = it_inst + Address;
    if (inst_address < EndAddress) {
      VolatileInstructions.emplace(Address + it_inst);
    } else {
      LogMan::Msg::DFmt("Volatile instruction 0x{:x} couldn't fit in to module range [0x{:x}, 0x{:x}). Not adding anymore volatile "
                        "instructions. Inspect your config!",
                        inst_address, Address, EndAddress);
      return;
    }
  }

  // Walk the volatile list
  for (const auto it_ranges : ExtendedMetaData.VolatileValidRanges) {
    if (it_ranges.Offset >= FileOffset && it_ranges.End < FileOffsetEnd) {
      VolatileValidRanges.Insert({Address + it_ranges.Offset - FileOffset, Address + it_ranges.End - FileOffset});
    }
  }

  // If it is fully disabled, then set the entire module range
  if (ExtendedMetaData.ModuleTSODisabled) {
    VolatileValidRanges.Clear();
    VolatileValidRanges.Insert({Address, EndAddress});
  }
}

inline bool ApplyTSOWhitelistMetadata(const FEX::VolatileMetadata::TSOWhitelistMetadata& Metadata,
                                      FEXCore::IntervalList<uint64_t>& ModuleRanges,
                                      FEXCore::IntervalList<uint64_t>& EnabledRanges, fextl::set<uint64_t>& EnabledInstructions,
                                      uint64_t Address, uint64_t EndAddress) {
  const uint64_t ModuleSize = EndAddress - Address;

  // Validate everything before applying anything. A malformed descriptor must
  // leave the module on the safe global TSO policy rather than partially
  // disabling its memory ordering.
  for (const auto& Range : Metadata.EnabledRanges) {
    if (Range.Offset >= Range.End || Range.End > ModuleSize) {
      LogMan::Msg::EFmt("TSO whitelist range [{:#x}, {:#x}) is outside module size {:#x}", Range.Offset, Range.End, ModuleSize);
      return false;
    }
  }
  for (const auto Offset : Metadata.EnabledInstructions) {
    if (Offset >= ModuleSize) {
      LogMan::Msg::EFmt("TSO whitelist instruction {:#x} is outside module size {:#x}", Offset, ModuleSize);
      return false;
    }
  }

  ModuleRanges.Insert({Address, EndAddress});
  for (const auto& Range : Metadata.EnabledRanges) {
    EnabledRanges.Insert({Address + Range.Offset, Address + Range.End});
  }
  for (const auto Offset : Metadata.EnabledInstructions) {
    EnabledInstructions.emplace(Address + Offset);
  }
  return true;
}

} // namespace FEX::VolatileMetadata
