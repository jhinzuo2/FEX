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
} // namespace FEXCore::Core
