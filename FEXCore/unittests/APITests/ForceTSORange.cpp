// SPDX-License-Identifier: MIT
#include "Interface/Core/ForceTSO.h"

#include <catch2/catch_all.hpp>

TEST_CASE("ForceTSO - range with no instruction opt-ins") {
  FEXCore::IntervalList<uint64_t> Ranges;
  Ranges.Insert({0x1000, 0x1100});
  fextl::set<uint64_t> Instructions;

  const auto Result = FEXCore::Core::GetForceTSOBlockInfo(Ranges, Instructions, 0x1020, 0x20);
  CHECK(Result.InValidRange);
  CHECK_FALSE(Result.FirstForceTSOInstruction.has_value());
}

TEST_CASE("ForceTSO - instruction opt-in inside range") {
  FEXCore::IntervalList<uint64_t> Ranges;
  Ranges.Insert({0x1000, 0x1100});
  fextl::set<uint64_t> Instructions {0x1030};

  const auto Result = FEXCore::Core::GetForceTSOBlockInfo(Ranges, Instructions, 0x1020, 0x20);
  CHECK(Result.InValidRange);
  REQUIRE(Result.FirstForceTSOInstruction.has_value());
  CHECK(*Result.FirstForceTSOInstruction == 0x1030);
}

TEST_CASE("ForceTSO - instruction opt-in outside block") {
  FEXCore::IntervalList<uint64_t> Ranges;
  Ranges.Insert({0x1000, 0x1100});
  fextl::set<uint64_t> Instructions {0x1080};

  const auto Result = FEXCore::Core::GetForceTSOBlockInfo(Ranges, Instructions, 0x1020, 0x20);
  CHECK(Result.InValidRange);
  CHECK_FALSE(Result.FirstForceTSOInstruction.has_value());
}

TEST_CASE("ForceTSO - block must be fully enclosed") {
  FEXCore::IntervalList<uint64_t> Ranges;
  Ranges.Insert({0x1000, 0x1100});
  fextl::set<uint64_t> Instructions;

  const auto Result = FEXCore::Core::GetForceTSOBlockInfo(Ranges, Instructions, 0x10f0, 0x20);
  CHECK_FALSE(Result.InValidRange);
  CHECK_FALSE(Result.FirstForceTSOInstruction.has_value());
}
