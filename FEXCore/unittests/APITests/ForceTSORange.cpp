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

TEST_CASE("TSO whitelist - module defaults disabled") {
  FEXCore::IntervalList<uint64_t> Modules;
  Modules.Insert({0x1000, 0x2000});
  FEXCore::IntervalList<uint64_t> Enabled;
  fextl::set<uint64_t> Instructions;

  const auto Result = FEXCore::Core::GetTSOWhitelistInfo(Modules, Enabled, Instructions, 0x1500);
  CHECK(Result.InWhitelistedModule);
  CHECK_FALSE(Result.ForceEnabled);
}

TEST_CASE("TSO whitelist - range and instruction opt in") {
  FEXCore::IntervalList<uint64_t> Modules;
  Modules.Insert({0x1000, 0x3000});
  FEXCore::IntervalList<uint64_t> Enabled;
  Enabled.Insert({0x1800, 0x1900});
  fextl::set<uint64_t> Instructions {0x2500};

  CHECK(FEXCore::Core::GetTSOWhitelistInfo(Modules, Enabled, Instructions, 0x1800).ForceEnabled);
  CHECK(FEXCore::Core::GetTSOWhitelistInfo(Modules, Enabled, Instructions, 0x18ff).ForceEnabled);
  CHECK_FALSE(FEXCore::Core::GetTSOWhitelistInfo(Modules, Enabled, Instructions, 0x1900).ForceEnabled);
  CHECK(FEXCore::Core::GetTSOWhitelistInfo(Modules, Enabled, Instructions, 0x2500).ForceEnabled);
}

TEST_CASE("TSO whitelist - outside module uses global policy") {
  FEXCore::IntervalList<uint64_t> Modules;
  Modules.Insert({0x1000, 0x2000});
  FEXCore::IntervalList<uint64_t> Enabled;
  Enabled.Insert({0x1800, 0x1900});
  fextl::set<uint64_t> Instructions {0x2500};

  const auto Result = FEXCore::Core::GetTSOWhitelistInfo(Modules, Enabled, Instructions, 0x2500);
  CHECK_FALSE(Result.InWhitelistedModule);
  CHECK_FALSE(Result.ForceEnabled);
}

TEST_CASE("TSO whitelist - policy priority") {
  const FEXCore::Core::TSOWhitelistInfo Outside {};
  const FEXCore::Core::TSOWhitelistInfo ModuleDefault {.InWhitelistedModule = true};
  const FEXCore::Core::TSOWhitelistInfo ModuleEnabled {.InWhitelistedModule = true, .ForceEnabled = true};

  using Override = FEXCore::Core::TSOPolicyOverride;
  CHECK(FEXCore::Core::ResolveTSOPolicy(true, false, ModuleDefault, true) == Override::ForceEnabled);
  CHECK(FEXCore::Core::ResolveTSOPolicy(false, true, ModuleDefault, true) == Override::ForceEnabled);
  CHECK(FEXCore::Core::ResolveTSOPolicy(false, false, ModuleEnabled, true) == Override::ForceEnabled);
  CHECK(FEXCore::Core::ResolveTSOPolicy(false, false, ModuleDefault, false) == Override::ForceDisabled);
  CHECK(FEXCore::Core::ResolveTSOPolicy(false, false, Outside, true) == Override::ForceDisabled);
  CHECK(FEXCore::Core::ResolveTSOPolicy(false, false, Outside, false) == Override::NoOverride);
}

TEST_CASE("TSO whitelist - cross-block addresses are resolved independently") {
  FEXCore::IntervalList<uint64_t> Modules;
  Modules.Insert({0x1000, 0x3000});
  FEXCore::IntervalList<uint64_t> Enabled;
  Enabled.Insert({0x17f8, 0x1808});
  fextl::set<uint64_t> Instructions {0x2000};

  CHECK(FEXCore::Core::GetTSOWhitelistInfo(Modules, Enabled, Instructions, 0x17ff).ForceEnabled);
  CHECK(FEXCore::Core::GetTSOWhitelistInfo(Modules, Enabled, Instructions, 0x1800).ForceEnabled);
  CHECK_FALSE(FEXCore::Core::GetTSOWhitelistInfo(Modules, Enabled, Instructions, 0x1808).ForceEnabled);
}

TEST_CASE("TSO whitelist - unmap and remap lifecycle") {
  FEXCore::IntervalList<uint64_t> Modules;
  Modules.Insert({0x1000, 0x2000});
  FEXCore::IntervalList<uint64_t> Enabled;
  Enabled.Insert({0x1100, 0x1200});
  fextl::set<uint64_t> Instructions {0x1300};

  FEXCore::Core::RemoveTSOWhitelistInformation(Modules, Enabled, Instructions, 0x1000, 0x1000);
  CHECK_FALSE(FEXCore::Core::GetTSOWhitelistInfo(Modules, Enabled, Instructions, 0x1100).InWhitelistedModule);
  CHECK(Instructions.empty());

  Modules.Insert({0x4000, 0x5000});
  Enabled.Insert({0x4100, 0x4200});
  Instructions.emplace(0x4300);
  CHECK(FEXCore::Core::GetTSOWhitelistInfo(Modules, Enabled, Instructions, 0x4100).ForceEnabled);
  CHECK(FEXCore::Core::GetTSOWhitelistInfo(Modules, Enabled, Instructions, 0x4300).ForceEnabled);
}
