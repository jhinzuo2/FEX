// SPDX-License-Identifier: MIT
#include "Common/VolatileMetadata.h"

#include <catch2/catch_all.hpp>

TEST_CASE("TSO whitelist parses D4 policy") {
  const auto Config = FEX::VolatileMetadata::ParseTSOWhitelist(
    "Diablo IV.exe;0x176f0d0-0x176f540;0x123b2c9,0x123b2e7");

  REQUIRE(Config.Valid);
  REQUIRE(Config.Modules.size() == 1);
  const auto It = Config.Modules.find("diablo iv.exe");
  REQUIRE(It != Config.Modules.end());
  CHECK(It->second.EnabledRanges.Contains({0x176f0d0, 0x176f540}));
  CHECK(It->second.EnabledInstructions.contains(0x123b2c9));
  CHECK(It->second.EnabledInstructions.contains(0x123b2e7));
}

TEST_CASE("TSO whitelist supports multiple modules and empty lists") {
  const auto Config = FEX::VolatileMetadata::ParseTSOWhitelist("game.exe;;:helper.dll;10-20;");

  REQUIRE(Config.Valid);
  REQUIRE(Config.Modules.size() == 2);
  CHECK(Config.Modules.find("game.exe") != Config.Modules.end());
  CHECK(Config.Modules.find("helper.dll") != Config.Modules.end());
}

TEST_CASE("TSO whitelist rejects malformed input as a whole") {
  for (const auto Input : {
         "game.exe;100-100;",
         "game.exe;200-100;",
         "game.exe;xyz-200;",
         "game.exe;100-200;xyz",
         "game.exe;100-200",
         "game.exe;100-200;:game.exe;300-400;",
         ":game.exe;;",
         "game.exe;;:",
       }) {
    const auto Config = FEX::VolatileMetadata::ParseTSOWhitelist(Input);
    CHECK_FALSE(Config.Valid);
    CHECK(Config.Modules.empty());
  }
}

TEST_CASE("TSO whitelist applies atomically and rebases offsets") {
  const auto Config = FEX::VolatileMetadata::ParseTSOWhitelist("game.exe;100-200;300");
  REQUIRE(Config.Valid);
  const auto& Metadata = Config.Modules.at("game.exe");

  FEXCore::IntervalList<uint64_t> Modules;
  FEXCore::IntervalList<uint64_t> Enabled;
  fextl::set<uint64_t> Instructions;
  REQUIRE(FEX::VolatileMetadata::ApplyTSOWhitelistMetadata(Metadata, Modules, Enabled, Instructions, 0x100000, 0x102000));
  CHECK(Modules.Contains({0x100000, 0x102000}));
  CHECK(Enabled.Contains({0x100100, 0x100200}));
  CHECK(Instructions.contains(0x100300));
}

TEST_CASE("TSO whitelist rejects out of module offsets without partial apply") {
  const auto Config = FEX::VolatileMetadata::ParseTSOWhitelist("game.exe;100-3000;4000");
  REQUIRE(Config.Valid);
  const auto& Metadata = Config.Modules.at("game.exe");

  FEXCore::IntervalList<uint64_t> Modules;
  FEXCore::IntervalList<uint64_t> Enabled;
  fextl::set<uint64_t> Instructions;
  CHECK_FALSE(FEX::VolatileMetadata::ApplyTSOWhitelistMetadata(Metadata, Modules, Enabled, Instructions, 0x100000, 0x102000));
  CHECK(Modules.Empty());
  CHECK(Enabled.Empty());
  CHECK(Instructions.empty());
}
