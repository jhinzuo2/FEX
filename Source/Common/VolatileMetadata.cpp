// SPDX-License-Identifier: MIT
#include "Common/VolatileMetadata.h"

#include <FEXCore/Utils/LogManager.h>

#include <cstdlib>
#include <charconv>
#include <cctype>
#include <system_error>

#include <range/v3/view/split.hpp>
#include <range/v3/view/transform.hpp>

namespace FEX::VolatileMetadata {
fextl::unordered_map<fextl::string, ExtendedVolatileMetadata> ParseExtendedVolatileMetadata(std::string_view ListOfDescriptors) {
  // Parsing: `<module>;<address begin>-<address-end>,<more addresses>;<instruction offset to force TSO>:`
  if (ListOfDescriptors.empty()) {
    return {};
  }

  fextl::unordered_map<fextl::string, ExtendedVolatileMetadata> ExtendedMetaData {};

  auto to_string_view = [](auto rng) {
    return std::string_view(&*rng.begin(), ranges::distance(rng));
  };
  for (auto module_config : ranges::views::split(ListOfDescriptors, ':') | ranges::views::transform(to_string_view)) {
    if (module_config.empty()) {
      continue;
    }

    auto sections = ranges::views::split(module_config, ';') | ranges::views::transform(to_string_view);
    auto section = ranges::begin(sections);
    const auto sections_end = ranges::end(sections);

    // Module name handling
    std::string_view section_str = *section;
    if (section_str.empty()) {
      continue;
    }

    auto current_module = ExtendedMetaData
                            .insert_or_assign(fextl::string(section_str),
                                              ExtendedVolatileMetadata {
                                                .ModuleTSODisabled = true,
                                              })
                            .first;
    ++section;

    // Address range handling
    if (section != sections_end) {
      std::string_view section_str = *section;
      if (section_str.empty()) {
        continue;
      }

      current_module->second.ModuleTSODisabled = false;

      // Walk all the address ranges provided.
      for (auto tso_region_view : ranges::views::split(section_str, ',') | ranges::views::transform(to_string_view)) {
        if (tso_region_view.empty()) {
          continue;
        }

        uint64_t begin {}, end {};
        char* str_end;
        begin = std::strtoull(tso_region_view.data(), &str_end, 16);
        LOGMAN_THROW_A_FMT(tso_region_view.data() != str_end, "Couldn't parse begin {}", tso_region_view);

        // Skip `-` separator.
        ++str_end;

        LOGMAN_THROW_A_FMT(str_end != tso_region_view.end(), "Couldn't parse end {}", tso_region_view);
        auto str_begin = str_end;
        end = std::strtoull(str_begin, &str_end, 16);
        LOGMAN_THROW_A_FMT(str_begin != str_end, "Couldn't parse end {}", tso_region_view);

        current_module->second.VolatileValidRanges.Insert({begin, end});
      }

      ++section;
    }

    // Individual instruction handling
    if (section != sections_end) {
      std::string_view section_str = *section;
      if (section_str.empty()) {
        continue;
      }

      for (auto tso_region_view : ranges::views::split(section_str, ',') | ranges::views::transform(to_string_view)) {
        if (tso_region_view.empty()) {
          continue;
        }

        uint64_t offset {};
        char* str_end;
        offset = std::strtoull(tso_region_view.data(), &str_end, 16);
        LOGMAN_THROW_A_FMT(tso_region_view.data() != str_end, "Couldn't parse offset {}", tso_region_view);

        current_module->second.VolatileInstructions.insert(offset);
      }

      ++section;
    }

    LOGMAN_THROW_A_FMT(section == sections_end, "Expected ':' or end of input, got {}", *section);
  }

  return ExtendedMetaData;
}

TSOWhitelistConfig ParseTSOWhitelist(std::string_view ListOfDescriptors) {
  TSOWhitelistConfig Result {};
  if (ListOfDescriptors.empty()) {
    return Result;
  }

  auto Fail = [&](std::string_view Reason) {
    LogMan::Msg::EFmt("Invalid TSO whitelist: {}", Reason);
    Result.Valid = false;
    Result.Modules.clear();
  };
  auto ToStringView = [](auto Range) -> std::string_view {
    if (ranges::empty(Range)) {
      return {};
    }
    return std::string_view(&*Range.begin(), ranges::distance(Range));
  };
  auto ParseHex = [](std::string_view Text, uint64_t& Value) {
    if (Text.empty()) {
      return false;
    }
    if (Text.starts_with("0x") || Text.starts_with("0X")) {
      Text.remove_prefix(2);
    }
    if (Text.empty()) {
      return false;
    }
    const auto [Ptr, Error] = std::from_chars(Text.data(), Text.data() + Text.size(), Value, 16);
    return Error == std::errc {} && Ptr == Text.data() + Text.size();
  };

  size_t DescriptorOffset {};
  while (true) {
    const auto NextDescriptor = ListOfDescriptors.find(':', DescriptorOffset);
    const auto ModuleConfig = ListOfDescriptors.substr(
      DescriptorOffset, NextDescriptor == std::string_view::npos ? std::string_view::npos : NextDescriptor - DescriptorOffset);
    // std::views/range-v3 split drops a trailing empty field. Locate the two
    // separators explicitly so an empty range or instruction list remains a
    // valid, intentional part of the grammar.
    const auto FirstSeparator = ModuleConfig.find(';');
    const auto SecondSeparator = FirstSeparator == std::string_view::npos ? std::string_view::npos : ModuleConfig.find(';', FirstSeparator + 1);
    if (FirstSeparator == std::string_view::npos || SecondSeparator == std::string_view::npos ||
        ModuleConfig.find(';', SecondSeparator + 1) != std::string_view::npos) {
      Fail("expected exactly three ';'-separated sections");
      return Result;
    }

    const std::string_view ModuleSection = ModuleConfig.substr(0, FirstSeparator);
    if (ModuleSection.empty()) {
      Fail("module name is empty");
      return Result;
    }

    fextl::string Module {ModuleSection};
    std::transform(Module.begin(), Module.end(), Module.begin(), [](unsigned char C) { return std::tolower(C); });
    if (Result.Modules.find(Module) != Result.Modules.end()) {
      Fail("module appears more than once");
      return Result;
    }
    const std::string_view RangesSection = ModuleConfig.substr(FirstSeparator + 1, SecondSeparator - FirstSeparator - 1);
    const std::string_view InstructionsSection = ModuleConfig.substr(SecondSeparator + 1);

    TSOWhitelistMetadata Metadata {};
    if (!RangesSection.empty()) {
      for (auto RangeText : ranges::views::split(RangesSection, ',') | ranges::views::transform(ToStringView)) {
        const auto Separator = RangeText.find('-');
        uint64_t Begin {};
        uint64_t End {};
        if (Separator == std::string_view::npos || !ParseHex(RangeText.substr(0, Separator), Begin) ||
            !ParseHex(RangeText.substr(Separator + 1), End) || Begin >= End) {
          Fail("range is not a valid non-empty half-open interval");
          return Result;
        }
        Metadata.EnabledRanges.Insert({Begin, End});
      }
    }

    if (!InstructionsSection.empty()) {
      for (auto InstructionText : ranges::views::split(InstructionsSection, ',') | ranges::views::transform(ToStringView)) {
        uint64_t Offset {};
        if (!ParseHex(InstructionText, Offset)) {
          Fail("instruction offset is not valid hexadecimal");
          return Result;
        }
        Metadata.EnabledInstructions.emplace(Offset);
      }
    }

    Result.Modules.emplace(std::move(Module), std::move(Metadata));
    if (NextDescriptor == std::string_view::npos) {
      break;
    }

    DescriptorOffset = NextDescriptor + 1;
  }

  return Result;
}
} // namespace FEX::VolatileMetadata
