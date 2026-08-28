#include <print>
#include <string>
#include <vector>

#include "dpdk/dpi/dpi_rule_engine.hpp"

#define CHECK(cond)                                                                 \
  do {                                                                              \
    if (!(cond)) {                                                                  \
      std::println(stderr, "CHECK failed at {}:{}: {}", __FILE__, __LINE__, #cond); \
      return 1;                                                                     \
    }                                                                               \
  } while (0)

int main() {
  dpdk::DpiConfig config;
  config.enabled = true;
  config.filters = {
      {
          .hostname_pattern = "*.facebook.com",
          .uri_pattern = std::nullopt,
          .filter_group = "fg_l7_facebook",
          .priority = 10,
          .label = "facebook",
      },
      {
          .hostname_pattern = "*.fbcdn.net",
          .uri_pattern = std::nullopt,
          .filter_group = "fg_l7_fbcdn",
          .priority = 15,
          .label = "fbcdn",
      },
      {
          .hostname_pattern = "*.youtube.com",
          .uri_pattern = std::nullopt,
          .filter_group = "fg_l7_youtube",
          .priority = 20,
          .label = "youtube",
      },
      {
          .hostname_pattern = "dns.google",
          .uri_pattern = std::nullopt,
          .filter_group = "fg_l7_dns_google",
          .priority = 5,  // Highest priority
          .label = "dns_google",
      },
      {
          .hostname_pattern = "*.google.com",
          .uri_pattern = std::nullopt,
          .filter_group = "fg_l7_google",
          .priority = 30,
          .label = "google",
      },
      {
          .hostname_pattern = "*",
          .uri_pattern = std::nullopt,
          .filter_group = "fg_l7_catchall",
          .priority = 999,
          .label = "catchall",
      },
  };

  auto compiled = dpdk::dpi::CompileDpiRuleTable(config);
  if (!compiled) {
    std::println(stderr, "Compilation failed: {}", compiled.error());
    return 1;
  }

  const auto& table = *compiled;
  CHECK(table.IsEnabled());
  CHECK(table.FilterCount() == 6);
  CHECK(table.HyperscanDb() != nullptr);

  // 1. Exact match (dns.google) -> priority 5
  {
    const auto res = table.Match("dns.google");
    CHECK(res.matched);
    CHECK(res.filter_group == "fg_l7_dns_google");
    CHECK(res.priority == 5);
    std::println("Test 1 (Exact match dns.google): PASSED");
  }

  // 2. Suffix match (*.facebook.com)
  {
    const auto res1 = table.Match("facebook.com");
    CHECK(res1.matched);
    CHECK(res1.filter_group == "fg_l7_facebook");

    const auto res2 = table.Match("m.facebook.com");
    CHECK(res2.matched);
    CHECK(res2.filter_group == "fg_l7_facebook");

    const auto res3 = table.Match("static.sub.facebook.com");
    CHECK(res3.matched);
    CHECK(res3.filter_group == "fg_l7_facebook");
    std::println("Test 2 (Suffix match facebook): PASSED");
  }

  // 3. Multi-level suffix match (*.fbcdn.net)
  {
    const auto res = table.Match("video.xx.fbcdn.net");
    CHECK(res.matched);
    CHECK(res.filter_group == "fg_l7_fbcdn");
    CHECK(res.priority == 15);
    std::println("Test 3 (Multi-level suffix fbcdn): PASSED");
  }

  // 4. Case-insensitivity (HS_FLAG_CASELESS)
  {
    const auto res = table.Match("VIDEO.XX.FBCDN.NET");
    CHECK(res.matched);
    CHECK(res.filter_group == "fg_l7_fbcdn");
    std::println("Test 4 (Case insensitivity): PASSED");
  }

  // 5. Catch-all match (*)
  {
    const auto res = table.Match("unknown-site-12345.org");
    CHECK(res.matched);
    CHECK(res.filter_group == "fg_l7_catchall");
    CHECK(res.priority == 999);
    std::println("Test 5 (Catch-all): PASSED");
  }

  // 6. Explicit scratch buffer test
  {
    auto* scratch = table.AllocScratch();
    CHECK(scratch != nullptr);
    const auto res = table.Match("www.youtube.com", scratch);
    CHECK(res.matched);
    CHECK(res.filter_group == "fg_l7_youtube");
    table.FreeScratch(scratch);
    std::println("Test 6 (Explicit scratch buffer): PASSED");
  }

  std::println("\n🎉 ALL HYPERSCAN DPI UNIT TESTS PASSED SUCCESSFULLY!");
  return 0;
}
