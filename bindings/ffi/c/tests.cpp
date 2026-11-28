// Tests for the C++ wrapper. Plain main(), no test framework: the header has
// no dependencies and neither should its checks.
//
//   g++ -std=c++17 -Wall -Wextra -Werror -I include tests.cpp
//       -L lib -lrust_curl_impersonate_ffi -Wl,-rpath,$PWD/lib -o tests
//   RCI_BASE=http://127.0.0.1:8765 ./tests
//
// Exit code 0 means every check held.

#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <vector>

#include "rci.hpp"

namespace {

int checks = 0;
std::vector<std::string> failures;

void check(const std::string& label, bool held, const std::string& detail = "") {
    ++checks;
    if (held) {
        std::printf("ok   %s\n", label.c_str());
    } else {
        failures.push_back(label + (detail.empty() ? "" : ": " + detail));
        std::printf("FAIL %s — %s\n", label.c_str(), detail.c_str());
    }
}

/** Runs `body` and asserts it throws rci::Error whose text contains `needle`. */
template <typename Body>
void expectThrows(const std::string& label, const std::string& needle, Body body) {
    try {
        body();
    } catch (const rci::Error& error) {
        const std::string message = error.what();
        check(label, message.find(needle) != std::string::npos, message);
        return;
    } catch (const std::exception& error) {
        check(label, false, std::string("unexpected exception type: ") + error.what());
        return;
    }
    check(label, false, "no exception was raised");
}

std::string serverBase() {
    const char* value = std::getenv("RCI_BASE");
    return value != nullptr ? value : "http://127.0.0.1:8765";
}

}  // namespace

int main() {
    const std::string base = serverBase();
    try {
        rci::Library lib;
        check("the ABI reports version 2 or newer", lib.version() >= 2, std::to_string(lib.version()));

        // -- profile queries ---------------------------------------------------
        const std::string targets = lib.targets();
        check("targets is a JSON array of presets",
              targets.find("[\"chrome100\"") != std::string::npos, targets.substr(0, 40));
        const std::string profiles = lib.profiles();
        check("profiles is a longer JSON array", profiles.size() > targets.size(),
              std::to_string(profiles.size()));
        const std::string info = lib.profileInfo("chrome150");
        check("profile_info names the family", info.find("\"family\":\"chrome\"") != std::string::npos);
        expectThrows("an unknown profile throws", "unknown profile",
                     [&]() { lib.profileInfo("nope-not-a-profile"); });

        // -- requests ----------------------------------------------------------
        auto client = lib.client("chrome150");
        check("the handle is valid", client.valid());

        const rci::Reply reply = client.get(base + "/index.html");
        check("GET status 200", reply.status == 200, std::to_string(reply.status));
        check("GET body", reply.body == "hello from rust-curl-impersonate", reply.body);
        check("GET body is text", reply.body_is_text);
        check("GET reports a version", reply.version == "HTTP/1.1" || reply.version == "HTTP/2.0",
              reply.version);
        check("the raw JSON still carries the headers",
              reply.json.find("\"headers\":[[") != std::string::npos);

        const rci::Reply binary = lib.get("chrome150", base + "/rci-smoke.bin");
        check("a binary body is not text", !binary.body_is_text);
        check("the binary body is hex", binary.body.rfind("000102fffe", 0) == 0,
              binary.body.substr(0, 20));

        const rci::Reply echoed =
            client.requestWithHeaders("POST", base + "/echo", "[[\"x-marker\",\"cpp\"]]", "{\"a\":1}");
        check("a per-request header arrives", echoed.body.find("\"x-marker\": \"cpp\"") != std::string::npos,
              echoed.body);

        expectThrows("an unknown option throws", "invalid options",
                     [&]() { lib.client("chrome150", "{\"nope\":1}"); });
        auto typed = lib.client("chrome150", "{\"timeout_ms\":5000}");
        check("a known option is accepted", typed.valid());

        // A body with quotes, backslashes and a newline proves the flat-field
        // reader unescapes rather than truncating at the first quote.
        const rci::Reply quoted =
            client.requestWithHeaders("POST", base + "/echo", "[[\"x-quote\",\"a\\\"b\\\\c\"]]", "line1\nline2");
        check("an escaped header value survives", quoted.body.find("a\\\"b\\\\c") != std::string::npos,
              quoted.body);
        check("a newline in the body survives", quoted.body.find("line1\\nline2") != std::string::npos,
              quoted.body);

        // -- redirect policy ---------------------------------------------------
        const rci::Reply redirect = lib.get("chrome150", base + "/redirect");
        check("a redirect comes back as 302", redirect.status == 302, std::to_string(redirect.status));
        expectThrows("follow_safe refuses a loopback hop", "blocked", [&]() {
            auto safe = lib.client("chrome150", "{\"follow_safe\":true}");
            safe.get(base + "/redirect");
        });

        // -- state on the handle ------------------------------------------------
        auto cookies = lib.client("chrome150");
        cookies.get(base + "/cookie");
        const rci::Reply withCookie = cookies.get(base + "/echo");
        check("the cookie jar carried to the next request",
              withCookie.body.find("sid=abc123") != std::string::npos, withCookie.body);
        check("the cookie change is recorded",
              cookies.activity().find("\"cookies\":[]") == std::string::npos);

        check("wire profile", client.wireProfile() == "chrome150", client.wireProfile());
        check("last headers are introspectable", client.lastHeaders().size() > 2);

        // -- move semantics -----------------------------------------------------
        rci::Client moved = std::move(client);
        check("a moved-from handle is empty", !client.valid());
        check("the moved handle is valid", moved.valid());
        expectThrows("a closed handle throws", "closed", [&]() {
            moved = rci::Client();
            moved.get(base + "/index.html");
        });

        // -- runtime registration ------------------------------------------------
        lib.loadFingerprints(
            "[{\"name\":\"cpp_test_client\",\"extends\":\"chrome150\",\"family\":\"chrome\",\"platform\":\"linux\"}]");
        check("a registered record resolves",
              lib.profileInfo("cpp_test_client").find("\"wire\":\"chrome150\"") != std::string::npos,
              lib.profileInfo("cpp_test_client").substr(0, 120));
        expectThrows("an unbuildable record throws", "NO_CIPHER_MATCH", [&]() {
            lib.loadFingerprints("[{\"name\":\"cpp_bad\",\"tls\":{\"ciphers\":\"NOT_A_CIPHER\"}}]");
        });
    } catch (const std::exception& error) {
        std::printf("aborted: %s\n", error.what());
        return 1;
    }

    const int passed = checks - static_cast<int>(failures.size());
    std::printf("\n%d/%d checks passed\n", passed, checks);
    return failures.empty() ? 0 : 1;
}
