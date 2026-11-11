#include "authenticator/OtpAuth.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <map>

#include "authenticator/TOTP.h"
#include "core/HardwareConfig.h"
#include "security/SecureZero.h"

namespace vaultkey {
namespace {

int hexValue(char character) {
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    return -1;
}

bool percentDecode(const std::string& input, std::string& output,
                   bool queryValue) {
    output.clear();
    output.reserve(input.size());
    for (std::size_t index = 0; index < input.size(); ++index) {
        const char character = input[index];
        if (character == '%' && index + 2 < input.size()) {
            const int high = hexValue(input[index + 1]);
            const int low = hexValue(input[index + 2]);
            if (high < 0 || low < 0) return false;
            const char decoded = static_cast<char>((high << 4) | low);
            if (decoded == '\0') return false;
            output.push_back(decoded);
            index += 2;
        } else if (character == '%') {
            return false;
        } else if (queryValue && character == '+') {
            output.push_back(' ');
        } else {
            output.push_back(character);
        }
    }
    return true;
}

std::string upper(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](char c) {
        return static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    });
    return value;
}

bool parseUnsigned(const std::string& value, unsigned long& result) {
    if (value.empty() ||
        !std::all_of(value.begin(), value.end(),
                     [](char c) { return c >= '0' && c <= '9'; })) {
        return false;
    }
    char* end = nullptr;
    result = std::strtoul(value.c_str(), &end, 10);
    return end != nullptr && *end == '\0';
}

class ParameterWiper {
  public:
    explicit ParameterWiper(std::map<std::string, std::string>& values)
        : values_(values) {}
    ~ParameterWiper() {
        for (auto& value : values_) secureClear(value.second);
    }

  private:
    std::map<std::string, std::string>& values_;
};

}  // namespace

bool OtpAuth::parse(const std::string& uri, TotpEntry& entry,
                    std::string& error) {
    entry.clearSensitive();
    entry = TotpEntry{};
    error.clear();
    static constexpr const char* PREFIX = "otpauth://totp/";
    static constexpr std::size_t PREFIX_LENGTH = 15;
    if (uri.rfind(PREFIX, 0) != 0) {
        error = "unsupported_uri";
        return false;
    }

    const std::size_t queryAt = uri.find('?', PREFIX_LENGTH);
    if (queryAt == std::string::npos || queryAt == PREFIX_LENGTH) {
        error = "missing_label_or_query";
        return false;
    }
    std::string label;
    if (!percentDecode(uri.substr(PREFIX_LENGTH, queryAt - PREFIX_LENGTH), label,
                       false)) {
        error = "invalid_label_encoding";
        return false;
    }

    std::map<std::string, std::string> parameters;
    ParameterWiper parameterWiper(parameters);
    std::size_t position = queryAt + 1;
    while (position <= uri.size()) {
        const std::size_t amp = uri.find('&', position);
        const std::size_t end = amp == std::string::npos ? uri.size() : amp;
        const std::string pair = uri.substr(position, end - position);
        const std::size_t equals = pair.find('=');
        if (equals == std::string::npos || equals == 0) {
            error = "invalid_query";
            return false;
        }
        std::string key;
        std::string value;
        if (!percentDecode(pair.substr(0, equals), key, true) ||
            !percentDecode(pair.substr(equals + 1), value, true)) {
            error = "invalid_query_encoding";
            return false;
        }
        key = upper(key);
        if (!parameters.emplace(key, value).second) {
            error = "duplicate_parameter";
            return false;
        }
        if (amp == std::string::npos) break;
        position = amp + 1;
    }

    const auto secretIt = parameters.find("SECRET");
    if (secretIt == parameters.end() ||
        !Base32::decode(secretIt->second, entry.secret) ||
        entry.secret.size() < 10) {
        error = "invalid_secret";
        entry.clearSensitive();
        return false;
    }

    const std::size_t colon = label.find(':');
    std::string labelIssuer;
    if (colon != std::string::npos) {
        labelIssuer = label.substr(0, colon);
        entry.account = label.substr(colon + 1);
    } else {
        entry.account = label;
    }
    const auto issuerIt = parameters.find("ISSUER");
    entry.issuer = issuerIt == parameters.end() ? labelIssuer : issuerIt->second;
    if (!labelIssuer.empty() && issuerIt != parameters.end() &&
        labelIssuer != issuerIt->second) {
        error = "issuer_mismatch";
        entry.clearSensitive();
        return false;
    }
    if (entry.issuer.empty() || entry.account.empty() ||
        entry.issuer.size() > limits::ISSUER ||
        entry.account.size() > limits::ACCOUNT) {
        error = "invalid_label";
        entry.clearSensitive();
        return false;
    }

    const std::string algorithm =
        upper(parameters.count("ALGORITHM") ? parameters["ALGORITHM"] : "SHA1");
    if (algorithm == "SHA1") {
        entry.algorithm = HashAlgorithm::Sha1;
    } else if (algorithm == "SHA256") {
        entry.algorithm = HashAlgorithm::Sha256;
    } else if (algorithm == "SHA512") {
        entry.algorithm = HashAlgorithm::Sha512;
    } else {
        error = "unsupported_algorithm";
        entry.clearSensitive();
        return false;
    }

    unsigned long parsed = 0;
    if (parameters.count("DIGITS")) {
        if (!parseUnsigned(parameters["DIGITS"], parsed) ||
            (parsed != 6 && parsed != 8)) {
            error = "invalid_digits";
            entry.clearSensitive();
            return false;
        }
        entry.digits = static_cast<uint8_t>(parsed);
    }
    if (parameters.count("PERIOD")) {
        if (!parseUnsigned(parameters["PERIOD"], parsed) || parsed < 15 ||
            parsed > 300) {
            error = "invalid_period";
            entry.clearSensitive();
            return false;
        }
        entry.period = static_cast<uint16_t>(parsed);
    }
    return true;
}

}  // namespace vaultkey
