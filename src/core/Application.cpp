#include "core/Application.h"

#include <Arduino.h>
#include <Wire.h>
#include <esp32-hal.h>

#include <algorithm>
#include <cctype>
#include <cstring>

#include "core/HardwareConfig.h"
#include "authenticator/TOTP.h"
#include "security/Crypto.h"
#include "security/SecureZero.h"

namespace vaultkey {
namespace {

const char* jsonString(JsonObjectConst object, const char* key) {
    return object[key].is<const char*>() ? object[key].as<const char*>() : nullptr;
}

bool within(const char* value, std::size_t maximum, bool required) {
    if (value == nullptr) return !required;
    const std::size_t length = std::strlen(value);
    return (!required || length != 0) && length <= maximum;
}

uint64_t unsignedValue(JsonVariantConst value) {
    if (value.is<uint64_t>()) return value.as<uint64_t>();
    if (value.is<unsigned long>()) return value.as<unsigned long>();
    return 0;
}

std::string folded(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](char character) {
        return static_cast<char>(
            std::tolower(static_cast<unsigned char>(character)));
    });
    return value;
}

}  // namespace

Application::Application()
    : credentials_(storage_), otp_(storage_), protocol_(*this),
      ui_(*this, display_, buttons_) {}

void Application::begin() {
    startupState_ = StartupState::HardwareInit;
    enableLoopWDT();
    buttons_.begin();

    startupState_ = StartupState::I2cInit;
    Wire.begin(hardware::PIN_I2C_SDA, hardware::PIN_I2C_SCL,
               hardware::I2C_FREQUENCY_HZ);
    Wire.setClock(hardware::I2C_FREQUENCY_HZ);
    startupState_ = StartupState::DisplayInit;
    const bool displayReady = display_.begin(Wire);
    if (!displayReady) setFatal("OLED_INIT_FAILED");
    if (displayReady) display_.showBoot("Hardware init");

    led_.begin();
    if (led_.available()) led_.set(LEDPattern::Startup);
    if (!Crypto::selfTest()) setFatal("CRYPTO_SELF_TEST_FAILED");
    if (!TOTP::selfTest()) setFatal("TOTP_SELF_TEST_FAILED");
    bool configurationReady = configuration_.begin();
    if (displayReady) {
        display_.setContrast(configuration_.settings().displayContrast);
        display_.showBoot("RTC check");
    }
    startupState_ = StartupState::RtcCheck;
    rtc_.begin(Wire);  // RTC failure is non-fatal; TOTP remains unavailable.

    startupState_ = StartupState::StorageInit;
    const bool keysReady = keyManager_.begin();
    if (!keysReady) setFatal("KEY_STORAGE_INIT_FAILED");
    const bool envelopePresent = keysReady && keyManager_.envelopePresent();
    const bool provisioned = keysReady && keyManager_.provisioned();
    const bool wipePending = keysReady && keyManager_.factoryResetPending();
    if (envelopePresent && !provisioned && !wipePending)
        setFatal("KEY_METADATA_CORRUPT");
    // Never auto-format when any key envelope exists, even if malformed.
    const bool storageReady =
        storage_.begin(keysReady && (!envelopePresent || wipePending));
    if (!storageReady)
        setFatal("STORAGE_MOUNT_FAILED");
    if (wipePending && storageReady) {
        // A factory wipe is journaled before destructive work. Resume it after
        // any power loss instead of leaving a partially deleted vault.
        const bool wiped = storage_.wipe();
        const bool configReset = configuration_.reset();
        configurationReady = configurationReady || configReset;
        if (!wiped || !configReset || !keyManager_.destroy()) {
            setFatal("FACTORY_RESET_RECOVERY_FAILED");
        }
    }
    if (!configurationReady) setFatal("CONFIG_INIT_FAILED");

    uint64_t nowUnix = 0;
    const bool rtcValid = rtc_.now(nowUnix);
    startupState_ = StartupState::SecurityInit;
    if (!fatal_) authentication_.begin(keyManager_, rtcValid, nowUnix, millis());

    startupState_ = StartupState::UsbInit;
    if (displayReady) display_.showBoot("USB init");
    // USB is non-fatal so the standalone UI and vault remain usable if the
    // host rejects enumeration.
    usb_.begin(configuration_.settings().keyboardLayout);

    startupState_ = StartupState::UiInit;
    lastActivityMs_ = millis();
    ui_.begin();
    startupState_ = fatal_ ? StartupState::Fault : StartupState::LockedHome;
    if (fatal_ && displayReady) display_.showError("STARTUP ERROR", fatalCode_);
    if (led_.available())
        led_.set(fatal_ ? LEDPattern::Error : LEDPattern::Normal);
}

void Application::update() {
    const uint32_t now = millis();
    buttons_.update(now);
    rtc_.update(now);
    const bool usbMounted = usb_.mounted();
    if (wasUsbMounted_ && !usbMounted) {
        revokeProvisioning();
        protocol_.reset();
    }
    wasUsbMounted_ = usbMounted;
    // Physical input has priority over outgoing HID and incoming CDC. A BACK
    // cancellation or lock is therefore applied before another key report or
    // host provisioning command can run.
    ui_.update(now);
    usb_.update(now);
    if (usb_.typing()) lastActivityMs_ = now;
    protocol_.update(usb_.cdc());
    led_.update();

    if (authentication_.unlocked() &&
        now - lastActivityMs_ >=
            static_cast<uint32_t>(configuration_.settings().idleTimeoutSeconds) *
                1000U) {
        lock();
    }
    if (provisioningUntilMs_ != 0 && !provisioningAuthorized()) {
        revokeProvisioning();
    }
    if (restartAtMs_ != 0 &&
        static_cast<int32_t>(now - restartAtMs_) >= 0) {
        ESP.restart();
    }
}

bool Application::setupPin(const std::string& pin,
                           const std::string& confirmation) {
    if (fatal_ || !authentication_.setup(pin, confirmation)) return false;
    if (!openAuthenticatedStorage()) {
        authentication_.lock();
        storage_.lock();
        setFatal("VAULT_INITIALIZATION_FAILED");
        return false;
    }
    noteActivity();
    return true;
}

bool Application::unlock(const std::string& pin) {
    if (fatal_) return false;
    uint64_t unixTime = 0;
    const bool rtcValid = rtc_.now(unixTime);
    if (!authentication_.unlock(pin, rtcValid, unixTime, millis())) {
        if (led_.available()) led_.set(LEDPattern::AuthFailure);
        return false;
    }
    if (!openAuthenticatedStorage()) {
        authentication_.lock();
        storage_.lock();
        setFatal("VAULT_INTEGRITY_FAILED");
        return false;
    }
    noteActivity();
    if (led_.available()) led_.set(LEDPattern::Unlock);
    return true;
}

bool Application::reauthenticate(const std::string& pin) {
    const bool result = authentication_.reauthenticate(pin);
    if (result) noteActivity();
    return result;
}

bool Application::changePin(const std::string& currentPin,
                            const std::string& newPin,
                            const std::string& confirmation) {
    const bool result = authentication_.changePin(currentPin, newPin, confirmation);
    if (result) noteActivity();
    return result;
}

void Application::lock() {
    usb_.cancelTyping();
    revokeProvisioning();
    protocol_.reset();
    credentials_.clear();
    otp_.clear();
    storage_.lock();
    authentication_.lock();
    ui_.forceLocked();
    if (led_.available()) led_.set(LEDPattern::Normal);
}

bool Application::factoryReset(const std::string& pin) {
    if (!authentication_.unlocked() || !authentication_.reauthenticate(pin)) {
        return false;
    }
    if (!keyManager_.markFactoryResetPending()) return false;
    if (led_.available()) led_.set(LEDPattern::Wipe);
    usb_.cancelTyping();
    revokeProvisioning();
    credentials_.clear();
    otp_.clear();
    const bool filesRemoved = storage_.wipe();
    const bool settingsReset = configuration_.reset();
    const bool keysRemoved =
        filesRemoved && settingsReset && authentication_.destroyKeys();
    restartAtMs_ = millis() + 1200U;
    return filesRemoved && settingsReset && keysRemoved;
}

bool Application::typeCredential(uint32_t id, bool password) {
    if (!authentication_.unlocked() || !usb_.hidReady()) return false;
    Credential record;
    if (!credentials_.get(id, record)) return false;
    const std::string& selected = password ? record.password : record.username;
    const bool result = usb_.typeAuthorized(
        selected, configuration_.settings().hidKeystrokeDelayMs);
    record.clearSensitive();
    if (result) noteActivity();
    return result;
}

bool Application::deleteCredential(uint32_t id) {
    const bool result = authentication_.unlocked() && credentials_.remove(id);
    if (result) noteActivity();
    return result;
}

bool Application::deleteTotp(uint32_t id) {
    const bool result = authentication_.unlocked() && otp_.remove(id);
    if (result) noteActivity();
    return result;
}

bool Application::setTime(uint64_t unixTime) {
    const bool result = authentication_.unlocked() && rtc_.setUnix(unixTime);
    if (result) noteActivity();
    return result;
}

bool Application::saveSettings() {
    const bool result = authentication_.unlocked() && configuration_.save();
    if (result) {
        display_.setContrast(configuration_.settings().displayContrast);
        usb_.setKeyboardLayout(configuration_.settings().keyboardLayout);
        noteActivity();
    }
    return result;
}

void Application::noteActivity() { lastActivityMs_ = millis(); }

bool Application::authorizeProvisioning() {
    if (!authentication_.unlocked() || !usb_.cdcConnected()) return false;
    provisioningUntilMs_ = millis() + 300000U;
    noteActivity();
    return true;
}

void Application::revokeProvisioning() { provisioningUntilMs_ = 0; }

bool Application::provisioningAuthorized() const {
    return authentication_.unlocked() && usb_.cdcConnected() &&
           provisioningUntilMs_ != 0 &&
           static_cast<int32_t>(provisioningUntilMs_ - millis()) > 0;
}

uint32_t Application::provisioningSecondsRemaining() const {
    if (!provisioningAuthorized()) return 0;
    return (provisioningUntilMs_ - millis() + 999U) / 1000U;
}

bool Application::openAuthenticatedStorage() {
    return authentication_.masterKey() != nullptr &&
           storage_.unlock(authentication_.masterKey()) &&
           credentials_.loadIndex() && otp_.loadIndex();
}

bool Application::requireProvisioning(const char*& errorCode) const {
    if (!authentication_.unlocked()) {
        errorCode = "device_locked";
        return false;
    }
    if (!provisioningAuthorized()) {
        errorCode = "provisioning_not_authorized";
        return false;
    }
    return true;
}

bool Application::handleUSBCommand(const char* command, JsonObjectConst request,
                                   JsonObject response,
                                   const char*& errorCode) {
    if (std::strcmp(command, "HELLO") == 0 ||
        std::strcmp(command, "GET_VERSION") == 0) {
        response["product"] = "VaultKey";
        response["firmware"] = hardware::FIRMWARE_VERSION;
        response["hardware"] = hardware::HARDWARE_VERSION;
        response["protocol"] = 1;
        return true;
    }
    if (std::strcmp(command, "GET_STATUS") == 0) {
        response["locked"] = !authentication_.unlocked();
        response["rtc"] = rtc_.statusText();
        response["storage"] = storage_.statusText();
        response["startup"] = startupStateText();
        if (fatal_) response["startup_error"] = fatalCode_;
        response["display"] = display_.ready() ? "ready" : "init_failed";
        response["button_event_drops"] = buttons_.droppedEvents();
        response["usb_driver"] = usb_.driverStarted();
        response["usb_mounted"] = usb_.mounted();
        response["cdc"] = usb_.cdcConnected();
        response["hid"] = usb_.hidReady();
        response["provisioning"] = provisioningAuthorized();
        if (provisioningAuthorized()) {
            response["credentials"] = credentials_.count();
            response["totp"] = otp_.count();
        }
        return true;
    }
    if (std::strcmp(command, "GET_TIME") == 0) {
        uint64_t unixTime = 0;
        if (!rtc_.now(unixTime)) {
            errorCode = "rtc_time_invalid";
            return false;
        }
        response["unix"] = unixTime;
        response["utc"] = true;
        return true;
    }
    if (std::strcmp(command, "LOCK_DEVICE") == 0) {
        lock();
        return true;
    }

    if (!requireProvisioning(errorCode)) return false;
    noteActivity();

    if (std::strcmp(command, "SET_TIME") == 0) {
        const uint64_t unixTime = unsignedValue(request["unix"]);
        if (unixTime == 0 || !setTime(unixTime)) {
            errorCode = "invalid_time";
            return false;
        }
        response["unix"] = unixTime;
        return true;
    }
    if (std::strcmp(command, "LIST_SERVICES") == 0) {
        const char* query = jsonString(request, "query");
        if (!within(query, limits::SERVICE, false)) {
            errorCode = "invalid_query";
            return false;
        }
        std::vector<RecordSummary> credentialMatches;
        const std::vector<RecordSummary>* credentialList =
            &credentials_.entries();
        if (query != nullptr && query[0] != '\0') {
            credentialMatches = credentials_.search(query);
            credentialList = &credentialMatches;
        }
        std::vector<RecordSummary> tokenMatches;
        const std::vector<RecordSummary>* tokenList = &otp_.entries();
        if (query != nullptr && query[0] != '\0') {
            const std::string needle = folded(query);
            for (const RecordSummary& entry : otp_.entries()) {
                if (folded(entry.primary).find(needle) != std::string::npos ||
                    folded(entry.secondary).find(needle) != std::string::npos) {
                    tokenMatches.push_back(entry);
                }
            }
            tokenList = &tokenMatches;
        }
        const uint64_t requestedOffset = unsignedValue(request["offset"]);
        const std::size_t maximumEntries =
            limits::MAX_CREDENTIALS + limits::MAX_TOTP_ENTRIES;
        if (requestedOffset > maximumEntries) {
            for (RecordSummary& entry : credentialMatches) {
                secureClear(entry.primary);
                secureClear(entry.secondary);
            }
            for (RecordSummary& entry : tokenMatches) {
                secureClear(entry.primary);
                secureClear(entry.secondary);
            }
            errorCode = "invalid_pagination";
            return false;
        }
        const std::size_t offset = static_cast<std::size_t>(requestedOffset);
        uint64_t requestedLimit = unsignedValue(request["limit"]);
        if (requestedLimit == 0) requestedLimit = 20;
        if (requestedLimit > 25) {
            for (RecordSummary& entry : credentialMatches) {
                secureClear(entry.primary);
                secureClear(entry.secondary);
            }
            for (RecordSummary& entry : tokenMatches) {
                secureClear(entry.primary);
                secureClear(entry.secondary);
            }
            errorCode = "invalid_pagination";
            return false;
        }
        const std::size_t limit = static_cast<std::size_t>(requestedLimit);
        response["offset"] = offset;
        response["limit"] = limit;
        response["credential_total"] = credentialList->size();
        response["totp_total"] = tokenList->size();
        JsonArray credentials = response["credentials"].to<JsonArray>();
        const std::size_t credentialEnd =
            std::min(credentialList->size(), offset + limit);
        for (std::size_t index = std::min(offset, credentialList->size());
             index < credentialEnd; ++index) {
            const auto& entry = (*credentialList)[index];
            JsonObject item = credentials.add<JsonObject>();
            item["id"] = entry.id;
            item["service"] = entry.primary;
        }
        JsonArray tokens = response["totp"].to<JsonArray>();
        const std::size_t tokenEnd = std::min(tokenList->size(), offset + limit);
        for (std::size_t index = std::min(offset, tokenList->size());
             index < tokenEnd; ++index) {
            const auto& entry = (*tokenList)[index];
            JsonObject item = tokens.add<JsonObject>();
            item["id"] = entry.id;
            item["issuer"] = entry.primary;
            item["account"] = entry.secondary;
        }
        for (RecordSummary& entry : credentialMatches) {
            secureClear(entry.primary);
            secureClear(entry.secondary);
        }
        for (RecordSummary& entry : tokenMatches) {
            secureClear(entry.primary);
            secureClear(entry.secondary);
        }
        return true;
    }
    if (std::strcmp(command, "ADD_CREDENTIAL") == 0) {
        return commandAddCredential(request, response, errorCode);
    }
    if (std::strcmp(command, "UPDATE_CREDENTIAL") == 0) {
        return commandUpdateCredential(request, response, errorCode);
    }
    if (std::strcmp(command, "ADD_TOTP") == 0) {
        return commandAddTotp(request, response, errorCode);
    }
    if (std::strcmp(command, "DELETE_ENTRY") == 0) {
        const char* type = jsonString(request, "type");
        const uint32_t id = static_cast<uint32_t>(unsignedValue(request["entry_id"]));
        bool result = false;
        if (type != nullptr && std::strcmp(type, "credential") == 0) {
            result = deleteCredential(id);
        } else if (type != nullptr && std::strcmp(type, "totp") == 0) {
            result = deleteTotp(id);
        } else {
            errorCode = "invalid_entry_type";
            return false;
        }
        if (!result) errorCode = "delete_failed";
        return result;
    }
    errorCode = "unknown_command";
    return false;
}

bool Application::commandAddCredential(JsonObjectConst request,
                                       JsonObject response,
                                       const char*& errorCode) {
    const char* service = jsonString(request, "service");
    const char* username = jsonString(request, "username");
    const char* password = jsonString(request, "password");
    const char* url = jsonString(request, "url");
    const char* notes = jsonString(request, "notes");
    if (!within(service, limits::SERVICE, true) ||
        !within(username, limits::USERNAME, false) ||
        !within(password, limits::PASSWORD, true) ||
        !within(url, limits::URL, false) || !within(notes, limits::NOTES, false)) {
        errorCode = "invalid_credential";
        return false;
    }
    Credential record;
    record.service = service;
    if (username) record.username = username;
    record.password = password;
    if (url) record.url = url;
    if (notes) record.notes = notes;
    (void)rtc_.now(record.createdAt);  // 0 explicitly means time unavailable.
    const bool result = credentials_.add(record);
    if (result) response["entry_id"] = record.id;
    record.clearSensitive();
    if (!result) errorCode = "storage_failed";
    return result;
}

bool Application::commandUpdateCredential(JsonObjectConst request,
                                          JsonObject response,
                                          const char*& errorCode) {
    const uint32_t id = static_cast<uint32_t>(unsignedValue(request["entry_id"]));
    Credential record;
    if (id == 0 || !credentials_.get(id, record)) {
        errorCode = "entry_not_found";
        return false;
    }
    const char* service = jsonString(request, "service");
    const char* username = jsonString(request, "username");
    const char* password = jsonString(request, "password");
    const char* url = jsonString(request, "url");
    const char* notes = jsonString(request, "notes");
    const bool fieldsValid = within(service, limits::SERVICE, true) &&
                             within(username, limits::USERNAME, false) &&
                             within(password, limits::PASSWORD, true) &&
                             within(url, limits::URL, false) &&
                             within(notes, limits::NOTES, false);
    if (fieldsValid) {
        secureClear(record.service);
        record.service = service;
        secureClear(record.username);
        record.username = username == nullptr ? "" : username;
        secureClear(record.password);
        record.password = password;
        secureClear(record.url);
        record.url = url == nullptr ? "" : url;
        secureClear(record.notes);
        record.notes = notes == nullptr ? "" : notes;
    }
    const bool result = fieldsValid && credentials_.update(record);
    record.clearSensitive();
    if (!result) errorCode = fieldsValid ? "storage_failed" : "invalid_credential";
    if (result) response["entry_id"] = id;
    return result;
}

bool Application::commandAddTotp(JsonObjectConst request, JsonObject response,
                                 const char*& errorCode) {
    const char* uri = jsonString(request, "uri");
    if (!within(uri, 1024, true)) {
        errorCode = "invalid_uri";
        return false;
    }
    uint64_t createdAt = 0;
    (void)rtc_.now(createdAt);
    uint32_t id = 0;
    std::string parseError;
    const bool result = otp_.importUri(uri, createdAt, id, parseError);
    if (result) {
        response["entry_id"] = id;
    } else {
        errorCode = parseError.empty() ? "storage_failed" : parseError.c_str();
        // USBProtocol serializes before this stack frame returns, but use a
        // stable generic code for safety when the parser supplied a temporary.
        if (!parseError.empty()) response["detail"] = parseError;
        errorCode = "invalid_totp";
    }
    secureClear(parseError);
    return result;
}

void Application::setFatal(const char* code) {
    if (fatal_) return;
    fatal_ = true;
    fatalCode_ = code;
    if (led_.available()) led_.set(LEDPattern::Error);
}

const char* Application::startupStateText() const {
    switch (startupState_) {
        case StartupState::PowerOn: return "power_on";
        case StartupState::HardwareInit: return "hardware_init";
        case StartupState::I2cInit: return "i2c_init";
        case StartupState::DisplayInit: return "display_init";
        case StartupState::RtcCheck: return "rtc_check";
        case StartupState::StorageInit: return "storage_init";
        case StartupState::SecurityInit: return "security_init";
        case StartupState::UsbInit: return "usb_init";
        case StartupState::UiInit: return "ui_init";
        case StartupState::LockedHome: return "locked_home";
        case StartupState::Fault: return "fault";
    }
    return "unknown";
}

}  // namespace vaultkey
