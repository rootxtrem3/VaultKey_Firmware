#pragma once

#include <ArduinoJson.h>

#include <cstdint>
#include <string>

#include "authenticator/OTPManager.h"
#include "core/Configuration.h"
#include "hardware/Buttons.h"
#include "hardware/Display.h"
#include "hardware/LED.h"
#include "hardware/RTC.h"
#include "hardware/USBComposite.h"
#include "interface/UIManager.h"
#include "security/Authentication.h"
#include "security/KeyManager.h"
#include "security/SecureStorage.h"
#include "usb/USBProtocol.h"
#include "vault/CredentialManager.h"

namespace vaultkey {

enum class StartupState : uint8_t {
    PowerOn,
    HardwareInit,
    I2cInit,
    DisplayInit,
    RtcCheck,
    StorageInit,
    SecurityInit,
    UsbInit,
    UiInit,
    LockedHome,
    Fault
};

class Application : public USBCommandHandler {
  public:
    Application();
    void begin();
    void update();

    bool setupPin(const std::string& pin, const std::string& confirmation);
    bool unlock(const std::string& pin);
    bool reauthenticate(const std::string& pin);
    bool changePin(const std::string& currentPin, const std::string& newPin,
                   const std::string& confirmation);
    void lock();
    bool factoryReset(const std::string& pin);

    bool typeCredential(uint32_t id, bool password);
    bool deleteCredential(uint32_t id);
    bool deleteTotp(uint32_t id);
    bool setTime(uint64_t unixTime);
    bool saveSettings();
    void noteActivity();

    bool authorizeProvisioning();
    void revokeProvisioning();
    bool provisioningAuthorized() const;
    uint32_t provisioningSecondsRemaining() const;

    bool handleUSBCommand(const char* command, JsonObjectConst request,
                          JsonObject response,
                          const char*& errorCode) override;

    Authentication& authentication() { return authentication_; }
    const Authentication& authentication() const { return authentication_; }
    CredentialManager& credentials() { return credentials_; }
    OTPManager& otp() { return otp_; }
    RTC& rtc() { return rtc_; }
    const RTC& rtc() const { return rtc_; }
    USBComposite& usb() { return usb_; }
    const USBComposite& usb() const { return usb_; }
    Configuration& configuration() { return configuration_; }
    const Configuration& configuration() const { return configuration_; }
    SecureStorage& storage() { return storage_; }
    const SecureStorage& storage() const { return storage_; }
    bool fatal() const { return fatal_; }
    const char* fatalCode() const { return fatalCode_; }
    StartupState startupState() const { return startupState_; }
    const char* startupStateText() const;

  private:
    bool openAuthenticatedStorage();
    bool requireProvisioning(const char*& errorCode) const;
    bool commandAddCredential(JsonObjectConst request, JsonObject response,
                              const char*& errorCode);
    bool commandUpdateCredential(JsonObjectConst request, JsonObject response,
                                 const char*& errorCode);
    bool commandAddTotp(JsonObjectConst request, JsonObject response,
                        const char*& errorCode);
    void setFatal(const char* code);

    Display display_;
    Buttons buttons_;
    RTC rtc_;
    LED led_;
    Configuration configuration_;
    KeyManager keyManager_;
    SecureStorage storage_;
    Authentication authentication_;
    CredentialManager credentials_;
    OTPManager otp_;
    USBComposite usb_;
    USBProtocol protocol_;
    UIManager ui_;

    uint32_t lastActivityMs_ = 0;
    uint32_t provisioningUntilMs_ = 0;
    uint32_t restartAtMs_ = 0;
    bool fatal_ = false;
    bool wasUsbMounted_ = false;
    const char* fatalCode_ = "none";
    StartupState startupState_ = StartupState::PowerOn;
};

}  // namespace vaultkey
