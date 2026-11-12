#pragma once

#include <cstdint>
#include <string>

#include "core/TimeUtils.h"
#include "hardware/Buttons.h"
#include "hardware/Display.h"

namespace vaultkey {

class Application;

class UIManager {
  public:
    UIManager(Application& application, Display& display, Buttons& buttons)
        : application_(application), display_(display), buttons_(buttons) {}
    void begin();
    void update(uint32_t nowMs);
    void forceLocked();

  private:
    enum class Screen : uint8_t {
        Fatal,
        Locked,
        Pin,
        Dashboard,
        VaultList,
        CredentialDetail,
        CredentialInfo,
        PasswordReveal,
        HidConfirm,
        HidSending,
        CredentialDelete,
        TotpList,
        TotpCode,
        TotpDelete,
        UsbFunctions,
        Settings,
        DateTimeEdit,
        AdjustIdle,
        AdjustTimezone,
        AdjustKeyboard,
        AdjustBrightness,
        FactoryWarning,
        FactoryHold,
        DeviceInfo,
        Message
    };

    enum class PinFlow : uint8_t {
        None,
        SetupNew,
        SetupConfirm,
        Unlock,
        ChangeCurrent,
        ChangeNew,
        ChangeConfirm,
        Factory
    };

    void handle(const ButtonEvent& event, uint32_t nowMs);
    void handleShort(ButtonId button, uint32_t nowMs);
    void handlePin(ButtonId button);
    void completePinEntry();
    void startPin(PinFlow flow);
    void resetPinEntry();
    void clearPinData();
    void showMessage(const std::string& title, const std::string& message,
                     Screen returnTo, uint32_t durationMs = 1800);
    void adjustSelection(int& selection, int count, int delta);
    void adjustDate(int delta);
    void render(uint32_t nowMs);
    void renderLocked(uint32_t nowMs);
    void renderPin();
    void renderDashboard();
    void renderVaultList();
    void renderCredentialDetail();
    void renderCredentialInfo();
    void renderPasswordReveal(uint32_t nowMs);
    void renderTotpList();
    void renderTotpCode();
    void renderUsbFunctions();
    void renderSettings();
    void renderDateTimeEdit();
    void renderAdjustment();
    void renderDelete(const char* type, uint32_t nowMs);
    void renderFactoryHold(uint32_t nowMs);
    void renderDeviceInfo();
    void renderMessage();
    void renderScrollable(const char* title, const std::string* items,
                          int count, int selection, int visible = 5);
    bool localCalendar(CalendarTime& calendar) const;

    Application& application_;
    Display& display_;
    Buttons& buttons_;
    Screen screen_ = Screen::Locked;
    Screen messageReturn_ = Screen::Dashboard;
    PinFlow pinFlow_ = PinFlow::None;
    std::string pinEntry_;
    std::string firstPin_;
    std::string currentPin_;
    std::string revealedPassword_;
    std::string credentialInfo_;
    std::string messageTitle_;
    std::string messageText_;
    uint8_t digit_ = 0;
    int mainSelection_ = 0;
    int listSelection_ = 0;
    int detailSelection_ = 0;
    int settingsSelection_ = 0;
    int editField_ = 0;
    int adjustmentValue_ = 0;
    int adjustmentOriginal_ = 0;
    std::size_t revealOffset_ = 0;
    std::size_t infoOffset_ = 0;
    uint32_t selectedId_ = 0;
    uint32_t revealUntilMs_ = 0;
    uint32_t messageUntilMs_ = 0;
    uint32_t lastRenderMs_ = 0;
    CalendarTime editTime_{};
    bool hidPassword_ = false;
    bool dirty_ = true;
};

}  // namespace vaultkey
