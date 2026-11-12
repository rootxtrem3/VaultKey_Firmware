#include "interface/UIManager.h"

#include <Arduino.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>

#include "core/Application.h"
#include "core/Configuration.h"
#include "core/HardwareConfig.h"
#include "authenticator/TOTP.h"
#include "security/SecureZero.h"

namespace vaultkey {
namespace {

constexpr const char* MONTHS[] = {"JAN", "FEB", "MAR", "APR", "MAY", "JUN",
                                  "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"};

bool actionable(ButtonEventType type) {
    return type == ButtonEventType::ShortPress ||
           type == ButtonEventType::Repeat;
}

std::string groupedCode(const std::string& code) {
    if (code.size() == 6) return code.substr(0, 3) + " " + code.substr(3);
    if (code.size() == 8) return code.substr(0, 4) + " " + code.substr(4);
    return code;
}

}  // namespace

void UIManager::begin() {
    clearPinData();
    if (application_.fatal()) {
        screen_ = Screen::Fatal;
    } else if (application_.authentication().setupRequired()) {
        startPin(PinFlow::SetupNew);
    } else {
        screen_ = Screen::Locked;
    }
    dirty_ = true;
    render(millis());
}

void UIManager::update(uint32_t nowMs) {
    if (application_.fatal()) {
        if (screen_ != Screen::Fatal) {
            screen_ = Screen::Fatal;
            dirty_ = true;
        }
    } else if (!application_.authentication().unlocked() &&
               !application_.authentication().setupRequired() &&
               screen_ != Screen::Locked && screen_ != Screen::Pin) {
        forceLocked();
    }

    ButtonEvent event;
    while (buttons_.pop(event)) handle(event, nowMs);

    if (screen_ == Screen::PasswordReveal &&
        static_cast<int32_t>(nowMs - revealUntilMs_) >= 0) {
        secureClear(revealedPassword_);
        screen_ = Screen::CredentialDetail;
        dirty_ = true;
    }
    if (screen_ == Screen::Message && messageUntilMs_ != 0 &&
        static_cast<int32_t>(nowMs - messageUntilMs_) >= 0) {
        secureClear(messageText_);
        messageTitle_.clear();
        screen_ = messageReturn_;
        dirty_ = true;
    }
    if (screen_ == Screen::HidSending && !application_.usb().typing()) {
        showMessage("USB HID", "Typing complete", Screen::CredentialDetail);
    }

    if (screen_ == Screen::CredentialDelete || screen_ == Screen::TotpDelete) {
        if (buttons_.isDown(ButtonId::Select) &&
            buttons_.heldFor(ButtonId::Select, nowMs) >= 2000U) {
            const bool credential = screen_ == Screen::CredentialDelete;
            const bool result = credential
                                    ? application_.deleteCredential(selectedId_)
                                    : application_.deleteTotp(selectedId_);
            selectedId_ = 0;
            listSelection_ = 0;
            showMessage(result ? "DELETED" : "DELETE ERROR",
                        result ? "Entry removed" : "Storage unchanged",
                        credential ? Screen::VaultList : Screen::TotpList);
        }
    }
    if (screen_ == Screen::FactoryHold && buttons_.isDown(ButtonId::Select) &&
        buttons_.heldFor(ButtonId::Select, nowMs) >= 2000U) {
        const bool result = application_.factoryReset(currentPin_);
        clearPinData();
        showMessage(result ? "FACTORY RESET" : "RESET ERROR",
                    result ? "Erasing; restarting" : "Wipe reported failure",
                    Screen::Locked, 5000);
    }

    const bool periodic = screen_ == Screen::Dashboard ||
                          screen_ == Screen::TotpCode ||
                          screen_ == Screen::UsbFunctions ||
                          screen_ == Screen::Locked ||
                          screen_ == Screen::CredentialDelete ||
                          screen_ == Screen::TotpDelete ||
                          screen_ == Screen::FactoryHold;
    if (dirty_ || (periodic && nowMs - lastRenderMs_ >= 250U)) render(nowMs);
}

void UIManager::forceLocked() {
    clearPinData();
    secureClear(revealedPassword_);
    secureClear(credentialInfo_);
    selectedId_ = 0;
    screen_ = application_.authentication().setupRequired() ? Screen::Pin
                                                             : Screen::Locked;
    if (application_.authentication().setupRequired()) startPin(PinFlow::SetupNew);
    dirty_ = true;
}

void UIManager::handle(const ButtonEvent& event, uint32_t nowMs) {
    if (event.type == ButtonEventType::Pressed || actionable(event.type) ||
        event.type == ButtonEventType::LongPress) {
        application_.noteActivity();
    }

    if (event.button == ButtonId::Back &&
        event.type == ButtonEventType::Pressed && application_.usb().typing()) {
        application_.usb().cancelTyping();
        showMessage("USB HID", "Transmission cancelled",
                    Screen::CredentialDetail);
        return;
    }
    if (event.button == ButtonId::Back &&
        event.type == ButtonEventType::LongPress &&
        application_.authentication().unlocked()) {
        application_.lock();
        return;
    }
    if (!actionable(event.type)) {
        if ((screen_ == Screen::CredentialDelete ||
             screen_ == Screen::TotpDelete || screen_ == Screen::FactoryHold) &&
            (event.type == ButtonEventType::Pressed ||
             event.type == ButtonEventType::Released)) {
            dirty_ = true;
        }
        return;
    }
    handleShort(event.button, nowMs);
}

void UIManager::handleShort(ButtonId button, uint32_t nowMs) {
    (void)nowMs;
    if (screen_ == Screen::Fatal) return;
    if (screen_ == Screen::Pin) {
        handlePin(button);
        return;
    }

    const int delta = button == ButtonId::Up ? -1 :
                      button == ButtonId::Down ? 1 : 0;
    switch (screen_) {
        case Screen::Locked: {
            if (button == ButtonId::Select) {
                uint64_t unixTime = 0;
                const bool rtcValid = application_.rtc().now(unixTime);
                if (application_.authentication().retryDelayRemaining(
                        rtcValid, unixTime, millis()) == 0) {
                    startPin(PinFlow::Unlock);
                }
            }
            break;
        }
        case Screen::Dashboard:
            if (delta != 0) adjustSelection(mainSelection_, 5, delta);
            if (button == ButtonId::Select) {
                listSelection_ = 0;
                if (mainSelection_ == 0) screen_ = Screen::VaultList;
                if (mainSelection_ == 1) screen_ = Screen::TotpList;
                if (mainSelection_ == 2) screen_ = Screen::UsbFunctions;
                if (mainSelection_ == 3) screen_ = Screen::Settings;
                if (mainSelection_ == 4) screen_ = Screen::DeviceInfo;
            }
            break;
        case Screen::VaultList: {
            const int count = static_cast<int>(application_.credentials().count());
            if (delta != 0 && count != 0) adjustSelection(listSelection_, count, delta);
            if (button == ButtonId::Select && count != 0) {
                selectedId_ = application_.credentials().entries()[listSelection_].id;
                detailSelection_ = 0;
                screen_ = Screen::CredentialDetail;
            } else if (button == ButtonId::Back) {
                screen_ = Screen::Dashboard;
            }
            break;
        }
        case Screen::CredentialDetail:
            if (delta != 0) adjustSelection(detailSelection_, 6, delta);
            if (button == ButtonId::Back) {
                screen_ = Screen::VaultList;
            } else if (button == ButtonId::Select) {
                if (detailSelection_ == 0) {
                    Credential record;
                    if (application_.credentials().get(selectedId_, record)) {
                        revealedPassword_ = record.password;
                        record.clearSensitive();
                        revealOffset_ = 0;
                        revealUntilMs_ = millis() + 10000U;
                        screen_ = Screen::PasswordReveal;
                    } else {
                        showMessage("VAULT ERROR", "Could not decrypt entry",
                                    Screen::VaultList);
                    }
                } else if (detailSelection_ == 1 || detailSelection_ == 2) {
                    hidPassword_ = detailSelection_ == 2;
                    screen_ = Screen::HidConfirm;
                } else if (detailSelection_ == 3) {
                    Credential record;
                    if (application_.credentials().get(selectedId_, record)) {
                        secureClear(credentialInfo_);
                        if (!record.url.empty())
                            credentialInfo_ = "URL: " + record.url;
                        if (!record.notes.empty()) {
                            if (!credentialInfo_.empty()) credentialInfo_ += "  ";
                            credentialInfo_ += "NOTES: " + record.notes;
                        }
                        infoOffset_ = 0;
                        record.clearSensitive();
                        screen_ = Screen::CredentialInfo;
                    } else {
                        showMessage("VAULT ERROR", "Could not decrypt entry",
                                    Screen::VaultList);
                    }
                } else if (detailSelection_ == 4) {
                    screen_ = Screen::CredentialDelete;
                } else {
                    screen_ = Screen::VaultList;
                }
            }
            break;
        case Screen::CredentialInfo:
            if (button == ButtonId::Back || button == ButtonId::Select) {
                secureClear(credentialInfo_);
                screen_ = Screen::CredentialDetail;
            } else if (button == ButtonId::Up && infoOffset_ >= 21) {
                infoOffset_ -= 21;
            } else if (button == ButtonId::Down &&
                       infoOffset_ + 84 < credentialInfo_.size()) {
                infoOffset_ += 21;
            }
            break;
        case Screen::PasswordReveal:
            if (button == ButtonId::Back || button == ButtonId::Select) {
                secureClear(revealedPassword_);
                screen_ = Screen::CredentialDetail;
            } else if (button == ButtonId::Up && revealOffset_ >= 21) {
                revealOffset_ -= 21;
            } else if (button == ButtonId::Down &&
                       revealOffset_ + 63 < revealedPassword_.size()) {
                revealOffset_ += 21;
            }
            break;
        case Screen::HidConfirm:
            if (button == ButtonId::Back) {
                screen_ = Screen::CredentialDetail;
            } else if (button == ButtonId::Select) {
                if (application_.typeCredential(selectedId_, hidPassword_)) {
                    screen_ = Screen::HidSending;
                } else {
                    showMessage("USB HID", "HID unavailable or invalid text",
                                Screen::CredentialDetail, 2500);
                }
            }
            break;
        case Screen::HidSending:
            if (button == ButtonId::Back) {
                application_.usb().cancelTyping();
                showMessage("USB HID", "Transmission cancelled",
                            Screen::CredentialDetail);
            }
            break;
        case Screen::CredentialDelete:
            if (button == ButtonId::Back) screen_ = Screen::CredentialDetail;
            break;
        case Screen::TotpList: {
            const int count = static_cast<int>(application_.otp().count());
            if (delta != 0 && count != 0) adjustSelection(listSelection_, count, delta);
            if (button == ButtonId::Select && count != 0) {
                selectedId_ = application_.otp().entries()[listSelection_].id;
                screen_ = Screen::TotpCode;
            } else if (button == ButtonId::Back) {
                screen_ = Screen::Dashboard;
            }
            break;
        }
        case Screen::TotpCode:
            if (button == ButtonId::Back) screen_ = Screen::TotpList;
            if (button == ButtonId::Select) screen_ = Screen::TotpDelete;
            break;
        case Screen::TotpDelete:
            if (button == ButtonId::Back) screen_ = Screen::TotpCode;
            break;
        case Screen::UsbFunctions:
            if (button == ButtonId::Back) {
                screen_ = Screen::Dashboard;
            } else if (button == ButtonId::Select) {
                if (application_.provisioningAuthorized()) {
                    application_.revokeProvisioning();
                } else {
                    if (!application_.authorizeProvisioning()) {
                        showMessage("CDC NOT READY", "Open the serial port first",
                                    Screen::UsbFunctions, 2200);
                    }
                }
            }
            break;
        case Screen::Settings:
            if (delta != 0) adjustSelection(settingsSelection_, 8, delta);
            if (button == ButtonId::Back) screen_ = Screen::Dashboard;
            if (button == ButtonId::Select) {
                if (settingsSelection_ == 0) {
                    if (!localCalendar(editTime_)) editTime_ = CalendarTime{};
                    editField_ = 0;
                    screen_ = Screen::DateTimeEdit;
                } else if (settingsSelection_ == 1) {
                    adjustmentOriginal_ =
                        application_.configuration().settings().idleTimeoutSeconds;
                    adjustmentValue_ = adjustmentOriginal_;
                    screen_ = Screen::AdjustIdle;
                } else if (settingsSelection_ == 2) {
                    startPin(PinFlow::ChangeCurrent);
                } else if (settingsSelection_ == 3) {
                    adjustmentOriginal_ =
                        application_.configuration().settings().timezoneMinutes;
                    adjustmentValue_ = adjustmentOriginal_;
                    screen_ = Screen::AdjustTimezone;
                } else if (settingsSelection_ == 4) {
                    adjustmentOriginal_ = static_cast<int>(
                        application_.configuration().settings().keyboardLayout);
                    adjustmentValue_ = adjustmentOriginal_;
                    screen_ = Screen::AdjustKeyboard;
                } else if (settingsSelection_ == 5) {
                    adjustmentOriginal_ =
                        application_.configuration().settings().displayContrast;
                    adjustmentValue_ = adjustmentOriginal_;
                    screen_ = Screen::AdjustBrightness;
                } else if (settingsSelection_ == 6) {
                    screen_ = Screen::FactoryWarning;
                } else {
                    screen_ = Screen::Dashboard;
                }
            }
            break;
        case Screen::DateTimeEdit:
            if (delta != 0) adjustDate(-delta);  // UP increases, DOWN decreases.
            if (button == ButtonId::Back) screen_ = Screen::Settings;
            if (button == ButtonId::Select) {
                if (++editField_ >= 6) {
                    uint64_t unixTime = 0;
                    editTime_.weekday = TimeUtils::weekday(
                        editTime_.year, editTime_.month, editTime_.day);
                    const bool result = TimeUtils::toUnix(editTime_, unixTime) &&
                                        application_.setTime(unixTime);
                    showMessage(result ? "CLOCK SET" : "CLOCK ERROR",
                                result ? "UTC time saved" : "RTC write failed",
                                Screen::Settings);
                }
            }
            break;
        case Screen::AdjustIdle:
        case Screen::AdjustTimezone:
        case Screen::AdjustKeyboard:
        case Screen::AdjustBrightness:
            if (delta != 0) {
                if (screen_ == Screen::AdjustIdle) {
                    static constexpr int choices[] = {30, 60, 120, 300, 600,
                                                       900, 1800, 3600};
                    int index = 0;
                    while (index < 7 && choices[index] != adjustmentValue_) ++index;
                    index = (index + (delta < 0 ? 1 : 7)) % 8;
                    adjustmentValue_ = choices[index];
                } else if (screen_ == Screen::AdjustTimezone) {
                    adjustmentValue_ += delta > 0 ? -30 : 30;
                    if (adjustmentValue_ < -720) adjustmentValue_ = 840;
                    if (adjustmentValue_ > 840) adjustmentValue_ = -720;
                } else if (screen_ == Screen::AdjustKeyboard) {
                    adjustmentValue_ = (adjustmentValue_ +
                                        (delta > 0 ? 1 : 10)) % 11;
                } else {
                    adjustmentValue_ += delta > 0 ? -16 : 16;
                    adjustmentValue_ = std::clamp(adjustmentValue_, 15, 255);
                }
            }
            if (button == ButtonId::Back) screen_ = Screen::Settings;
            if (button == ButtonId::Select) {
                auto& settings = application_.configuration().settings();
                if (screen_ == Screen::AdjustIdle)
                    settings.idleTimeoutSeconds = adjustmentValue_;
                if (screen_ == Screen::AdjustTimezone)
                    settings.timezoneMinutes = adjustmentValue_;
                if (screen_ == Screen::AdjustKeyboard)
                    settings.keyboardLayout =
                        static_cast<KeyboardLayout>(adjustmentValue_);
                if (screen_ == Screen::AdjustBrightness)
                    settings.displayContrast =
                        static_cast<uint8_t>(adjustmentValue_);
                const bool saved = application_.saveSettings();
                showMessage(saved ? "SETTINGS" : "SETTINGS ERROR",
                            saved ? "Saved" : "Write failed", Screen::Settings);
            }
            break;
        case Screen::FactoryWarning:
            if (button == ButtonId::Back) screen_ = Screen::Settings;
            if (button == ButtonId::Select) startPin(PinFlow::Factory);
            break;
        case Screen::FactoryHold:
            if (button == ButtonId::Back) {
                clearPinData();
                screen_ = Screen::Settings;
            }
            break;
        case Screen::DeviceInfo:
            if (button == ButtonId::Back || button == ButtonId::Select)
                screen_ = Screen::Dashboard;
            break;
        case Screen::Message:
            if (button == ButtonId::Back || button == ButtonId::Select) {
                secureClear(messageText_);
                messageTitle_.clear();
                screen_ = messageReturn_;
            }
            break;
        case Screen::Fatal:
        case Screen::Pin:
            break;
    }
    dirty_ = true;
}

void UIManager::handlePin(ButtonId button) {
    if (button == ButtonId::Up) {
        digit_ = static_cast<uint8_t>((digit_ + 1U) % 10U);
    } else if (button == ButtonId::Down) {
        digit_ = static_cast<uint8_t>((digit_ + 9U) % 10U);
    } else if (button == ButtonId::Select) {
        if (pinEntry_.size() < limits::PIN_DIGITS) {
            pinEntry_.push_back(static_cast<char>('0' + digit_));
            digit_ = 0;
        }
        if (pinEntry_.size() == limits::PIN_DIGITS) completePinEntry();
    } else if (button == ButtonId::Back) {
        if (!pinEntry_.empty()) {
            pinEntry_.back() = '\0';
            pinEntry_.pop_back();
        } else if (pinFlow_ == PinFlow::Unlock) {
            clearPinData();
            screen_ = Screen::Locked;
        } else if (pinFlow_ == PinFlow::ChangeCurrent ||
                   pinFlow_ == PinFlow::ChangeNew ||
                   pinFlow_ == PinFlow::ChangeConfirm ||
                   pinFlow_ == PinFlow::Factory) {
            clearPinData();
            screen_ = Screen::Settings;
        }
    }
    dirty_ = true;
}

void UIManager::completePinEntry() {
    switch (pinFlow_) {
        case PinFlow::SetupNew:
            secureClear(firstPin_);
            firstPin_ = pinEntry_;
            resetPinEntry();
            pinFlow_ = PinFlow::SetupConfirm;
            break;
        case PinFlow::SetupConfirm: {
            const bool result = application_.setupPin(firstPin_, pinEntry_);
            clearPinData();
            if (result) {
                screen_ = Screen::Dashboard;
                showMessage("PIN CREATED", "Vault initialized",
                            Screen::Dashboard, 1600);
            } else {
                startPin(PinFlow::SetupNew);
                showMessage("SETUP ERROR", "PIN mismatch or storage error",
                            Screen::Pin, 2200);
            }
            break;
        }
        case PinFlow::Unlock: {
            const bool result = application_.unlock(pinEntry_);
            clearPinData();
            if (result) {
                showMessage("UNLOCKED", "Vault authentication OK",
                            Screen::Dashboard, 1000);
            } else {
                showMessage("AUTH FAILED", "PIN rejected", Screen::Locked,
                            1400);
            }
            break;
        }
        case PinFlow::ChangeCurrent:
            if (application_.reauthenticate(pinEntry_)) {
                secureClear(currentPin_);
                currentPin_ = pinEntry_;
                resetPinEntry();
                pinFlow_ = PinFlow::ChangeNew;
            } else {
                clearPinData();
                showMessage("AUTH FAILED", "Current PIN rejected",
                            Screen::Settings);
            }
            break;
        case PinFlow::ChangeNew:
            secureClear(firstPin_);
            firstPin_ = pinEntry_;
            resetPinEntry();
            pinFlow_ = PinFlow::ChangeConfirm;
            break;
        case PinFlow::ChangeConfirm: {
            const bool result =
                application_.changePin(currentPin_, firstPin_, pinEntry_);
            clearPinData();
            showMessage(result ? "PIN CHANGED" : "PIN ERROR",
                        result ? "New PIN saved" : "Confirmation failed",
                        Screen::Settings);
            break;
        }
        case PinFlow::Factory:
            if (application_.reauthenticate(pinEntry_)) {
                secureClear(currentPin_);
                currentPin_ = pinEntry_;
                secureClear(pinEntry_);
                pinFlow_ = PinFlow::None;
                screen_ = Screen::FactoryHold;
            } else {
                clearPinData();
                showMessage("AUTH FAILED", "Factory reset cancelled",
                            Screen::Settings);
            }
            break;
        case PinFlow::None:
            break;
    }
    dirty_ = true;
}

void UIManager::startPin(PinFlow flow) {
    secureClear(pinEntry_);
    if (flow != PinFlow::SetupConfirm && flow != PinFlow::ChangeConfirm) {
        secureClear(firstPin_);
    }
    if (flow != PinFlow::ChangeNew && flow != PinFlow::ChangeConfirm &&
        flow != PinFlow::Factory) {
        secureClear(currentPin_);
    }
    digit_ = 0;
    pinFlow_ = flow;
    screen_ = Screen::Pin;
    dirty_ = true;
}

void UIManager::resetPinEntry() {
    secureClear(pinEntry_);
    digit_ = 0;
}

void UIManager::clearPinData() {
    secureClear(pinEntry_);
    secureClear(firstPin_);
    secureClear(currentPin_);
    digit_ = 0;
    pinFlow_ = PinFlow::None;
}

void UIManager::showMessage(const std::string& title,
                            const std::string& message, Screen returnTo,
                            uint32_t durationMs) {
    messageTitle_ = title;
    secureClear(messageText_);
    messageText_ = message;
    messageReturn_ = returnTo;
    messageUntilMs_ = durationMs == 0 ? 0 : millis() + durationMs;
    screen_ = Screen::Message;
    dirty_ = true;
}

void UIManager::adjustSelection(int& selection, int count, int delta) {
    if (count <= 0) {
        selection = 0;
        return;
    }
    selection = (selection + delta) % count;
    if (selection < 0) selection += count;
}

void UIManager::adjustDate(int delta) {
    if (delta == 0) return;
    auto wrap = [delta](int value, int minimum, int maximum) {
        value += delta;
        if (value > maximum) value = minimum;
        if (value < minimum) value = maximum;
        return value;
    };
    switch (editField_) {
        case 0:
            editTime_.year = static_cast<uint16_t>(
                wrap(editTime_.year, 2000, 2099));
            break;
        case 1:
            editTime_.month = static_cast<uint8_t>(
                wrap(editTime_.month, 1, 12));
            break;
        case 2:
            editTime_.day = static_cast<uint8_t>(wrap(
                editTime_.day, 1,
                TimeUtils::daysInMonth(editTime_.year, editTime_.month)));
            break;
        case 3:
            editTime_.hour = static_cast<uint8_t>(wrap(editTime_.hour, 0, 23));
            break;
        case 4:
            editTime_.minute =
                static_cast<uint8_t>(wrap(editTime_.minute, 0, 59));
            break;
        case 5:
            editTime_.second =
                static_cast<uint8_t>(wrap(editTime_.second, 0, 59));
            break;
        default:
            break;
    }
    const uint8_t days = TimeUtils::daysInMonth(editTime_.year, editTime_.month);
    if (editTime_.day > days) editTime_.day = days;
}

bool UIManager::localCalendar(CalendarTime& calendar) const {
    uint64_t unixTime = 0;
    if (!application_.rtc().now(unixTime)) return false;
    const int32_t offset =
        static_cast<int32_t>(application_.configuration().settings().timezoneMinutes) *
        60;
    if (offset < 0 && unixTime < static_cast<uint64_t>(-offset)) return false;
    unixTime = offset < 0 ? unixTime - static_cast<uint64_t>(-offset)
                          : unixTime + static_cast<uint64_t>(offset);
    return TimeUtils::fromUnix(unixTime, calendar);
}

void UIManager::render(uint32_t nowMs) {
    lastRenderMs_ = nowMs;
    dirty_ = false;
    switch (screen_) {
        case Screen::Fatal:
            display_.showError("STARTUP ERROR", application_.fatalCode());
            return;
        case Screen::Locked:
            renderLocked(nowMs);
            return;
        case Screen::Pin:
            renderPin();
            return;
        case Screen::Dashboard:
            renderDashboard();
            return;
        case Screen::VaultList:
            renderVaultList();
            return;
        case Screen::CredentialDetail:
            renderCredentialDetail();
            return;
        case Screen::CredentialInfo:
            renderCredentialInfo();
            return;
        case Screen::PasswordReveal:
            renderPasswordReveal(nowMs);
            return;
        case Screen::HidConfirm:
            display_.beginFrame("CONFIRM USB HID", "HID");
            display_.text(0, 15, hidPassword_ ? "Type PASSWORD?" : "Type USERNAME?");
            display_.text(0, 29, "Host receives keystrokes");
            display_.text(0, 45, "SELECT yes  BACK no");
            display_.commit();
            return;
        case Screen::HidSending:
            display_.beginFrame("USB HID", "SEND");
            display_.centered(20, "Typing authorized data");
            display_.centered(38, "BACK cancels");
            display_.commit();
            return;
        case Screen::CredentialDelete:
            renderDelete("credential", nowMs);
            return;
        case Screen::TotpList:
            renderTotpList();
            return;
        case Screen::TotpCode:
            renderTotpCode();
            return;
        case Screen::TotpDelete:
            renderDelete("TOTP token", nowMs);
            return;
        case Screen::UsbFunctions:
            renderUsbFunctions();
            return;
        case Screen::Settings:
            renderSettings();
            return;
        case Screen::DateTimeEdit:
            renderDateTimeEdit();
            return;
        case Screen::AdjustIdle:
        case Screen::AdjustTimezone:
        case Screen::AdjustKeyboard:
        case Screen::AdjustBrightness:
            renderAdjustment();
            return;
        case Screen::FactoryWarning:
            display_.beginFrame("FACTORY RESET", "WARN");
            display_.text(0, 14, "ERASE ALL VAULT DATA");
            display_.text(0, 27, "Credentials + TOTP + PIN");
            display_.text(0, 45, "SELECT continue");
            display_.text(0, 55, "BACK cancel");
            display_.commit();
            return;
        case Screen::FactoryHold:
            renderFactoryHold(nowMs);
            return;
        case Screen::DeviceInfo:
            renderDeviceInfo();
            return;
        case Screen::Message:
            renderMessage();
            return;
    }
}

void UIManager::renderLocked(uint32_t nowMs) {
    display_.beginFrame("VAULTKEY", "LOCK");
    display_.centered(16, "DEVICE LOCKED");
    uint64_t unixTime = 0;
    const bool rtcValid = application_.rtc().now(unixTime);
    const uint32_t delay = application_.authentication().retryDelayRemaining(
        rtcValid, unixTime, nowMs);
    if (delay != 0) {
        char text[24]{};
        std::snprintf(text, sizeof(text), "Retry in %lus",
                      static_cast<unsigned long>(delay));
        display_.centered(33, text);
    } else {
        display_.centered(33, "SELECT: Enter PIN");
    }
    display_.centered(50, rtcValid ? "RTC UTC ready" : "RTC TIME INVALID");
    display_.commit();
}

void UIManager::renderPin() {
    const char* title = "ENTER PIN";
    switch (pinFlow_) {
        case PinFlow::SetupNew: title = "CREATE PIN"; break;
        case PinFlow::SetupConfirm: title = "CONFIRM PIN"; break;
        case PinFlow::Unlock: title = "UNLOCK"; break;
        case PinFlow::ChangeCurrent: title = "CURRENT PIN"; break;
        case PinFlow::ChangeNew: title = "NEW PIN"; break;
        case PinFlow::ChangeConfirm: title = "CONFIRM NEW PIN"; break;
        case PinFlow::Factory: title = "RESET: ENTER PIN"; break;
        case PinFlow::None: break;
    }
    display_.beginFrame(title, "PIN");
    std::string mask;
    for (std::size_t index = 0; index < limits::PIN_DIGITS; ++index) {
        mask.push_back(index < pinEntry_.size() ? '*' : '_');
        if (index == 2) mask.push_back(' ');
    }
    display_.centered(17, mask, 2);
    char chooser[24]{};
    std::snprintf(chooser, sizeof(chooser), "Choose digit: %u", digit_);
    display_.centered(42, chooser);
    display_.text(0, 55, "UP/DN set SEL accept");
    display_.commit();
}

void UIManager::renderDashboard() {
    display_.beginFrame("VAULTKEY", "OPEN");
    CalendarTime calendar;
    char timeLine[16]{};
    char dateLine[20]{};
    if (localCalendar(calendar)) {
        std::snprintf(timeLine, sizeof(timeLine), "%02u:%02u:%02u",
                      calendar.hour, calendar.minute, calendar.second);
        std::snprintf(dateLine, sizeof(dateLine), "%02u %s %04u", calendar.day,
                      MONTHS[calendar.month - 1], calendar.year);
    } else {
        std::snprintf(timeLine, sizeof(timeLine), "TIME NOT SET");
        std::snprintf(dateLine, sizeof(dateLine), "TOTP unavailable");
    }
    display_.centered(11, timeLine);
    display_.centered(20, dateLine);
    display_.separator(30);
    static const std::array<std::string, 5> items = {
        "Password Vault", "Authenticator", "USB Functions", "Settings",
        "Device Information"};
    const int visible = 3;
    int start = mainSelection_ - visible / 2;
    start = std::clamp(start, 0, static_cast<int>(items.size()) - visible);
    for (int row = 0; row < visible; ++row) {
        const int index = start + row;
        display_.text(0, 33 + row * 10,
                      std::string(index == mainSelection_ ? "> " : "  ") +
                          items[index],
                      index == mainSelection_);
    }
    display_.commit();
}

void UIManager::renderVaultList() {
    display_.beginFrame("PASSWORD VAULT",
                        std::to_string(application_.credentials().count()).c_str());
    const auto& entries = application_.credentials().entries();
    if (entries.empty()) {
        display_.centered(20, "Vault is empty");
        display_.centered(35, "Use authorized CDC");
        display_.text(0, 55, "BACK: Menu");
        display_.commit();
        return;
    }
    const int visible = 5;
    int start = listSelection_ - visible / 2;
    start = std::clamp(start, 0,
                       std::max(0, static_cast<int>(entries.size()) - visible));
    for (int row = 0; row < visible && start + row < static_cast<int>(entries.size());
         ++row) {
        const int index = start + row;
        display_.text(0, 12 + row * 10,
                      std::string(index == listSelection_ ? "> " : "  ") +
                          entries[index].primary,
                      index == listSelection_);
    }
    display_.commit();
}

void UIManager::renderCredentialDetail() {
    Credential record;
    if (!application_.credentials().get(selectedId_, record)) {
        display_.showError("VAULT ERROR", "Record authentication failed");
        return;
    }
    display_.beginFrame(record.service.c_str(), "CRED");
    display_.text(0, 12, "User: " + record.username);
    display_.text(0, 22, "Password: ********");
    display_.separator(32);
    static const std::array<std::string, 6> actions = {
        "Show Password", "Type Username", "Type Password", "View Details",
        "Delete", "Back"};
    const int start = std::clamp(detailSelection_ - 1, 0, 4);
    for (int row = 0; row < 3 && start + row < 6; ++row) {
        const int index = start + row;
        display_.text(0, 35 + row * 9,
                      std::string(index == detailSelection_ ? "> " : "  ") +
                          actions[index],
                      index == detailSelection_);
    }
    display_.commit();
    record.clearSensitive();
}

void UIManager::renderCredentialInfo() {
    display_.beginFrame("CREDENTIAL DETAILS", "INFO");
    if (credentialInfo_.empty()) {
        display_.centered(25, "No URL or notes");
    } else {
        for (int row = 0; row < 4; ++row) {
            const std::size_t offset =
                infoOffset_ + static_cast<std::size_t>(row * 21);
            if (offset < credentialInfo_.size())
                display_.text(0, 13 + row * 10,
                              credentialInfo_.substr(offset, 21));
        }
    }
    display_.text(0, 54, "UP/DN scroll BACK");
    display_.commit();
}

void UIManager::renderPasswordReveal(uint32_t nowMs) {
    display_.beginFrame("PASSWORD", "SHOW");
    for (int row = 0; row < 3; ++row) {
        const std::size_t offset = revealOffset_ + static_cast<std::size_t>(row * 21);
        if (offset < revealedPassword_.size())
            display_.text(0, 13 + row * 11, revealedPassword_.substr(offset, 21));
    }
    const uint32_t remaining =
        static_cast<int32_t>(revealUntilMs_ - nowMs) > 0
            ? (revealUntilMs_ - nowMs + 999U) / 1000U
            : 0;
    char footer[32]{};
    std::snprintf(footer, sizeof(footer), "Auto-hide %lus  BACK",
                  static_cast<unsigned long>(remaining));
    display_.text(0, 53, footer);
    display_.commit();
}

void UIManager::renderTotpList() {
    display_.beginFrame("AUTHENTICATOR",
                        std::to_string(application_.otp().count()).c_str());
    const auto& entries = application_.otp().entries();
    if (entries.empty()) {
        display_.centered(20, "No TOTP entries");
        display_.centered(35, "Import through CDC");
        display_.text(0, 55, "BACK: Menu");
        display_.commit();
        return;
    }
    const int visible = 5;
    int start = listSelection_ - visible / 2;
    start = std::clamp(start, 0,
                       std::max(0, static_cast<int>(entries.size()) - visible));
    for (int row = 0; row < visible && start + row < static_cast<int>(entries.size());
         ++row) {
        const int index = start + row;
        display_.text(0, 12 + row * 10,
                      std::string(index == listSelection_ ? "> " : "  ") +
                          entries[index].primary,
                      index == listSelection_);
    }
    display_.commit();
}

void UIManager::renderTotpCode() {
    TotpEntry entry;
    if (!application_.otp().get(selectedId_, entry)) {
        display_.showError("TOTP ERROR", "Record authentication failed");
        return;
    }
    display_.beginFrame(entry.issuer.c_str(), "TOTP");
    uint64_t unixTime = 0;
    if (!application_.rtc().now(unixTime)) {
        display_.centered(17, "TIME NOT SET");
        display_.centered(33, "Authenticator unavailable");
        display_.text(0, 54, "BACK return");
        display_.commit();
        entry.clearSensitive();
        return;
    }
    std::string code;
    uint16_t remaining = 0;
    if (!TOTP::generate(entry, unixTime, code)) {
        display_.showError("TOTP ERROR", "Code generation failed");
        entry.clearSensitive();
        return;
    }
    remaining = TOTP::remaining(unixTime, entry.period);
    display_.centered(17, groupedCode(code), 2);
    char validity[24]{};
    std::snprintf(validity, sizeof(validity), "Valid for %us", remaining);
    display_.centered(39, validity);
    display_.progress(4, 50, 120, 8, remaining, entry.period);
    display_.commit();
    secureClear(code);
    entry.clearSensitive();
}

void UIManager::renderUsbFunctions() {
    display_.beginFrame("USB FUNCTIONS", application_.usb().mounted() ? "USB" : "OFF");
    display_.text(0, 13,
                  std::string("CDC Serial   ") +
                      (application_.usb().cdcConnected() ? "CONNECTED" : "WAIT"));
    display_.text(0, 24,
                  std::string("HID Keyboard ") +
                      (application_.usb().hidReady() ? "READY" : "WAIT"));
    if (application_.provisioningAuthorized()) {
        char line[28]{};
        std::snprintf(line, sizeof(line), "> Revoke auth (%lus)",
                      static_cast<unsigned long>(
                          application_.provisioningSecondsRemaining()));
        display_.text(0, 39, line, true);
    } else {
        display_.text(0, 39, "> Authorize CDC 5 min", true);
    }
    display_.text(0, 54, "SELECT toggle BACK menu");
    display_.commit();
}

void UIManager::renderSettings() {
    static const std::array<std::string, 8> items = {
        "Date / Time (UTC)", "Idle lock timeout", "Change PIN", "Display timezone",
        "Keyboard layout", "Display contrast", "Factory reset", "Back"};
    renderScrollable("SETTINGS", items.data(), items.size(), settingsSelection_);
}

void UIManager::renderDateTimeEdit() {
    static const char* fields[] = {"YEAR", "MONTH", "DAY", "HOUR", "MINUTE",
                                   "SECOND"};
    display_.beginFrame("SET UTC TIME", fields[editField_]);
    char date[24]{};
    char time[24]{};
    std::snprintf(date, sizeof(date), "%04u-%02u-%02u", editTime_.year,
                  editTime_.month, editTime_.day);
    std::snprintf(time, sizeof(time), "%02u:%02u:%02u", editTime_.hour,
                  editTime_.minute, editTime_.second);
    display_.centered(17, date, 2);
    display_.centered(38, time);
    display_.text(0, 54, "UP/DN set SEL next");
    display_.commit();
}

void UIManager::renderAdjustment() {
    if (screen_ == Screen::AdjustIdle) {
        display_.beginFrame("IDLE LOCK", "SET");
        char value[24]{};
        std::snprintf(value, sizeof(value), "%d seconds", adjustmentValue_);
        display_.centered(22, value, 2);
    } else if (screen_ == Screen::AdjustTimezone) {
        display_.beginFrame("DISPLAY TIMEZONE", "SET");
        const int absolute = std::abs(adjustmentValue_);
        char value[24]{};
        std::snprintf(value, sizeof(value), "UTC%c%02d:%02d",
                      adjustmentValue_ < 0 ? '-' : '+', absolute / 60,
                      absolute % 60);
        display_.centered(22, value, 2);
        display_.text(0, 43, "TOTP always uses UTC");
    } else if (screen_ == Screen::AdjustKeyboard) {
        display_.beginFrame("KEYBOARD LAYOUT", "SET");
        display_.centered(
            22,
            Configuration::keyboardLayoutName(
                static_cast<KeyboardLayout>(adjustmentValue_)),
            2);
    } else {
        display_.beginFrame("DISPLAY CONTRAST", "SET");
        char value[24]{};
        std::snprintf(value, sizeof(value), "%d / 255", adjustmentValue_);
        display_.centered(22, value, 2);
    }
    display_.text(0, 54, "UP/DN set SEL save");
    display_.commit();
}

void UIManager::renderDelete(const char* type, uint32_t nowMs) {
    display_.beginFrame("DELETE ENTRY", "WARN");
    display_.centered(14, std::string("Delete ") + type + "?");
    display_.centered(28, "Hold SELECT 2 sec");
    const uint32_t held = buttons_.heldFor(ButtonId::Select, nowMs);
    display_.progress(4, 43, 120, 8,
                      static_cast<uint16_t>(std::min<uint32_t>(held, 2000U)),
                      2000);
    display_.text(0, 54, "BACK cancels");
    display_.commit();
}

void UIManager::renderFactoryHold(uint32_t nowMs) {
    display_.beginFrame("FACTORY RESET", "FINAL");
    display_.centered(13, "IRREVERSIBLE");
    display_.centered(27, "Hold SELECT 2 sec");
    const uint32_t held = buttons_.heldFor(ButtonId::Select, nowMs);
    display_.progress(4, 42, 120, 8,
                      static_cast<uint16_t>(std::min<uint32_t>(held, 2000U)),
                      2000);
    display_.text(0, 54, "BACK cancels");
    display_.commit();
}

void UIManager::renderDeviceInfo() {
    display_.beginFrame("DEVICE INFO", hardware::HARDWARE_VERSION);
    display_.text(0, 12,
                  std::string("FW ") + hardware::FIRMWARE_VERSION);
    display_.text(0, 22, std::string("RTC ") + application_.rtc().statusText());
    char counts[28]{};
    std::snprintf(counts, sizeof(counts), "Cred %u  TOTP %u",
                  static_cast<unsigned>(application_.credentials().count()),
                  static_cast<unsigned>(application_.otp().count()));
    display_.text(0, 32, counts);
    display_.text(0, 42,
                  std::string("USB ") +
                      (application_.usb().mounted() ? "mounted" : "not mounted"));
    display_.text(0, 52,
                  std::string("Store ") + application_.storage().statusText());
    display_.commit();
}

void UIManager::renderMessage() {
    display_.beginFrame(messageTitle_.c_str(), "INFO");
    for (int row = 0; row < 4; ++row) {
        const std::size_t offset = static_cast<std::size_t>(row * 21);
        if (offset < messageText_.size())
            display_.text(0, 15 + row * 10, messageText_.substr(offset, 21));
    }
    display_.commit();
}

void UIManager::renderScrollable(const char* title, const std::string* items,
                                 int count, int selection, int visible) {
    display_.beginFrame(title, nullptr);
    int start = selection - visible / 2;
    start = std::clamp(start, 0, std::max(0, count - visible));
    for (int row = 0; row < visible && start + row < count; ++row) {
        const int index = start + row;
        display_.text(0, 12 + row * 10,
                      std::string(index == selection ? "> " : "  ") +
                          items[index],
                      index == selection);
    }
    display_.commit();
}

}  // namespace vaultkey
