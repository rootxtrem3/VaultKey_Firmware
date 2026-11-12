#pragma once

#include <ArduinoJson.h>
#include <Stream.h>

#include <cstddef>

#include "core/HardwareConfig.h"

namespace vaultkey {

class USBCommandHandler {
  public:
    virtual ~USBCommandHandler() = default;
    virtual bool handleUSBCommand(const char* command, JsonObjectConst request,
                                  JsonObject response,
                                  const char*& errorCode) = 0;
};

class USBProtocol {
  public:
    explicit USBProtocol(USBCommandHandler& handler) : handler_(handler) {}
    void update(Stream& stream);
    void reset();

  private:
    void process(Stream& stream);
    void sendError(Stream& stream, const char* code, const char* requestId = nullptr);
    USBCommandHandler& handler_;
    char line_[limits::USB_LINE + 1]{};
    std::size_t length_ = 0;
    bool overflow_ = false;
};

}  // namespace vaultkey
