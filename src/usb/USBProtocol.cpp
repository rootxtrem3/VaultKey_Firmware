#include "usb/USBProtocol.h"

#include <cstring>

#include "security/SecureZero.h"

namespace vaultkey {

void USBProtocol::update(Stream& stream) {
    while (stream.available() > 0) {
        const int incoming = stream.read();
        if (incoming < 0) break;
        const char character = static_cast<char>(incoming);
        if (character == '\r') continue;
        if (character == '\n') {
            if (overflow_) {
                sendError(stream, "line_too_long");
            } else if (length_ != 0) {
                process(stream);
            }
            reset();
            continue;
        }
        if (overflow_) continue;
        if (length_ >= limits::USB_LINE) {
            overflow_ = true;
            continue;
        }
        line_[length_++] = character;
    }
}

void USBProtocol::reset() {
    secureZero(line_, sizeof(line_));
    length_ = 0;
    overflow_ = false;
}

void USBProtocol::process(Stream& stream) {
    line_[length_] = '\0';
    JsonDocument request;
    const DeserializationError parse = deserializeJson(request, line_);
    if (parse || !request.is<JsonObject>()) {
        sendError(stream, "invalid_json");
        return;
    }
    const JsonObjectConst object = request.as<JsonObjectConst>();
    const int version = object["v"] | 0;
    const char* command = object["cmd"] | nullptr;
    const char* requestId = object["id"] | nullptr;
    if (version != 1) {
        sendError(stream, "unsupported_protocol", requestId);
        return;
    }
    if (command == nullptr || command[0] == '\0') {
        sendError(stream, "missing_command", requestId);
        return;
    }

    JsonDocument responseDocument;
    JsonObject response = responseDocument.to<JsonObject>();
    response["v"] = 1;
    if (requestId != nullptr) response["id"] = requestId;
    const char* errorCode = "command_failed";
    const bool success =
        handler_.handleUSBCommand(command, object, response, errorCode);
    response["ok"] = success;
    if (!success) response["error"] = errorCode;
    serializeJson(responseDocument, stream);
    stream.write('\n');
    // request uses zero-copy strings into line_; erase all provisioning data.
    request.clear();
    reset();
}

void USBProtocol::sendError(Stream& stream, const char* code,
                            const char* requestId) {
    JsonDocument responseDocument;
    responseDocument["v"] = 1;
    responseDocument["ok"] = false;
    responseDocument["error"] = code;
    if (requestId != nullptr) responseDocument["id"] = requestId;
    serializeJson(responseDocument, stream);
    stream.write('\n');
}

}  // namespace vaultkey
