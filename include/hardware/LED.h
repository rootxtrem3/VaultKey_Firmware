#pragma once

namespace vaultkey {

enum class LEDPattern { Startup, Normal, Unlock, AuthFailure, Warning, Error, Wipe };

// Rev-D's green D1 is connected directly to the 3.3 V rail. This driver is
// deliberately explicit rather than pretending a controllable LED exists.
class LED {
  public:
    bool begin() { return false; }
    bool available() const { return false; }
    void set(LEDPattern) {}
    void update() {}
};

}  // namespace vaultkey
