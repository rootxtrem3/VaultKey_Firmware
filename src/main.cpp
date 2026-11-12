#include <Arduino.h>

#include "core/Application.h"

namespace {
vaultkey::Application application;
}

void setup() { application.begin(); }

void loop() {
    application.update();
    delay(2);
}
