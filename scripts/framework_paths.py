"""Work around PlatformIO espressif32 8.0.0's missing transitive FS path.

Arduino-ESP32's USB library declares `depends=FS`, but PlatformIO does not add
the framework FS include directory while compiling every USB source file. The
USBHostMSC translation unit then fails even though this project only uses USB
device mode. Resolve the installed framework path dynamically; do not hardcode
a user-specific package directory.
"""

from os.path import join

Import("env")  # type: ignore[name-defined]  # supplied by PlatformIO/SCons

framework = env.PioPlatform().get_package_dir("framework-arduinoespressif32")
if framework:
    env.Append(CPPPATH=[join(framework, "libraries", "FS", "src")])
