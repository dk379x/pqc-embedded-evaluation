# ESP32-SLH-DSA-FIPS205

Implementation and benchmarking of the SLH-DSA (FIPS 205) post-quantum digital signature scheme on the ESP32 platform.

## Overview

This repository provides a resource-constrained implementation of the **SLH-DSA** algorithm (formerly known as SPHINCS+) standardized by **NIST** in **FIPS 205** for use on **Espressif ESP32** microcontrollers. The implementation targets secure, quantum-resistant digital signatures for embedded and IoT devices.

## Features

- 🛡️ SLH-DSA (FIPS 205) cryptographic primitives
- ⚙️ Hardware-specific integration for ESP32 using ESP-IDF
- 📊 Benchmarking: execution time, RAM/flash usage, CPU cycles
- 🔌 UART-based logging for performance analysis
- 🔐 Integration with ESP32 TRNG for secure randomness

## Requirements

- ESP32-PICO-KIT or any ESP32 development board  
- ESP-IDF v4.4 or newer  
- Python 3.x (for flashing/debug scripts)  
- OpenOCD or ESP-PROG (for optional JTAG debugging)

## Folder Structure



## Getting Started

1. **Clone the repo**  

2. **Build and flash the firmware**

3. **View logs**


## References

- [FIPS 205 – SLH-DSA Standard](https://csrc.nist.gov/publications/detail/fips/205/final)
- SPHINCS+ Reference Implementation
- [Espressif ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/)

## License

MIT License. See `LICENSE` for details.
