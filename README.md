# PQC Embedded Evaluation Framework

Embedded evaluation and benchmarking framework for NIST-standardized post-quantum cryptographic algorithms on resource-constrained platforms.

The framework currently targets the **ESP32-C6** and supports:

- **ML-KEM** (FIPS 203)
- **ML-DSA** (FIPS 204)
- **SLH-DSA** (FIPS 205)

This repository accompanies the PLOS ONE article:

> *Exploring hardware implementation feasibility of post-quantum cryptography in embedded systems: Evaluation of NIST-standardized ML-KEM, ML-DSA and SLH-DSA on ESP32-C6*

The manuscript has been accepted for publication in **PLOS ONE**.

---

## Overview

The project provides a modular ESP-IDF-based environment for executing, measuring, and comparing post-quantum cryptographic implementations on constrained embedded hardware.

It includes:

- algorithm-specific benchmark modules,
- combined benchmark scenarios,
- execution-time and memory measurements,
- hardware-assisted SHA-2 integration,
- realistic workload generation,
- internal temperature monitoring,
- Bluetooth Low Energy and Wi-Fi support,
- trigger support for external measurement equipment,
- an embedded-oriented `liboqs` fork integrated as a Git submodule.

The framework was designed for reproducible academic evaluation and for future extensions involving energy measurements, side-channel analysis, protocol integration, and implementation-level optimization.

---

## Repository Structure

```text
.
├── .devcontainer/              # Development-container configuration
├── .vscode/                    # Visual Studio Code configuration
├── build/                      # ESP-IDF build output
│
├── components/
│   ├── crypto/                 # Cryptographic support code
│   │   ├── CMakeLists.txt
│   │   ├── randombytes.c
│   │   └── randombytes.h
│   │
│   └── liboqs/                 # Embedded-oriented liboqs fork (Git submodule)
│
├── main/
│   ├── bench/
│   │   ├── combined/           # Combined benchmark scenarios
│   │   ├── mlkem/              # ML-KEM benchmarks
│   │   ├── mldsa/              # ML-DSA benchmarks
│   │   └── slhdsa/             # SLH-DSA benchmarks
│   │
│   ├── hardware/
│   │   └── sha2/
│   │       ├── oqs_sha2_esp.c  # ESP32 SHA-2 integration
│   │       └── oqs_sha2_esp.h
│   │
│   ├── measure/
│   │   ├── ppk2_trigger.c      # Trigger support for external measurements
│   │   └── ppk2_trigger.h
│   │
│   ├── sensor/
│   │   ├── internal_temp.c     # Internal temperature monitoring
│   │   └── internal_temp.h
│   │
│   ├── wireless/
│   │   ├── bt_le.c             # Bluetooth Low Energy support
│   │   ├── bt_le.h
│   │   ├── wifi.c              # Wi-Fi support
│   │   └── wifi.h
│   │
│   ├── workload/
│   │   ├── workload.c          # Realistic workload generation
│   │   └── workload.h
│   │
│   ├── CMakeLists.txt
│   ├── Kconfig                 # Project configuration options
│   └── main.c                  # Application entry point
│
├── .gitignore
├── .gitmodules
├── CMakeLists.txt
├── pytest_hello_world.py       # Basic ESP-IDF test
├── sdkconfig
├── sdkconfig.ci
└── README.md
```

Generated files such as `build/`, `debug.log`, `sdkconfig.old`, and editor-specific temporary files should not be committed.

---

## Requirements

- ESP-IDF **v5.5.1**
- ESP32-C6 development board
- Python environment required by ESP-IDF
- Git with submodule support
- Serial connection to the target board

Optional hardware depends on the selected evaluation scenario and may include external power-measurement equipment.

---

## Clone the Repository

Clone the repository together with its submodules:

```bash
git clone --recurse-submodules https://github.com/dk379x/pqc-embedded-evaluation.git
cd pqc-embedded-evaluation
```

For an existing clone:

```bash
git submodule update --init --recursive
```

The embedded-oriented `liboqs` fork is maintained separately at:

```text
https://github.com/dk379x/liboqs
```

---

## Build and Flash

Load the ESP-IDF environment, select the ESP32-C6 target, configure the project, and build it:

```bash
idf.py set-target esp32c6
idf.py menuconfig
idf.py build
```

Flash the firmware and open the serial monitor:

```bash
idf.py -p /dev/ttyUSB0 flash monitor
```

On macOS, the serial device may instead use a path such as:

```text
/dev/tty.usbserial-*
```

Exit the monitor with:

```text
Ctrl+]
```

---

## Configuration

Project options are available through:

```bash
idf.py menuconfig
```

Configuration is defined in `main/Kconfig`.

Depending on the selected build and benchmark module, the configuration may include:

- algorithm family,
- parameter set or security level,
- benchmark scenario,
- number of repetitions,
- logging options,
- heap and memory monitoring,
- hardware SHA-2 support,
- workload execution,
- wireless activity,
- sensor measurements,
- external measurement triggers.

The exact options available are defined by the current `Kconfig` implementation.

---

## Benchmark Modules

### ML-KEM

The ML-KEM module evaluates operations such as:

- key generation,
- encapsulation,
- decapsulation.

### ML-DSA

The ML-DSA module evaluates:

- key generation,
- signing,
- signature verification.

### SLH-DSA

The SLH-DSA module evaluates:

- key generation,
- signing,
- signature verification.

### Combined Scenarios

The `main/bench/combined/` directory contains scenarios that combine multiple operations or supporting components in a single execution flow.

---

## Measurement and Runtime Support

The framework contains dedicated modules for:

- execution-time measurements,
- heap and memory observation,
- external measurement triggering,
- internal temperature acquisition,
- realistic workload generation,
- Wi-Fi activity,
- Bluetooth Low Energy activity,
- ESP32-C6 SHA-2 hardware integration.

The availability and behavior of individual measurements depend on the selected configuration and benchmark scenario.

---

## Reproducibility

For reproducible experiments:

1. Record the ESP-IDF version.
2. Record the commit IDs of this repository and the `liboqs` submodule.
3. Preserve the active `sdkconfig`.
4. Use the same board revision and clock configuration.
5. Keep benchmark repetition counts and workload settings unchanged.
6. Record whether hardware SHA-2, wireless activity, sensors, or external triggers were enabled.
7. Report compiler optimization settings and any local source modifications.

A useful command for recording repository state is:

```bash
git rev-parse HEAD
git submodule status
```

---

## Tests

A basic ESP-IDF test file is included:

```text
pytest_hello_world.py
```

Run it using the ESP-IDF pytest workflow appropriate for the connected target and local environment.

---

## Research Context

The framework supports research on:

- feasibility of post-quantum cryptography on embedded systems,
- execution-time and memory trade-offs,
- realistic on-device workloads,
- hardware-assisted hashing,
- energy-aware benchmarking,
- side-channel measurement preparation,
- wireless and sensor activity during cryptographic execution,
- reproducible comparison of NIST-standardized PQC algorithms.

---

## Data Availability

The source code, benchmark modules, and configuration files used in the study are available in this repository:

```text
https://github.com/dk379x/pqc-embedded-evaluation
```

The corresponding embedded-oriented `liboqs` fork is available at:

```text
https://github.com/dk379x/liboqs
```

---

## Citation

A complete journal citation will be added after the PLOS ONE article receives its final bibliographic details and DOI.

Until then, please cite the accepted manuscript by title:

```text
Daniel Patryk Karcz et al.
Exploring hardware implementation feasibility of post-quantum cryptography in embedded systems:
Evaluation of NIST-standardized ML-KEM, ML-DSA and SLH-DSA on ESP32-C6.
PLOS ONE, accepted for publication.
```

---

## License

MIT License

Copyright (c) 2025-2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
