# PQC Embedded Evaluation Framework

Evaluation framework and benchmarking modules for NIST post-quantum cryptographic algorithms  
(**ML-KEM, ML-DSA, SLH-DSA**) on resource-constrained embedded platforms.

---

## Overview

This repository contains an embedded evaluation framework designed for systematic
execution, measurement, and future optimization of post-quantum cryptographic
algorithms on constrained microcontrollers.

The framework currently targets ESP32-C6 (RISC-V) but is designed to be portable
to other embedded platforms.

---

## Features

- Support for **ML-KEM**, **ML-DSA**, **SLH-DSA**
- Execution time measurement
- Dynamic heap usage monitoring
- Configurable evaluation scenarios
- Benchmarking modules as part of the framework
- No OpenSSL dependency
- Designed for academic reproducibility
- Dedicated `liboqs` branch integrated into the framework

---

## Repository Structure

```
.
├── .vscode/                # VSCode configuration
├── build/                  # ESP-IDF build output
├── components/
│   ├── crypto/             # Lightweight crypto helpers
│   │   ├── CMakeLists.txt
│   │   ├── randombytes.c
│   │   └── randombytes.h
│   │
│   └── liboqs/             # Integrated liboqs (dedicated branch)
│       ├── src/
│       ├── CMakeLists.txt
│       └── shim.c          # ESP-IDF compatibility layer
│
├── main/
│   ├── main.c              # Evaluation runner
│   └── bench/              # Benchmarking / evaluation modules
│       ├── mlkem/          # ML-KEM evaluation
│       ├── mldsa/          # ML-DSA evaluation
│       └── slhdsa/         # SLH-DSA evaluation
│
├── CMakeLists.txt
├── sdkconfig
└── README.md
```

---

## Configuration

All evaluation and logging options are configured via:

```
idf.py menuconfig
```

Configurable parameters include:

- Algorithm selection
- Security level
- Logging verbosity
- Heap monitoring
- Execution loops

---

## Measurement Metrics

The framework records:

- Key generation time
- Encapsulation / Signing time
- Decapsulation / Verification time
- Minimum free heap
- Largest free block
- Fragmentation behavior

---

## Platform

Primary evaluation platform:

- **ESP32-C6**
- 32-bit RISC-V core
- No external PSRAM
- No hardware PQC acceleration

The framework is portable to other ESP32 and RISC-V platforms.

---

## Research Context

This framework was developed for academic research focused on:

- Practical feasibility of PQC on embedded devices
- Performance and memory trade-offs
- Optimization strategies
- Future energy and side-channel analysis
- Reproducible benchmarking

---

## Future Directions

Planned extensions include:

- Energy consumption measurements
- Side-channel leakage evaluation
- Additional RISC-V microcontrollers
- Hardware acceleration analysis
- Protocol-level PQC integration
- Implementation-level optimizations

---

## License

MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.