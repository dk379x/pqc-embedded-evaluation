# pqc-embedded-evaluation

Configurable and reproducible evaluation environment for benchmarking
**NIST-standardized post-quantum cryptographic algorithms** on constrained
embedded systems, with a focus on **ESP32-C6** microcontrollers.

---

## Overview

This repository provides an experimental evaluation framework for analyzing the
**feasibility, performance, and resource requirements** of post-quantum
cryptographic (PQC) algorithms on low-power embedded platforms.

The project targets algorithms standardized by the U.S. National Institute of
Standards and Technology (NIST) in **FIPS 203–205**, including:

- **ML-KEM** (key encapsulation)
- **ML-DSA** (lattice-based digital signatures)
- **SLH-DSA** (stateless hash-based digital signatures, formerly SPHINCS+)

All algorithms are evaluated using a unified benchmark harness built on top of
the **ESP-IDF** framework and the **Open Quantum Safe (liboqs)** library.

---

## Key Features

- 🧪 Configurable benchmark runner using ESP-IDF `menuconfig` (Kconfig)
- 🔐 Support for **ML-KEM, ML-DSA, and SLH-DSA** (FIPS 203–205)
- 📊 Measurement of:
  - execution time (microseconds)
  - memory usage (heap availability)
  - algorithm-specific key and signature sizes
- 📈 Dual logging mode:
  - machine-readable **CSV output**
  - human-friendly **visual UART logs**
- 🔁 Support for warm-up iterations and repeated measurements (N runs)
- ⚙️ Designed for **resource-constrained microcontrollers** (no external RAM)
- 🔐 Secure randomness sourced from ESP32 hardware TRNG

---

## Target Platform

- **ESP32-C6**
  - 32-bit RISC-V core
  - Up to 160 MHz
  - 512 KB on-chip SRAM
  - No external PSRAM
  - Hardware RNG, AES, SHA accelerators (no PQC acceleration)

The ESP32-C6 is used as a representative platform for IoT and edge-security
deployments with tight memory and power constraints.

---

## Software Stack

- **ESP-IDF** v5.x
- **FreeRTOS**
- **liboqs** (Open Quantum Safe)
- Cross-compiled PQC algorithms with minimal configuration
- No OpenSSL dependency

---

## Repository Structure

main/
├── main.c                 # Benchmark runner (Kconfig-controlled)
├── Kconfig                # Benchmark configuration options
├── bench/
│   ├── mlkem/              # ML-KEM benchmarks
│   ├── mldsa/              # ML-DSA benchmarks
│   └── slhdsa/             # SLH-DSA benchmarks
└── CMakeLists.txt


---

## Configuration

All benchmarks and logging options are configured via:


bash
idf.py menuconfig

Available options include:
	•	enabling or disabling individual PQC algorithms
	•	number of warm-up iterations
	•	number of measured runs
	•	CSV logging
	•	visual UART logging
	•	logging frequency (every N runs)


Running Benchmarks
	1.	Configure:

    idf.py menuconfig

	2.	Build and flash:

    idf.py build flash


3.	Monitor output:

idf.py monitor


CSV-formatted results can be captured and post-processed using standard tools
(e.g., grep, Python pandas).



Output Format

Benchmark results are emitted as:
	•	CSV lines (prefixed with CSV,) for automated analysis
	•	Human-readable logs for real-time inspection

This dual-format approach enables both reproducibility and developer-friendly
debugging.



Scope and Limitations

Current evaluation focuses on:
	•	execution time
	•	memory feasibility
	•	algorithmic overhead

Energy consumption measurements and protocol-level integration (e.g., TLS,
secure boot) are considered future work.


Intended Use

This repository is intended for:
	•	academic research and benchmarking
	•	reproducible experimental evaluation
	•	preparation of peer-reviewed publications
	•	feasibility studies for PQC deployment on embedded devices

It is not intended to be a production cryptographic library.


References
	•	NIST FIPS 203–205 — Post-Quantum Cryptography Standards
	•	Open Quantum Safe Project (liboqs)
	•	Espressif ESP-IDF Documentation


License

MIT License. See LICENSE for details.

---
