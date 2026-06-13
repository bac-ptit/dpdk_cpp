# DPDK Modern C++ Wrapper

A modern C++26 wrapper around [DPDK](https://www.dpdk.org/) (Data Plane Development Kit), designed with zero-overhead abstraction principles for high-performance packet processing.

> **Status:** 🚧 In Active Development — API is not yet stable.

## Features

- Modern C++26 with zero-overhead abstraction
- RAII-based resource management
- Type-safe YAML configuration via [Glaze](https://github.com/stephenberry/glaze)
- Exception-free error handling optimized for high-performance packet processing

## Requirements

| Dependency | Version |
|------------|---------|
| C++ Compiler | C++26 (GCC 15+ / Clang 20+) |
| CMake | ≥ 4.2 |
| DPDK | ≥ 22.x |
| Glaze | Latest (fetched via FetchContent) |
| yaml-cpp | System package |
| pkg-config | For DPDK discovery |

### Fedora

```bash
sudo dnf install dpdk-devel yaml-cpp-devel pkg-config cmake
```

### Ubuntu

```bash
sudo apt install libdpdk-dev libyaml-cpp-dev pkg-config cmake
```
