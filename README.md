<div align="center">

# ARM64 Call Stack Spoofing — Analysis

[![PDF Report](https://img.shields.io/badge/PDF-Report-red)](https://github.com/taekwondodev/ARM64-CallStackSpoofing/raw/main/docs/main.pdf)

</div>

Analysis of 5 call stack spoofing techniques on Windows 11 ARM64.

## Original Framework

The framework source code (`stack_spoof_arm64.c`, `stack_spoof_arm64.asm`, `build.bat`)
comes from the following repository, used without modifications:
https://github.com/xaitax/ARM64-CallStackSpoofing

This repository is NOT an official GitHub fork. It extends the original source
with a lab report document and real execution artifacts.

## What This Repository Adds

- [Lab report](https://github.com/taekwondodev/ARM64-CallStackSpoofing/raw/main/docs/main.pdf) (LaTeX, 4 chapters): ARM64 fundamentals, offensive analysis
  of all 5 scenarios, defensive detection analysis (user-mode walker limits and
  MDE kernel-mode coverage), attacker/defender tradeoffs
- Real execution artifacts per scenario: WinDbg stack traces,
  CaptureStackBackTrace output, System Informer captures, Sysmon EID 1 logs
- Detection coverage matrix: per-tool, per-scenario, with privilege level required

## Scenarios

| # | Technique | Key Finding |
|---|-----------|-------------|
| 1 | Baseline — direct call | 3 tools, 3 different frame counts on a legitimate stack (4 / 9 / 8) |
| 2 | Single-frame spoofing | WinDbg: 2 frames + null RetAddr. CaptureStackBackTrace: 6 frames (gadget visible) |
| 3 | Multi-frame recursion | 10 structurally valid frames — no user-mode signature; requires kernel-mode ML analysis |
| 4 | Stack pivot | SP outside TEB bounds — deterministic kernel signature; CaptureStackBackTrace: 0 frames |
| 5 | Spoofed process launch | Sysmon EID 1: ParentImage detectable; no CallTrace |

## Repository Structure

```
stack_spoof_arm64.c     — original framework source
stack_spoof_arm64.asm   — original framework source
build.bat               — original build script
docs/                   — lab report source (LaTeX) and compiled PDF
artifacts/              — raw captures from each scenario
```

## Disclaimer

For authorized security research and educational purposes only.
