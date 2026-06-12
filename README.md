<div align="center">

# ARM64 Call Stack Spoofing — Analysis

[![PDF Report](https://img.shields.io/badge/PDF-Report-red)](https://github.com/taekwondodev/ARM64-CallStackSpoofing/raw/main/docs/main.pdf)

</div>

Analysis of 3 call stack spoofing techniques on Windows 11 ARM64.

## Original Framework

Based on the framework by Alexander Hagenah (@xaitax) — MIT License:
https://github.com/xaitax/ARM64-CallStackSpoofing

This repository is NOT an official GitHub fork.

## What Was Retained from the Original

- Call-site gadget discovery and random selection (`CacheCallSites`, `GetRandomGadget`):
  scans the `.text` section of `ntdll.dll` for BL instructions and picks a random
  post-BL address as spoofed return — `.pdata`-aligned, non-deterministic.
- Stack pivot execution mechanism (`ExecuteWithFakeFrame` + ASM): pivots SP to a
  `VirtualAlloc`'d region outside TEB bounds, breaking user-mode stack walkers.
- Single-frame spoofer (`SpoofCallStack` ASM): replaces the caller return address
  in-frame with a gadget address before calling the target function.

## What This Repository Adds

- **Multi-frame recursion fix**: `SpoofCallStack` applied also to the base case of
  `RecursiveSpoofHelper`, so the `.pdata` walker sees the spoofed frame as the top
  of the chain, not the helper function itself.
- **Realistic target function** (`InjectExplorer`): replaces the original stub with
  a full injection pattern (`OpenProcess` + `VirtualAllocEx RWX` + `WriteProcessMemory`
  + `CreateRemoteThread`) on `explorer.exe` — benign NOP+RET payload, but the API
  call sequence triggers EDR behavioral detection, making attribution evasion measurable.
- **In-target stack capture**: `CaptureStackBackTrace` called from inside `InjectExplorer`
  for direct comparison with WinDbg `k` and System Informer captures across all scenarios.
- **[Lab report](https://github.com/taekwondodev/ARM64-CallStackSpoofing/raw/main/docs/main.pdf)**
  (LaTeX, 4 chapters): ARM64 fundamentals, offensive analysis of all 4 scenarios,
  defensive detection analysis (user-mode walker limits and MDE kernel-mode coverage),
  attacker/defender tradeoffs.
- **Real execution artifacts** per scenario: WinDbg stack traces, CaptureStackBackTrace
  output, System Informer captures, detection coverage matrix per-tool/per-scenario.

## Scenarios

**Baseline (scenario 1)** is a direct call with no spoofing — it establishes the ground
truth of what a legitimate stack looks like across the 3 tools (4 / 9 / 8 frames depending
on the tool). It is not a spoofing technique.

| # | Technique | Key Finding |
|---|-----------|-------------|
| 2 | Single-frame spoofing | WinDbg: 2 frames + null RetAddr. CaptureStackBackTrace: 6 frames (gadget visible) |
| 3 | Multi-frame recursion | 10 structurally valid frames — no user-mode signature; requires kernel-mode analysis |
| 4 | Stack pivot | SP outside TEB bounds — deterministic kernel signature; CaptureStackBackTrace: 0 frames |

## Repository Structure

```
stack_spoof_arm64.c     — modified framework source (see header for change log)
stack_spoof_arm64.asm   — original assembly (SpoofCallStack, ExecuteWithFakeFrame)
build.bat               — original build script
docs/                   — lab report source (LaTeX) and compiled PDF
artifacts/              — raw captures from each scenario
```

## Disclaimer

For authorized security research and educational purposes only.
