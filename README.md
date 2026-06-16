<div align="center">

# ARM64 Call Stack Spoofing — Analysis

[![PDF Report](https://img.shields.io/badge/PDF-Report-red)](https://github.com/taekwondodev/ARM64-CallStackSpoofing/raw/main/docs/main.pdf)
[![PDF Slides](https://img.shields.io/badge/PDF-Slides-blue)](https://github.com/taekwondodev/ARM64-CallStackSpoofing/raw/main/docs/slides.pdf)

</div>

Analysis of 2 call stack spoofing techniques on Windows 11 ARM64.

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

- **Realistic target function** (`InjectExplorer`): replaces the original stub with
  a full injection pattern (`OpenProcess` + `VirtualAllocEx RWX` + `WriteProcessMemory`
  + `CreateRemoteThread`) on `explorer.exe` — benign NOP+RET payload, but the API
  call sequence triggers EDR behavioral detection, making attribution evasion measurable.
- **In-target stack capture**: `CaptureStackBackTrace` called from inside `InjectExplorer`
  for direct comparison with WinDbg `k` and System Informer captures across all scenarios.
- **[Lab report](https://github.com/taekwondodev/ARM64-CallStackSpoofing/raw/main/docs/main.pdf)**
  (LaTeX, 4 chapters): ARM64 fundamentals, offensive analysis of all 3 scenarios,
  defensive detection analysis (user-mode walker limits and EDR kernel-mode coverage),
  attacker/defender tradeoffs.
- **Real execution artifacts** per scenario: WinDbg stack traces, CaptureStackBackTrace
  output, System Informer captures, detection coverage matrix per-tool/per-scenario.

## What Was Removed vs the Original

- **Multi-frame recursion** (`RecursiveSpoofHelper`): removed. Analysis shows that
  regardless of recursion depth N, the first semantic call site failure always occurs
  at depth 2 — RSH's base case must carry a gadget as its return address, so any
  checker with budget ≥ 2 catches it at the same point as single-frame spoofing.
  Adding more recursion levels shifts the failure pair upward by a constant but does
  not increase the depth at which the first anomaly appears. The technique offers no
  advantage over Single-Frame Spoofing against any checker with budget ≥ 2.

## Techniques

**Baseline** is a direct call with no spoofing — it establishes the ground truth of what
a legitimate stack looks like across the 3 tools (4 / 9 / 8 frames depending on the tool).
It is not a spoofing technique.

| Technique | Key Finding |
|-----------|-------------|
| Single-Frame Spoofing | WinDbg: 2 frames + null RetAddr. CaptureStackBackTrace: 6 frames (gadget at [01], `main` visible at [02]) |
| Stack Pivot | SP outside TEB bounds — deterministic signature; CaptureStackBackTrace: 0 frames |

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
