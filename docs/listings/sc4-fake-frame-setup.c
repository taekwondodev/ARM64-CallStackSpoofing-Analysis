typedef struct _FAKE_FRAME_DATA {
    void   *fakeFp;        // Spoofed frame pointer (x29)
    void   *fakeLr;        // Spoofed link register (x30)
    void   *fakeSp;        // Top of isolated stack
    DWORD64 reserved[5];
} FAKE_FRAME_DATA;

// Allocate 64 KB isolated stack
void *fakeStackBase = VirtualAlloc(NULL, DEFAULT_STACK_SIZE,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE);
void *fakeStackTop = (void *)((ULONG_PTR)fakeStackBase + DEFAULT_STACK_SIZE);

FAKE_FRAME_DATA fakeFrame = {
    .fakeFp = (void *)((ULONG_PTR)fakeStackTop - 0x100),
    .fakeLr = GetRandomGadget(&g_gadgetCache),
    .fakeSp = fakeStackTop
};

g_captureStack = FALSE;
DWORD64 result = ExecuteWithFakeFrame(SecretFunction, &fakeFrame,
                                      (LPVOID)0x44444444);
g_captureStack = TRUE;

VirtualFree(fakeStackBase, 0, MEM_RELEASE);
