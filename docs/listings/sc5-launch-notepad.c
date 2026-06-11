// Setup identico a Scenario 4: stesso ExecuteWithFakeFrame, target = LaunchNotepad
FAKE_FRAME_DATA fakeFrame = {
    .fakeFp = (void *)((ULONG_PTR)fakeStackTop - 0x100), // identico a Sc4
    .fakeLr = GetRandomGadget(&g_gadgetCache),
    .fakeSp = fakeStackTop
};

DWORD64 result = ExecuteWithFakeFrame(LaunchNotepad, &fakeFrame, NULL);
