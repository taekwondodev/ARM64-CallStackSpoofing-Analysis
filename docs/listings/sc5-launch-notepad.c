__declspec(noinline) BOOL WINAPI LaunchNotepad(LPVOID param)
{
    UNREFERENCED_PARAMETER(param);

    wchar_t cmd[] = L"C:\\Windows\\System32\\notepad.exe";
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};

    BOOL success = CreateProcessW(NULL, cmd, NULL, NULL,
                                  FALSE, 0, NULL, NULL, &si, &pi);
    if (success) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return success;
}

// Setup identico a Scenario 4: stesso ExecuteWithFakeFrame, target = LaunchNotepad
FAKE_FRAME_DATA fakeFrame = {
    .fakeFp = (void *)((ULONG_PTR)fakeStackTop - 0x100), // identico a Sc4
    .fakeLr = GetRandomGadget(&g_gadgetCache),
    .fakeSp = fakeStackTop
};

DWORD64 result = ExecuteWithFakeFrame(LaunchNotepad, &fakeFrame, NULL);
