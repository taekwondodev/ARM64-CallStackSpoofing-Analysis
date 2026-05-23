// TestNormalExecution -- inlined into main() by MSVC /O2
void TestNormalExecution(void)
{
    // ...
    DWORD result = SecretFunction((LPVOID)0x11111111);
    // ...
}

// Target function declared noinline -- always has its own frame
__declspec(noinline) DWORD WINAPI SecretFunction(LPVOID param)
{
    DWORD value = (DWORD)(ULONG_PTR)param;
    // CaptureStackBackTrace called here to show the call chain
    void *backtrace[12];
    USHORT frames = CaptureStackBackTrace(0, 12, backtrace, NULL);
    // ...
    g_secretValue = value ^ 0xDEADBEEF;
    return g_secretValue;
}
