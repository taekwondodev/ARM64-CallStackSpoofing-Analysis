// Scenario 2: Single-Frame Spoofing
// Un gadget ntdll e' passato a SpoofCallStack come LR falso.
void TestBasicSpoofing(void)
{
    void *spoofedReturnGadget = GetRandomGadget(&g_gadgetCache); // ntdll post-BL site
    void *realReturn = NULL;

    DWORD64 result = SpoofCallStack(
        SecretFunction,       // target
        spoofedReturnGadget,  // fake return address (ntdll gadget)
        (LPVOID)0x22222222,   // parametro dummy Sc2 (Sc1 usa 0x11111111)
        &realReturn);         // receives real LR for verification
}
