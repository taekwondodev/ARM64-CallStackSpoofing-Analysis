// Scenario 2: Single-Frame Spoofing
// Gadget discovery: scan ntdll .text for BL instructions,
// cache the address immediately after each BL (valid return sites).
BOOL CacheCallSites(const char *moduleName, GADGET_CACHE *cache) { /* ... */ }

void TestBasicSpoofing(void)
{
    void *spoofedReturnGadget = GetRandomGadget(&g_gadgetCache); // ntdll post-BL site
    void *realReturn = NULL;

    DWORD64 result = SpoofCallStack(
        SecretFunction,       // target
        spoofedReturnGadget,  // fake return address (ntdll gadget)
        (LPVOID)0x22222222,   // parameter
        &realReturn);         // receives real LR for verification
}
