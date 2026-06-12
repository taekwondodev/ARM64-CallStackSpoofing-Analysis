// Sc3 estende Sc2: Sc2 inserisce un solo frame ntdll.
// Qui 2 livelli di ricorsione chiamano ciascuno SpoofCallStack,
// producendo 2 frame reali di RecursiveSpoofHelper con LR falsificato.
// Al caso base, anche la chiamata al target passa per SpoofCallStack:
// spoofChain ha 3 slot (indici 0..maxDepth), l'ultimo per il caso base.
// CaptureStackBackTrace vede: target, gadget[2], Helper+0x30, gadget[1], Helper+0x64, gadget[0], Helper+0x64, CRT
// -- frame[01] e' un gadget ntdll; firma residua: Helper+0x0030 al frame[02].

typedef struct _RECURSIVE_SPOOF_CONTEXT {
    void    *targetFunc;   // funzione da chiamare al caso base
    void    *parameter;
    void   **spoofChain;   // gadget ntdll: indici 0..maxDepth (maxDepth+1 slot)
    DWORD    currentDepth;
    DWORD    maxDepth;     // 2 in questo scenario
    DWORD64  result;
} RECURSIVE_SPOOF_CONTEXT;

__declspec(noinline) static void RecursiveSpoofHelper(RECURSIVE_SPOOF_CONTEXT *ctx)
{
    if (ctx->currentDepth >= ctx->maxDepth) {
        // caso base: anche qui LR e' falsificato con spoofChain[maxDepth].
        // InjectExplorer vedra' un gadget ntdll al frame[01], non questo Helper.
        void *baseGadget = ctx->spoofChain[ctx->currentDepth];
        ctx->result = SpoofCallStack(ctx->targetFunc, baseGadget, ctx->parameter, NULL);
        return;
    }

    void *spoofedReturn = ctx->spoofChain[ctx->currentDepth]; // gadget per questo livello
    void *realReturn    = NULL;

    ctx->currentDepth++;

    // SpoofCallStack(RecursiveSpoofHelper, gadget, ctx):
    // crea un frame reale di RecursiveSpoofHelper con LR = gadget,
    // poi richiama RecursiveSpoofHelper al livello successivo.
    SpoofCallStack(
        (void *)RecursiveSpoofHelper,
        spoofedReturn,
        ctx,
        &realReturn
    );
}
