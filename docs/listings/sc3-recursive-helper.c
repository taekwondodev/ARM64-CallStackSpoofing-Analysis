typedef struct _RECURSIVE_SPOOF_CONTEXT {
    void    *targetFunc;
    void    *parameter;
    void   **spoofChain;
    DWORD    currentDepth;
    DWORD    maxDepth;
    DWORD64  result;
} RECURSIVE_SPOOF_CONTEXT;

__declspec(noinline) static void RecursiveSpoofHelper(RECURSIVE_SPOOF_CONTEXT *ctx)
{
    if (ctx->currentDepth >= ctx->maxDepth) {
        typedef DWORD(WINAPI *TargetFunc)(LPVOID);
        TargetFunc target = (TargetFunc)ctx->targetFunc;
        ctx->result = target(ctx->parameter);
        return;
    }

    void *spoofedReturn = ctx->spoofChain[ctx->currentDepth];
    void *realReturn    = NULL;

    ctx->currentDepth++;

    SpoofCallStack(
        (void *)RecursiveSpoofHelper,
        spoofedReturn,
        ctx,
        &realReturn
    );
}
