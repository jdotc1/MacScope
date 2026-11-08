#include <QBDI.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern uint64_t qbdi_trace_target(uint64_t, uint64_t, uint64_t);
extern const char qbdi_trace_target_end[];

typedef struct {
    rword start;
    unsigned pre_count;
    unsigned post_count;
    rword before0, before1, before2, before_flags;
    rword after0, after1, after2, after_flags;
    char instruction[128];
} Trace;

static VMAction before(VMInstanceRef vm, GPRState *gpr, FPRState *fpr, void *data) {
    (void)fpr;
    Trace *t = data;
    const InstAnalysis *analysis = qbdi_getInstAnalysis(vm, QBDI_ANALYSIS_INSTRUCTION | QBDI_ANALYSIS_DISASSEMBLY);
    if (analysis && analysis->address == t->start) {
        t->pre_count++;
        t->before0 = gpr->x0; t->before1 = gpr->x1; t->before2 = gpr->x2; t->before_flags = gpr->nzcv;
        snprintf(t->instruction, sizeof(t->instruction), "%s", analysis->disassembly);
    }
    return QBDI_CONTINUE;
}

static VMAction after(VMInstanceRef vm, GPRState *gpr, FPRState *fpr, void *data) {
    (void)fpr;
    Trace *t = data;
    const InstAnalysis *analysis = qbdi_getInstAnalysis(vm, QBDI_ANALYSIS_INSTRUCTION);
    if (analysis && analysis->address == t->start) {
        t->post_count++;
        t->after0 = gpr->x0; t->after1 = gpr->x1; t->after2 = gpr->x2; t->after_flags = gpr->nzcv;
    }
    return QBDI_CONTINUE;
}

int main(void) {
    VMInstanceRef vm = NULL;
    qbdi_initVM(&vm, NULL, NULL, 0);
    if (!vm) { fputs("VM initialization failed\n", stderr); return 1; }
    GPRState *state = qbdi_getGPRState(vm);
    uint8_t *stack = NULL;
    if (!state || !qbdi_allocateVirtualStack(state, 65536, &stack)) {
        fputs("stack allocation failed\n", stderr); qbdi_terminateVM(vm); return 1;
    }
    state->nzcv = 0;
    Trace trace = {.start = (rword)qbdi_trace_target};
    qbdi_addInstrumentedRange(vm, trace.start, (rword)qbdi_trace_target_end);
    if (qbdi_addCodeCB(vm, QBDI_PREINST, before, &trace, 0) == QBDI_INVALID_EVENTID ||
        qbdi_addCodeCB(vm, QBDI_POSTINST, after, &trace, 0) == QBDI_INVALID_EVENTID) {
        fputs("callback registration failed\n", stderr); qbdi_alignedFree(stack); qbdi_terminateVM(vm); return 1;
    }
    const rword args[] = {UINT64_C(0xfeedfacefeedface), 0, UINT64_MAX};
    rword result = 0;
    bool ok = qbdi_callA(vm, &result, trace.start, 3, args);
    printf("QBDI %s, oracle v000001, instruction 0x0b020020\n", qbdi_getVersion(NULL));
    printf("Instruction: %s\n", trace.instruction);
    printf("Before: x0=0x%016" PRIx64 " x1=0x%016" PRIx64 " x2=0x%016" PRIx64 " nzcv=0x%08" PRIx64 "\n", (uint64_t)trace.before0, (uint64_t)trace.before1, (uint64_t)trace.before2, (uint64_t)trace.before_flags);
    printf("After:  x0=0x%016" PRIx64 " x1=0x%016" PRIx64 " x2=0x%016" PRIx64 " nzcv=0x%08" PRIx64 "\n", (uint64_t)trace.after0, (uint64_t)trace.after1, (uint64_t)trace.after2, (uint64_t)trace.after_flags);
    printf("Callback counts: pre=%u post=%u; function result=0x%016" PRIx64 "\n", trace.pre_count, trace.post_count, (uint64_t)result);
    int pass = ok && trace.pre_count == 1 && trace.post_count == 1 &&
        trace.before0 == args[0] && trace.before1 == args[1] && trace.before2 == args[2] &&
        trace.after0 == UINT64_C(0xffffffff) && trace.after1 == args[1] && trace.after2 == args[2] &&
        (trace.before_flags & UINT64_C(0xf0000000)) == (trace.after_flags & UINT64_C(0xf0000000)) &&
        result == UINT64_C(0xffffffff);
    qbdi_alignedFree(stack);
    qbdi_terminateVM(vm);
    puts(pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
