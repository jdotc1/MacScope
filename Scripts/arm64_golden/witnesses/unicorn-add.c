#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <unicorn/unicorn.h>

#define CHECK(expr) do { uc_err error = (expr); if (error != UC_ERR_OK) { \
    fprintf(stderr, "%s: %s\n", #expr, uc_strerror(error)); return 1; } } while (0)

int main(void) {
    uc_engine *engine = NULL;
    const uint64_t pc = 0x400100;
    const uint8_t code[4] = {0x20, 0x00, 0x02, 0x0b};
    uint64_t x0 = UINT64_C(0xfeedfacefeedface);
    uint64_t x1 = 0;
    uint64_t x2 = UINT64_MAX;
    uint32_t nzcv = 0;
    unsigned int major = 0, minor = 0;
    uc_version(&major, &minor);
    CHECK(uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &engine));
    CHECK(uc_mem_map(engine, 0x400000, 0x1000, UC_PROT_ALL));
    CHECK(uc_mem_write(engine, pc, code, sizeof(code)));
    CHECK(uc_reg_write(engine, UC_ARM64_REG_X0, &x0));
    CHECK(uc_reg_write(engine, UC_ARM64_REG_X1, &x1));
    CHECK(uc_reg_write(engine, UC_ARM64_REG_X2, &x2));
    CHECK(uc_reg_write(engine, UC_ARM64_REG_NZCV, &nzcv));
    CHECK(uc_emu_start(engine, pc, pc + 4, 0, 1));
    CHECK(uc_reg_read(engine, UC_ARM64_REG_X0, &x0));
    CHECK(uc_reg_read(engine, UC_ARM64_REG_X1, &x1));
    CHECK(uc_reg_read(engine, UC_ARM64_REG_X2, &x2));
    CHECK(uc_reg_read(engine, UC_ARM64_REG_NZCV, &nzcv));
    CHECK(uc_close(engine));
    printf("Unicorn %u.%u; MacScope oracle v000001; instruction 0x0b020020\n", major, minor);
    printf("X0=0x%016" PRIx64 " X1=0x%016" PRIx64 " X2=0x%016" PRIx64 " NZCV=0x%08" PRIx32 "\n", x0, x1, x2, nzcv);
    if (x0 != UINT64_C(0x00000000ffffffff) || x1 != 0 || x2 != UINT64_MAX || (nzcv & 0xf0000000U) != 0) {
        fputs("witness mismatch\n", stderr);
        return 1;
    }
    puts("PASS: result and checked unchanged registers/flags match the existing fixture");
    return 0;
}
