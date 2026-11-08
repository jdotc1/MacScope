// Options:   --seed 202 --max-funcs 3 --max-block-depth 2 --max-block-size 3 --max-expr-complexity 5 --max-array-len-per-dim 3 --concise --output Scripts/decompiler-oracles/fixtures/csmith-arm64/seed-202.c
#include "csmith.h"


static long __undefined;


struct S0 {
   const signed f0 : 19;
   volatile signed f1 : 28;
   unsigned f2 : 14;
   unsigned f3 : 2;
   volatile unsigned f4 : 9;
   volatile signed f5 : 28;
   volatile unsigned f6 : 10;
   const signed f7 : 23;
};

#pragma pack(push)
#pragma pack(1)
struct S1 {
   unsigned f0 : 14;
   const uint16_t  f1;
   const volatile unsigned f2 : 9;
   unsigned f3 : 27;
   volatile signed : 0;
   signed f4 : 14;
};
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
struct S2 {
   volatile signed f0 : 5;
   volatile signed f1 : 2;
   unsigned f2 : 25;
   volatile unsigned f3 : 25;
   const volatile unsigned f4 : 28;
};
#pragma pack(pop)

union U3 {
   uint16_t  f0;
   unsigned f1 : 17;
   int16_t  f2;
   int32_t  f3;
};


static int32_t g_5[3][2] = {{0x13E13A6CL,1L},{1L,0x13E13A6CL},{1L,1L}};
static int32_t g_6 = 0xFBCE008FL;
static int32_t g_9 = 0xD40A1650L;
static uint8_t g_32 = 255UL;
static int32_t g_44 = (-1L);
static int32_t *** volatile g_45 = (void*)0;
static int32_t *** volatile g_46 = (void*)0;
static int32_t **g_48 = (void*)0;
static int32_t *** volatile g_47 = &g_48;
static struct S0 g_58 = {-595,12459,76,0,3,-6369,7,1292};
static struct S2 g_62[3] = {{4,-0,4143,1163,7922},{4,-0,4143,1163,7922},{4,-0,4143,1163,7922}};
static struct S2 *g_61 = &g_62[2];
static struct S2 ** const  volatile g_60 = &g_61;
static int32_t * volatile g_63 = &g_9;
static union U3 g_67 = {65533UL};
static const uint8_t g_79 = 7UL;
static int16_t g_82 = 0x2164L;
static struct S1 g_91 = {111,0x2C85L,7,10954,-63};
static int32_t *g_92 = &g_9;
static uint8_t *g_100[3][2] = {{&g_32,&g_32},{&g_32,&g_32},{&g_32,&g_32}};
static uint8_t **g_99 = &g_100[0][1];



static uint8_t  func_1(void);
static int32_t * func_2(int32_t * p_3);
static uint64_t  func_26(uint8_t  p_27, uint16_t  p_28, int32_t * p_29, int32_t ** p_30);




static uint8_t  func_1(void)
{ 
    int32_t *l_4 = &g_5[0][0];
    int32_t **l_93 = &l_4;
    uint8_t **l_98[1][2][1];
    int i, j, k;
    for (i = 0; i < 1; i++)
    {
        for (j = 0; j < 2; j++)
        {
            for (k = 0; k < 1; k++)
                l_98[i][j][k] = (void*)0;
        }
    }
    (*l_93) = func_2(l_4);
    (*l_4) = (((safe_add_func_uint64_t_u_u(((void*)0 != &g_92), (safe_sub_func_int8_t_s_s(((l_98[0][1][0] = l_98[0][1][0]) != g_99), g_5[0][0])))) , (*l_4)) , (**l_93));
    return (**l_93);
}



static int32_t * func_2(int32_t * p_3)
{ 
    int32_t l_12 = 0L;
    int32_t l_14 = 0x7778E10AL;
    int32_t l_16 = (-6L);
    int32_t l_17 = (-4L);
    int32_t l_20[3];
    int32_t *l_36 = (void*)0;
    int32_t **l_35 = &l_36;
    uint64_t l_49[2][3][2] = {{{0xAC514D69EA850200LL,0x90203C69C835A82DLL},{0x0B10B9BD427A37A7LL,0xAC514D69EA850200LL},{0UL,0UL}},{{0UL,0xAC514D69EA850200LL},{0x0B10B9BD427A37A7LL,0x90203C69C835A82DLL},{0xAC514D69EA850200LL,0x90203C69C835A82DLL}}};
    int i, j, k;
    for (i = 0; i < 3; i++)
        l_20[i] = 0xDBD7CCF7L;
    for (g_6 = 0; (g_6 <= 26); g_6 = safe_add_func_int16_t_s_s(g_6, 8))
    { 
        int64_t l_13[2][2] = {{(-8L),(-8L)},{(-8L),(-8L)}};
        int32_t l_15 = 0xFA3C9E4AL;
        int32_t l_18 = 1L;
        int32_t l_19[3][2][3];
        uint64_t l_21 = 18446744073709551607UL;
        uint8_t *l_76 = &g_32;
        int32_t l_84[3];
        int i, j, k;
        for (i = 0; i < 3; i++)
        {
            for (j = 0; j < 2; j++)
            {
                for (k = 0; k < 3; k++)
                    l_19[i][j][k] = 0xFF510212L;
            }
        }
        for (i = 0; i < 3; i++)
            l_84[i] = 0x8E352C4DL;
        for (g_9 = 1; (g_9 >= 0); g_9 -= 1)
        { 
            int32_t *l_10 = (void*)0;
            int32_t *l_11[3][3] = {{&g_5[(g_9 + 1)][g_9],&g_5[(g_9 + 1)][g_9],&g_5[(g_9 + 1)][g_9]},{&g_5[(g_9 + 1)][g_9],&g_5[(g_9 + 1)][g_9],&g_5[(g_9 + 1)][g_9]},{&g_5[(g_9 + 1)][g_9],&g_5[(g_9 + 1)][g_9],&g_5[(g_9 + 1)][g_9]}};
            uint8_t *l_31[1];
            int i, j;
            for (i = 0; i < 1; i++)
                l_31[i] = &g_32;
            l_21--;
            (*g_47) = (((safe_add_func_int8_t_s_s((func_26((--g_32), g_5[(g_9 + 1)][g_9], &g_5[0][0], l_35) > 0xF98811FBA6500C24LL), g_6)) , l_19[0][1][2]) , &p_3);
            ++l_49[0][1][0];
        }
        if ((safe_mod_func_int16_t_s_s(l_21, (1L ^ (safe_add_func_uint8_t_u_u((safe_rshift_func_uint8_t_u_s((g_58 , g_58.f7), g_9)), l_49[0][1][0]))))))
        { 
            struct S2 *l_59 = (void*)0;
            (*g_60) = l_59;
            if ((*p_3))
                continue;
            return p_3;
        }
        else
        { 
            int32_t l_66[2];
            const uint8_t *l_78 = &g_79;
            const uint8_t **l_77 = &l_78;
            int16_t *l_80 = &g_67.f2;
            int16_t *l_81 = &g_82;
            int32_t l_83[2];
            int i;
            for (i = 0; i < 2; i++)
                l_66[i] = 0L;
            for (i = 0; i < 2; i++)
                l_83[i] = 6L;
            (*g_63) = (l_21 <= ((*p_3) = (*p_3)));
            (*p_3) = (((safe_add_func_uint16_t_u_u((l_66[0] = l_13[0][1]), (((g_67 , (safe_div_func_uint32_t_u_u((safe_mul_func_uint8_t_u_u(((safe_sub_func_uint64_t_u_u((((*l_81) = ((*l_80) |= ((safe_div_func_uint8_t_u_u((l_76 != ((*l_77) = (void*)0)), g_58.f3)) < g_44))) != l_19[0][1][2]), l_83[0])) ^ g_62[2].f4), g_44)), (*p_3)))) ^ l_84[2]) , g_5[0][0]))) == g_9) & g_58.f2);
            (*p_3) = (-9L);
        }
        for (g_67.f2 = 0; (g_67.f2 <= 1); g_67.f2 += 1)
        { 
            int i, j;
            l_84[2] = (g_5[(g_67.f2 + 1)][g_67.f2] = (safe_mul_func_int8_t_s_s((safe_mod_func_int64_t_s_s((safe_lshift_func_int16_t_s_s(l_20[(g_67.f2 + 1)], 0)), l_20[(g_67.f2 + 1)])), (g_91 , 0x5CL))));
        }
    }
    return g_92;
}



static uint64_t  func_26(uint8_t  p_27, uint16_t  p_28, int32_t * p_29, int32_t ** p_30)
{ 
    const int32_t l_39 = 0x41E233C2L;
    int16_t l_42 = (-3L);
    int32_t *l_43[3];
    int i;
    for (i = 0; i < 3; i++)
        l_43[i] = &g_44;
    g_44 |= ((g_9 >= (safe_sub_func_uint64_t_u_u((((((l_39 | 0x9CL) < (safe_mod_func_int64_t_s_s((-5L), 0x706CD8FDA5E0CF2FLL))) && g_5[1][1]) != l_42) < 0x2EB5F757037A9E21LL), 9UL))) , (*p_29));
    (*p_29) = (-8L);
    return g_5[0][0];
}





int main (int argc, char* argv[])
{
    int i, j;
    int print_hash_value = 0;
    if (argc == 2 && strcmp(argv[1], "1") == 0) print_hash_value = 1;
    platform_main_begin();
    crc32_gentab();
    func_1();
    for (i = 0; i < 3; i++)
    {
        for (j = 0; j < 2; j++)
        {
            transparent_crc(g_5[i][j], "g_5[i][j]", print_hash_value);
            if (print_hash_value) printf("index = [%d][%d]\n", i, j);

        }
    }
    transparent_crc(g_6, "g_6", print_hash_value);
    transparent_crc(g_9, "g_9", print_hash_value);
    transparent_crc(g_32, "g_32", print_hash_value);
    transparent_crc(g_44, "g_44", print_hash_value);
    transparent_crc(g_58.f0, "g_58.f0", print_hash_value);
    transparent_crc(g_58.f1, "g_58.f1", print_hash_value);
    transparent_crc(g_58.f2, "g_58.f2", print_hash_value);
    transparent_crc(g_58.f3, "g_58.f3", print_hash_value);
    transparent_crc(g_58.f4, "g_58.f4", print_hash_value);
    transparent_crc(g_58.f5, "g_58.f5", print_hash_value);
    transparent_crc(g_58.f6, "g_58.f6", print_hash_value);
    transparent_crc(g_58.f7, "g_58.f7", print_hash_value);
    for (i = 0; i < 3; i++)
    {
        transparent_crc(g_62[i].f0, "g_62[i].f0", print_hash_value);
        transparent_crc(g_62[i].f1, "g_62[i].f1", print_hash_value);
        transparent_crc(g_62[i].f2, "g_62[i].f2", print_hash_value);
        transparent_crc(g_62[i].f3, "g_62[i].f3", print_hash_value);
        transparent_crc(g_62[i].f4, "g_62[i].f4", print_hash_value);
        if (print_hash_value) printf("index = [%d]\n", i);

    }
    transparent_crc(g_67.f0, "g_67.f0", print_hash_value);
    transparent_crc(g_67.f2, "g_67.f2", print_hash_value);
    transparent_crc(g_79, "g_79", print_hash_value);
    transparent_crc(g_82, "g_82", print_hash_value);
    transparent_crc(g_91.f0, "g_91.f0", print_hash_value);
    transparent_crc(g_91.f1, "g_91.f1", print_hash_value);
    transparent_crc(g_91.f2, "g_91.f2", print_hash_value);
    transparent_crc(g_91.f3, "g_91.f3", print_hash_value);
    transparent_crc(g_91.f4, "g_91.f4", print_hash_value);
    platform_main_end(crc32_context ^ 0xFFFFFFFFUL, print_hash_value);
    return 0;
}
