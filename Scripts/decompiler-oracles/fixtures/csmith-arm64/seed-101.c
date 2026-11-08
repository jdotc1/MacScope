// Options:   --seed 101 --max-funcs 3 --max-block-depth 2 --max-block-size 3 --max-expr-complexity 5 --max-array-len-per-dim 3 --concise --output Scripts/decompiler-oracles/fixtures/csmith-arm64/seed-101.c
#include "csmith.h"


static long __undefined;



static volatile int32_t g_2 = 0L;
static int32_t g_3 = 2L;
static volatile int32_t g_6[2][2] = {{0xBF0B96CAL,0xBF0B96CAL},{0xBF0B96CAL,0xBF0B96CAL}};
static int32_t g_7[3] = {0x2443250EL,0x2443250EL,0x2443250EL};
static int32_t * volatile g_29 = (void*)0;
static int32_t g_31 = (-1L);
static int32_t * volatile g_30 = &g_31;
static int32_t * volatile g_38[1] = {&g_31};
static uint32_t *g_57[1] = {(void*)0};
static uint32_t g_60 = 4294967294UL;
static uint32_t *g_59 = &g_60;
static int32_t * volatile g_64 = &g_7[2];



static int32_t  func_1(void);
static int32_t * func_10(int32_t * p_11, int32_t * const  p_12);
static int32_t * func_14(int32_t * p_15, uint8_t  p_16, int32_t * const  p_17);




static int32_t  func_1(void)
{ 
    uint16_t l_42 = 0xD8F3L;
    uint32_t l_63 = 0x55EF1C8DL;
    for (g_3 = 0; (g_3 >= (-21)); g_3 = safe_sub_func_uint64_t_u_u(g_3, 1))
    { 
        int64_t l_41 = 0x273426AE69ED994ALL;
        for (g_7[1] = 0; (g_7[1] >= (-2)); --g_7[1])
        { 
            int32_t *l_13 = &g_7[0];
            int32_t *l_19 = &g_7[1];
            int32_t **l_18 = &l_19;
            int32_t *l_43 = &g_31;
            (*l_18) = func_10((g_7[1] , (g_7[1] , l_13)), func_14(((*l_18) = (void*)0), g_7[1], &g_7[1]));
            (*l_43) &= (l_41 || (l_42 | ((void*)0 == g_30)));
            (*l_43) = (+(safe_lshift_func_uint16_t_u_s(l_42, 2)));
        }
    }
    for (g_3 = (-25); (g_3 == (-4)); g_3 = safe_add_func_uint8_t_u_u(g_3, 3))
    { 
        if (l_42)
            break;
    }
    for (g_3 = (-19); (g_3 != 14); g_3++)
    { 
        uint32_t **l_58 = &g_57[0];
        int32_t l_62 = 0x066FA41DL;
        (*g_64) = (safe_mod_func_int32_t_s_s((safe_sub_func_int16_t_s_s((safe_add_func_uint64_t_u_u((((g_59 = ((*l_58) = g_57[0])) == &g_60) , (((~0xFCF62392L) < (l_42 , g_6[1][1])) , l_42)), l_42)), l_62)), l_63));
    }
    return l_63;
}



static int32_t * func_10(int32_t * p_11, int32_t * const  p_12)
{ 
    uint32_t l_25 = 4294967292UL;
    int16_t l_28 = 0xF885L;
    uint32_t *l_36 = (void*)0;
    int32_t l_37[1][1][3];
    int32_t *l_39 = &g_31;
    int32_t *l_40 = &l_37[0][0][2];
    int i, j, k;
    for (i = 0; i < 1; i++)
    {
        for (j = 0; j < 1; j++)
        {
            for (k = 0; k < 3; k++)
                l_37[i][j][k] = 0xD015B01DL;
        }
    }
    (*g_30) = (safe_div_func_uint16_t_u_u((safe_lshift_func_int16_t_s_s((l_25 >= (((safe_div_func_int8_t_s_s(((l_25 <= g_6[0][1]) > (((0xACL != l_25) , (void*)0) != (void*)0)), l_25)) | g_7[1]) >= l_28)), 13)), 65534UL));
    (*l_39) = (safe_div_func_int64_t_s_s((((l_37[0][0][2] = l_25) | ((l_25 , l_36) != &g_31)) >= l_25), 0x82F744ED25E42506LL));
    (*l_39) = (g_6[1][0] || (l_40 == (void*)0));
    return p_11;
}



static int32_t * func_14(int32_t * p_15, uint8_t  p_16, int32_t * const  p_17)
{ 
    int32_t *l_20 = (void*)0;
    g_6[0][1] ^= (*p_17);
    return l_20;
}





int main (int argc, char* argv[])
{
    int i, j;
    int print_hash_value = 0;
    if (argc == 2 && strcmp(argv[1], "1") == 0) print_hash_value = 1;
    platform_main_begin();
    crc32_gentab();
    func_1();
    transparent_crc(g_2, "g_2", print_hash_value);
    transparent_crc(g_3, "g_3", print_hash_value);
    for (i = 0; i < 2; i++)
    {
        for (j = 0; j < 2; j++)
        {
            transparent_crc(g_6[i][j], "g_6[i][j]", print_hash_value);
            if (print_hash_value) printf("index = [%d][%d]\n", i, j);

        }
    }
    for (i = 0; i < 3; i++)
    {
        transparent_crc(g_7[i], "g_7[i]", print_hash_value);
        if (print_hash_value) printf("index = [%d]\n", i);

    }
    transparent_crc(g_31, "g_31", print_hash_value);
    transparent_crc(g_60, "g_60", print_hash_value);
    platform_main_end(crc32_context ^ 0xFFFFFFFFUL, print_hash_value);
    return 0;
}
