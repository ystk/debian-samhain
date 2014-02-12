

/* This is auto-generated code. Edit at your own peril. */

#include "config.h"
#include <stdio.h>
#include "CuTest.h"

extern void Test_quote_string_ok (CuTest*);
extern void Test_unquote_string_ok (CuTest*);
extern void Test_csv_escape_ok (CuTest*);
extern void Test_tiger(CuTest*);
extern void Test_tiger_file(CuTest*);
extern void Test_tiger_file_with_length(CuTest*);
extern void Test_sh_tools_safe_name_01(CuTest*);
extern void Test_sh_tools_safe_name_02(CuTest*);
extern void Test_sh_tools_safe_name_03(CuTest*);
extern void Test_sh_tools_safe_name_04(CuTest*);
extern void Test_sh_tools_safe_name_05(CuTest*);
extern void Test_sh_tools_safe_name_06(CuTest*);
extern void Test_sh_tools_safe_name_07(CuTest*);
extern void Test_is_numeric_01(CuTest*);
extern void Test_dnmalloc (CuTest*);
extern void Test_sh_unix_lookup_page (CuTest*);
extern void Test_sl_strlcpy (CuTest*);
extern void Test_sl_strlcat (CuTest*);
extern void Test_sh_util_acl_compact (CuTest*);
extern void Test_sh_util_strdup_ok (CuTest*);
extern void Test_sh_util_strconcat_ok (CuTest*);
extern void Test_sh_util_base64_enc_ok (CuTest*);
extern void Test_sh_util_dirname_ok (CuTest*);
extern void Test_sh_util_basename_ok (CuTest*);
extern void Test_sh_util_utf8_ok (CuTest*);
extern void Test_sh_util_obscure_ok (CuTest*);
extern void Test_sl_stale (CuTest*);
extern void Test_sl_snprintf (CuTest*);
extern void Test_sl_strcasecmp (CuTest*);
extern void Test_zAVLTree(CuTest*);
extern void Test_entropy (CuTest*);
extern void Test_file_dequote (CuTest*);
extern void Test_login (CuTest*);
extern void Test_login (CuTest*);
extern void Test_portcheck_lists (CuTest*);
extern void Test_processcheck_watchlist_ok (CuTest*);
extern void Test_processcheck_listhandle_ok (CuTest*);
extern void Test_restrict (CuTest*);
extern void Test_srp (CuTest*);
extern void Test_string (CuTest*);


int RunAllTests(void) 
{
    CuString *output = CuStringNew();
    CuSuite* suite = CuSuiteNew();


    SUITE_ADD_TEST(suite, Test_quote_string_ok );
    SUITE_ADD_TEST(suite, Test_unquote_string_ok );
    SUITE_ADD_TEST(suite, Test_csv_escape_ok );
    SUITE_ADD_TEST(suite, Test_tiger);
    SUITE_ADD_TEST(suite, Test_tiger_file);
    SUITE_ADD_TEST(suite, Test_tiger_file_with_length);
    SUITE_ADD_TEST(suite, Test_sh_tools_safe_name_01);
    SUITE_ADD_TEST(suite, Test_sh_tools_safe_name_02);
    SUITE_ADD_TEST(suite, Test_sh_tools_safe_name_03);
    SUITE_ADD_TEST(suite, Test_sh_tools_safe_name_04);
    SUITE_ADD_TEST(suite, Test_sh_tools_safe_name_05);
    SUITE_ADD_TEST(suite, Test_sh_tools_safe_name_06);
    SUITE_ADD_TEST(suite, Test_sh_tools_safe_name_07);
    SUITE_ADD_TEST(suite, Test_is_numeric_01);
    SUITE_ADD_TEST(suite, Test_dnmalloc );
    SUITE_ADD_TEST(suite, Test_sh_unix_lookup_page );
    SUITE_ADD_TEST(suite, Test_sl_strlcpy );
    SUITE_ADD_TEST(suite, Test_sl_strlcat );
    SUITE_ADD_TEST(suite, Test_sh_util_acl_compact );
    SUITE_ADD_TEST(suite, Test_sh_util_strdup_ok );
    SUITE_ADD_TEST(suite, Test_sh_util_strconcat_ok );
    SUITE_ADD_TEST(suite, Test_sh_util_base64_enc_ok );
    SUITE_ADD_TEST(suite, Test_sh_util_dirname_ok );
    SUITE_ADD_TEST(suite, Test_sh_util_basename_ok );
    SUITE_ADD_TEST(suite, Test_sh_util_utf8_ok );
    SUITE_ADD_TEST(suite, Test_sh_util_obscure_ok );
    SUITE_ADD_TEST(suite, Test_sl_stale );
    SUITE_ADD_TEST(suite, Test_sl_snprintf );
    SUITE_ADD_TEST(suite, Test_sl_strcasecmp );
    SUITE_ADD_TEST(suite, Test_zAVLTree);
    SUITE_ADD_TEST(suite, Test_entropy );
    SUITE_ADD_TEST(suite, Test_file_dequote );
    SUITE_ADD_TEST(suite, Test_login );
    SUITE_ADD_TEST(suite, Test_login );
    SUITE_ADD_TEST(suite, Test_portcheck_lists );
    SUITE_ADD_TEST(suite, Test_processcheck_watchlist_ok );
    SUITE_ADD_TEST(suite, Test_processcheck_listhandle_ok );
    SUITE_ADD_TEST(suite, Test_restrict );
    SUITE_ADD_TEST(suite, Test_srp );
    SUITE_ADD_TEST(suite, Test_string );

    CuSuiteRun(suite);
    CuSuiteSummary(suite, output);
    CuSuiteDetails(suite, output);
    if (suite->failCount > 0)
      fprintf(stderr, "%s%c", output->buffer, 0x0A);
    else
      fprintf(stdout, "%s%c", output->buffer, 0x0A);
    return suite->failCount;
}

int main(void)
{
#if !defined(USE_SYSTEM_MALLOC)
    typedef void assert_handler_tp(const char * error, const char *file, int line);
    extern assert_handler_tp *dnmalloc_set_handler(assert_handler_tp *new);
    extern void safe_fatal  (const char * details, const char *f, int l);
#endif
#if !defined(USE_SYSTEM_MALLOC) && defined(USE_MALLOC_LOCK)
    extern int dnmalloc_pthread_init(void);
    dnmalloc_pthread_init();
#endif
#if !defined(USE_SYSTEM_MALLOC)
    (void) dnmalloc_set_handler(safe_fatal);
#endif
    int retval;
    retval = RunAllTests();
    return (retval == 0) ? 0 : 1;
}

