/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "library/xcena_test_utility_lib.h"
#include "stdio.h"

typedef struct {
    uint32_t case_id;
    uint32_t total_pass;
    uint32_t total_fail;
} common_test_case_result_t;

typedef struct {
    uint32_t group_id;
    uint32_t total_pass;
    uint32_t total_fail;
    common_test_case_result_t   *test_case_results;
} common_test_group_result_t;

typedef struct {
    uint32_t total_pass;
    uint32_t total_fail;
    common_test_group_result_t  *test_group_results;
} common_test_suite_result_t;

#define COMMON_TEST_MAX_MESSAGE_LENGTH 0x800

extern FILE *m_log_file;
extern common_test_suite_result_t *m_test_suite_result;

static common_test_group_id s_group_id;
static common_test_case_id s_case_id;
static common_test_assertion_id s_assertion_id;

static char *xcena_test_result_to_string (common_test_result_t test_result)
{
    switch (test_result) {
    case COMMON_TEST_RESULT_NOT_TESTED:
        return "NOT_TESTED";
    case COMMON_TEST_RESULT_PASS:
        return "PASS";
    case COMMON_TEST_RESULT_FAIL:
        return "FAIL";
    default:
        assert (0);
        return "<UNKNOWN>";
    }
}

static void xcena_test_record_test_suite_result (
    common_test_group_id group_id,
    common_test_case_id case_id,
    common_test_result_t test_result,
    common_test_suite_result_t *test_suite_result)
{
    uint32_t group_index;
    uint32_t case_index;
    common_test_group_result_t *test_group_result;
    common_test_case_result_t *test_case_result;

    if (test_result == COMMON_TEST_RESULT_PASS) {
        test_suite_result->total_pass++;
    } else if (test_result == COMMON_TEST_RESULT_FAIL) {
        test_suite_result->total_fail++;
    }

    for (group_index = 0; ; group_index++) {
        test_group_result = &test_suite_result->test_group_results[group_index];
        if (test_group_result->group_id == COMMON_TEST_ID_END) {
            break;
        }
        if (test_group_result->group_id == group_id) {
            if (test_result == COMMON_TEST_RESULT_PASS) {
                test_group_result->total_pass++;
            } else if (test_result == COMMON_TEST_RESULT_FAIL) {
                test_group_result->total_fail++;
            }
            for (case_index = 0; ; case_index++) {
                test_case_result = &test_group_result->test_case_results[case_index];
                if (test_case_result->case_id == COMMON_TEST_ID_END) {
                    break;
                }
                if (test_case_result->case_id == case_id) {
                    if (test_result == COMMON_TEST_RESULT_PASS) {
                        test_case_result->total_pass++;
                    } else if (test_result == COMMON_TEST_RESULT_FAIL) {
                        test_case_result->total_fail++;
                    }
                    break;
                }
            }
            break;
        }
    }
}

void xcena_test_record_test_assertion_custom_set(common_test_group_id group_id,
                                                 common_test_case_id case_id)
{
    s_group_id = group_id;
    s_case_id = case_id;
    s_assertion_id = 0;
}

void xcena_test_record_test_assertion_custom_print(
    common_test_result_t test_result,
    const char *message_format,
    ...)
{
    char buffer[COMMON_TEST_MAX_MESSAGE_LENGTH];
    va_list marker;

    fprintf(m_log_file,
            "    test assertion %d.%d.%d - %s",
            s_group_id, s_case_id, s_assertion_id++,
            xcena_test_result_to_string (test_result)
            );

    if (message_format != NULL) {
        va_start(marker, message_format);

        vsnprintf(buffer, sizeof(buffer), message_format, marker);

        va_end(marker);

        fprintf(m_log_file, " %s", buffer);
    }
    fprintf(m_log_file, "\n");
    fflush(m_log_file);

    xcena_test_record_test_suite_result (s_group_id, s_case_id, test_result, m_test_suite_result);
}

void xcena_test_record_test_message_custom(const char *message_format, ...)
{
    char buffer[COMMON_TEST_MAX_MESSAGE_LENGTH];
    va_list marker;

    va_start(marker, message_format);

    vsnprintf(buffer, sizeof(buffer), message_format, marker);

    va_end(marker);

    fprintf(m_log_file, "%s", buffer);
    fflush(m_log_file);
}