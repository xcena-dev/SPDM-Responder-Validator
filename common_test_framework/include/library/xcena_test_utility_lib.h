/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF, Componolit. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __XCENA_TEST_UTILITY_LIB_H__
#define __XCENA_TEST_UTILITY_LIB_H__

#include "library/common_test_utility_lib.h"

void xcena_test_record_test_assertion_custom_set(common_test_group_id group_id,
                                                 common_test_case_id case_id);

void xcena_test_record_test_assertion_custom_print(common_test_result_t test_result,
                                                    const char *message_format,
                                                    ...);

void xcena_test_record_test_message_custom(const char *message_format, ...);

#endif
