#include <stdio.h>
#include <stddef.h>
#include "Zend/zend.h"
#include "Zend/zend_API.h"
#include "Zend/zend_compile.h"
int main(void) {
    printf("FCI_size %zu\n", sizeof(zend_fcall_info));
    printf("FCI_function_name %zu\n", offsetof(zend_fcall_info, function_name));
    printf("FCI_function_val %zu\n", offsetof(zend_fcall_info, function_name) + offsetof(zval, value));
    printf("FCI_function_type %zu\n", offsetof(zend_fcall_info, function_name) + offsetof(zval, u1.type_info));
    printf("FCI_param_count %zu\n", offsetof(zend_fcall_info, param_count));
    printf("FCI_params %zu\n", offsetof(zend_fcall_info, params));
    printf("IF_type %zu\n", offsetof(zend_internal_function, type));
    printf("IF_handler %zu\n", offsetof(zend_internal_function, handler));
    printf("IF_size %zu\n", sizeof(zend_internal_function));
    printf("ZVAL_size %zu\n", sizeof(zval));
    printf("HT_size %zu\n", sizeof(HashTable));
    return 0;
}
