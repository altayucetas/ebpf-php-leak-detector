#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_leak_test.h"

static void *module_memory = NULL;
static void *request_memory = NULL;

/* MINIT - Module initialization */
PHP_MINIT_FUNCTION(php_leak_test)
{
    php_printf("MINIT: Extension initiated...\n");
    
    module_memory = pemalloc(1024, 1);
    if (module_memory) {
        memset(module_memory, 0xAA, 1024);
        php_printf("MINIT: 1024 byte persistent memory allocated at %p\n", module_memory);
    }
    
    return SUCCESS;
}

/* MSHUTDOWN - Module shutdown */
PHP_MSHUTDOWN_FUNCTION(php_leak_test)
{
    php_printf("MSHUTDOWN: Extension shut down...\n");
    
    if (module_memory) {
        pefree(module_memory, 1);
        php_printf("MSHUTDOWN: Module memory freed from %p\n", module_memory);
        module_memory = NULL;
    }
    
    return SUCCESS;
}

/* RINIT - Request initialization */
PHP_RINIT_FUNCTION(php_leak_test)
{
    php_printf("RINIT: Request initiated...\n");
    
    request_memory = emalloc(512);
    if (request_memory) {
        memset(request_memory, 0xBB, 512);
        php_printf("RINIT: 512 byte request memory allocated at %p\n", request_memory);
    }
    
    return SUCCESS;
}

/* RSHUTDOWN - Request shutdown */
PHP_RSHUTDOWN_FUNCTION(php_leak_test)
{
    php_printf("RSHUTDOWN: Request shut down...\n");
    
    if (request_memory) {
        efree(request_memory);
        php_printf("RSHUTDOWN: Request memory freed from %p\n", request_memory);
        request_memory = NULL;
    }
    
    return SUCCESS;
}

void trigger_efree(void *ptr) {
    efree(ptr);
}

void trigger_pefree(void *ptr) {
    pefree(ptr, 1);
}

PHP_FUNCTION(trigger_emalloc)
{
    size_t emalloc_size = 100;
    void *emalloc_pointer = emalloc(emalloc_size);
    php_printf("[emalloc_test] emalloc is called with size: %zu, pointer: %p\n", emalloc_size, emalloc_pointer);

    //efree(emalloc_pointer);
    //php_printf("[emalloc_test] efree is called for pointer: %p\n", emalloc_pointer);
    //efree(emalloc_pointer);
    //trigger_efree(emalloc_pointer);
    //php_printf("[emalloc_test] efree is called again for pointer: %p\n", emalloc_pointer);

    RETURN_TRUE;
}

PHP_FUNCTION(trigger_pemalloc)
{
    size_t pesize = 100;
    void *pemalloc_pointer = pemalloc(pesize, 1);
    php_printf("[pemalloc_test] pemalloc is called with size: %zu, pointer: %p\n", pesize, pemalloc_pointer);

    //pefree(pemalloc_pointer, 1);
    //php_printf("[pemalloc_test] pefree is called for pointer: %p\n", pemalloc_pointer);
    //pefree(pemalloc_pointer, 1);
    //trigger_pefree(pemalloc_pointer);
    //php_printf("[pemalloc_test] pefree is called again for pointer: %p\n", pemalloc_pointer);

    RETURN_TRUE;
}

PHP_FUNCTION(trigger_erealloc) {
    size_t emalloc_size = 100;
    void *emalloc_pointer = emalloc(emalloc_size);
    php_printf("[erealloc_test] emalloc is called with size: %zu, pointer: %p\n", emalloc_size, emalloc_pointer);

    size_t new_size = 1500;
    void *realloc_pointer = erealloc(emalloc_pointer, new_size);
    php_printf("[erealloc_test] erealloc is called with new size: %zu, pointer: %p\n", new_size, realloc_pointer);

    //efree(realloc_pointer);
    //php_printf("[erealloc_test] efree is called for pointer: %p\n", realloc_pointer);
    //efree(realloc_pointer);
    //trigger_efree(realloc_pointer);
    //php_printf("[erealloc_test] efree is called again for pointer: %p\n", realloc_pointer);

    RETURN_TRUE;
}

PHP_FUNCTION(trigger_perealloc) {
    size_t pemalloc_size = 100;
    void *pemalloc_pointer = pemalloc(pemalloc_size, 1);
    php_printf("[perealloc_test] pemalloc is called with size: %zu, pointer: %p\n", pemalloc_size, pemalloc_pointer);

    size_t new_size = 1500;
    void *realloc_pointer = perealloc(pemalloc_pointer, new_size, 1);
    php_printf("[perealloc_test] perealloc is called with new size: %zu, pointer: %p\n", new_size, realloc_pointer);

    //pefree(realloc_pointer, 1);
    //php_printf("[perealloc_test] efree is called for pointer: %p\n", realloc_pointer);
    //pefree(realloc_pointer, 1);
    //trigger_pefree(realloc_pointer);
    //php_printf("[perealloc_test] efree is called again for pointer: %p\n", realloc_pointer);

    RETURN_TRUE;
}

PHP_FUNCTION(trigger_ecalloc)
{
    size_t ecalloc_size = 100;
    void *ecalloc_pointer = ecalloc(ecalloc_size, sizeof(int));
    php_printf("[ecalloc_test] ecalloc is called with size: %zu, pointer: %p\n", ecalloc_size * sizeof(int), ecalloc_pointer);

    //efree(ecalloc_pointer);
    //php_printf("[ecalloc_test] efree is called for pointer: %p\n", ecalloc_pointer);
    //efree(ecalloc_pointer);
    //trigger_efree(ecalloc_pointer);
    //php_printf("[ecalloc_test] efree is called again for pointer: %p\n", ecalloc_pointer);

    RETURN_TRUE;
}

PHP_FUNCTION(trigger_pecalloc)
{
    size_t pecalloc_size = 100;
    void *pecalloc_pointer = pecalloc(pecalloc_size, sizeof(int), 1);
    php_printf("[pecalloc_test] pecalloc is called with size: %zu, pointer: %p\n", pecalloc_size * sizeof(int), pecalloc_pointer);

    //pefree(pecalloc_pointer, 1);
    //php_printf("[pecalloc_test] efree is called for pointer: %p\n", pecalloc_pointer);
    //pefree(pecalloc_pointer, 1);
    //trigger_pefree(pecalloc_pointer);
    //php_printf("[pecalloc_test] efree is called again for pointer: %p\n", pecalloc_pointer);

    RETURN_TRUE;
}

PHP_FUNCTION(trigger_sprintf)
{
    
    char *buffer = emalloc(128);
    const char *name = "Test";
    int id = 42;

    php_printf("Buffer allocated at: %p\n", buffer);

    efree(buffer);

    sprintf(buffer, "User '%s' has ID %d.", name, id);

    php_printf("sprintf finished. Buffer content: \"%s\"\n", buffer);

    RETURN_TRUE;
}

PHP_FUNCTION(trigger_strtok) {

    char original_string[] = "first second";
    char *buffer = emalloc(strlen(original_string) + 1);
    strcpy(buffer, original_string);

    php_printf("Buffer allocated at: %p\n", buffer);
    php_printf("Original content: \"%s\"\n", buffer);

    efree(buffer);
    
    char *token = strtok(buffer, " ");
    
    RETURN_TRUE;
}

ZEND_BEGIN_ARG_INFO(arginfo_trigger_emalloc, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_trigger_pemalloc, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_trigger_erealloc, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_trigger_perealloc, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_trigger_ecalloc, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_trigger_pecalloc, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_trigger_sprintf, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_trigger_strtok, 0)
ZEND_END_ARG_INFO()


const zend_function_entry php_leak_test_functions[] = {
    PHP_FE(trigger_emalloc, arginfo_trigger_emalloc)
    PHP_FE(trigger_pemalloc, arginfo_trigger_pemalloc)
    PHP_FE(trigger_erealloc, arginfo_trigger_erealloc)
    PHP_FE(trigger_perealloc, arginfo_trigger_perealloc)
    PHP_FE(trigger_ecalloc, arginfo_trigger_ecalloc)
    PHP_FE(trigger_pecalloc, arginfo_trigger_pecalloc)
    PHP_FE(trigger_sprintf, arginfo_trigger_sprintf)
    PHP_FE(trigger_strtok, arginfo_trigger_strtok)
    PHP_FE_END
};

zend_module_entry php_leak_test_module_entry = {
    STANDARD_MODULE_HEADER,
    "php_leak_test",
    php_leak_test_functions,
    PHP_MINIT(php_leak_test),     /* MINIT - module startup */
    PHP_MSHUTDOWN(php_leak_test), /* MSHUTDOWN - module shutdown */
    PHP_RINIT(php_leak_test),     /* RINIT - request startup */
    PHP_RSHUTDOWN(php_leak_test), /* RSHUTDOWN - request shutdown */
    NULL,
    "1.0",
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_PHP_LEAK_TEST
ZEND_GET_MODULE(php_leak_test)
#endif