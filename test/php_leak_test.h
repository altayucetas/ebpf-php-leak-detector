#ifndef PHP_PHP_LEAK_TEST_H
#define PHP_PHP_LEAK_TEST_H

extern zend_module_entry php_leak_test_module_entry;
#define phpext_php_leak_test_ptr &php_leak_test_module_entry

/* Function declarations */
PHP_FUNCTION(trigger_emalloc);
PHP_FUNCTION(trigger_pemalloc);
PHP_FUNCTION(trigger_basic);
PHP_FUNCTION(trigger_ecalloc);
PHP_FUNCTION(trigger_pecalloc);
PHP_FUNCTION(trigger_memcpy);
PHP_FUNCTION(show_memory_status);

/* Lifecycle functions */
PHP_MINIT_FUNCTION(php_leak_test);
PHP_MSHUTDOWN_FUNCTION(php_leak_test);
PHP_RINIT_FUNCTION(php_leak_test);
PHP_RSHUTDOWN_FUNCTION(php_leak_test);
PHP_MINFO_FUNCTION(php_leak_test);

#endif