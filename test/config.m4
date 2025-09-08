PHP_ARG_ENABLE(php_leak_test, whether to enable php_leak_test support,
[  --enable-php-leak-test   Enable php_leak_test support])

if test "$PHP_PHP_LEAK_TEST" = "yes"; then
  AC_DEFINE(HAVE_PHP_LEAK_TEST, 1, [Whether you have php_leak_test])
  PHP_NEW_EXTENSION(php_leak_test, php_leak_test.c, $ext_shared)
fi