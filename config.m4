PHP_ARG_ENABLE(selinux, whether to enable selinux support,
[  --enable-selinux           Enable selinux support])

if test "$PHP_SELINUX" != "no"; then
  PHP_NEW_EXTENSION(selinux, selinux.c, $ext_shared)
  AC_CHECK_LIB(selinux, is_selinux_enabled,
               AC_DEFINE(HAVE_SELINUX,1, [Enable PHP/SELinux support])
               PHP_ADD_LIBRARY(selinux),
               AC_MSG_ERROR("libselinux is not available hoge"))
fi
