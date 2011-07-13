PHP_ARG_ENABLE(selix, whether to enable SELinux support,
[  --enable-selix           Enable SELinux support])

if test "$PHP_SELIX" != "no"; then
  PHP_NEW_EXTENSION(selix, selix.c, $ext_shared)
  AC_CHECK_LIB(selinux, is_selinux_enabled,
               AC_DEFINE(HAVE_SELINUX,1, [Enable PHP/SELinux support])
               PHP_ADD_LIBRARY(selinux),
               AC_MSG_ERROR("libselinux is not available hoge"))
fi
