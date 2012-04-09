PHP_ARG_ENABLE(selix, whether to enable SELinux support,
[  --enable-selix           Enable SELinux support])

if test "$PHP_SELIX" != "no"; then
  PHP_CHECK_LIBRARY(selinux, is_selinux_enabled, 
  [
    PHP_ADD_LIBRARY(selinux, 1, SELIX_SHARED_LIBADD)
    # AC_DEFINE(HAVE_LIBMCRYPT,1,[ ])
  ],[
    AC_MSG_ERROR("libselinux not found!")
  ],[
    -lselinux
  ])

  PHP_NEW_EXTENSION(selix, selix.c, $ext_shared,,,,yes)
  PHP_SUBST(SELIX_SHARED_LIBADD)
fi
