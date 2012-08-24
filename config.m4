PHP_ARG_ENABLE(selix, whether to enable selix extension,
[  --enable-selix           Enable SELinux support])

if test "$PHP_SELIX" != "no"; then
  CFLAGS="$CFLAGS -Wall -fvisibility=hidden"
  
  # Check libselinux
  PHP_CHECK_LIBRARY(selinux, is_selinux_enabled, 
  [
    PHP_ADD_LIBRARY(selinux, 1, SELIX_SHARED_LIBADD)
    # AC_DEFINE(HAVE_LIBMCRYPT,1,[ ])
  ],[
    AC_MSG_ERROR("libselinux not found!")
  ],[
    -lselinux
  ])

  PHP_CHECK_LIBRARY(lttng-ust-ctl, ustctl_create_session, 
  [
    AC_DEFINE(HAVE_LTTNGUST,1,[ ])
    PHP_ADD_LIBRARY(dl, 1, SELIX_SHARED_LIBADD)
    PHP_ADD_LIBRARY(lttng-ust, 1, SELIX_SHARED_LIBADD)
  ],[],[
    -llttng-ust-ctl -ldl
  ])

  selix_sources="selix.c \
                 selix_utils.c"
  
  PHP_NEW_EXTENSION(selix, $selix_sources, $ext_shared,,,,yes)
  PHP_SUBST(SELIX_SHARED_LIBADD)
fi
