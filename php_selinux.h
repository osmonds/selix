#ifndef PHP_SELINUX_H
#define PHP_SELINUX_H

#define SELINUX_PARAMS_COUNT		2
#define PARAM_DOMAIN_IDX	0
#define PARAM_DOMAIN_NAME	"SELINUX_DOMAIN"
#define PARAM_RANGE_IDX		1
#define PARAM_RANGE_NAME	"SELINUX_RANGE"

extern zend_module_entry selinux_module_entry;
#define phpext_selinux_ptr &selinux_module_entry

#ifdef PHP_WIN32
#	define PHP_SELINUX_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_SELINUX_API __attribute__ ((visibility("default")))
#else
#	define PHP_SELINUX_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

typedef struct _zend_compile_args {
	zend_file_handle *file_handle;
	int type;
} zend_compile_args;

PHP_MINIT_FUNCTION(selinux);
PHP_MSHUTDOWN_FUNCTION(selinux);
PHP_RINIT_FUNCTION(selinux);
PHP_RSHUTDOWN_FUNCTION(selinux);
PHP_MINFO_FUNCTION(selinux);

ZEND_BEGIN_MODULE_GLOBALS(selinux)
	char *separams_names[SELINUX_PARAMS_COUNT];
	char *separams_values[SELINUX_PARAMS_COUNT];
ZEND_END_MODULE_GLOBALS(selinux)

#ifdef ZTS
#define SELINUX_G(v) TSRMG(selinux_globals_id, zend_selinux_globals *, v)
#else
#define SELINUX_G(v) (selinux_globals.v)
#endif

#endif
