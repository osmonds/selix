#ifndef PHP_SELIX_H
#define PHP_SELIX_H

#define SELIX_NAME			"selix"
#define SELIX_VERSION 		"0.1"
#define SELIX_AUTHOR 		"Ettore Del Negro"
#define SELIX_URL 			"http://github.com/ettoredn/selix"
#define SELIX_COPYRIGHT  	"Copyright (c) 2011-2012"

#define SCP_COUNT			4
#define SCP_DOMAIN_IDX		0
#define SCP_RANGE_IDX		1
#define SCP_CDOMAIN_IDX		2
#define SCP_CRANGE_IDX		3

extern zend_module_entry selix_module_entry;
#define phpext_selix_ptr &selix_module_entry

#ifdef PHP_WIN32
#	define PHP_SELIX_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_SELIX_API __attribute__ ((visibility("default")))
#else
#	define PHP_SELIX_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

typedef struct _zend_compile_args {
	zend_file_handle *file_handle;
	int type;
#ifdef ZTS
	TSRMLS_D;
#endif
} zend_compile_args;

typedef struct _zend_execute_args {
	zend_op_array *op_array;
	sigset_t *sigmask;
#ifdef ZTS
	TSRMLS_D;
#endif
} zend_execute_args;

PHP_MINIT_FUNCTION(selix);
PHP_MSHUTDOWN_FUNCTION(selix);
PHP_RINIT_FUNCTION(selix);
PHP_RSHUTDOWN_FUNCTION(selix);
PHP_MINFO_FUNCTION(selix);

ZEND_BEGIN_MODULE_GLOBALS(selix)
	char *separams_names[SCP_COUNT];
	char *separams_values[SCP_COUNT];
	zend_bool force_context_change;
	zend_bool verbose;
	char *domain_env;
	char *range_env;
	char *compile_domain_env;
	char *compile_range_env;
ZEND_END_MODULE_GLOBALS(selix)

#ifdef ZTS
#define SELIX_G(v) TSRMG(selix_globals_id, zend_selix_globals *, v)
#else
#define SELIX_G(v) (selix_globals.v)
#endif

#endif
