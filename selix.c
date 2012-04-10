#include <signal.h>
#include <pthread.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <assert.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "php.h"
#include "php_variables.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "zend_extensions.h"
#include "php_selix.h"

ZEND_DECLARE_MODULE_GLOBALS(selix)
static PHP_GINIT_FUNCTION(selix);

void (*old_zend_execute)(zend_op_array *op_array TSRMLS_DC);
void selix_zend_execute(zend_op_array *op_array TSRMLS_DC);

zend_op_array *(*old_zend_compile_file)(zend_file_handle *file_handle, int type TSRMLS_DC);
zend_op_array *selix_zend_compile_file(zend_file_handle *file_handle, int type TSRMLS_DC);

void *do_zend_compile_file( void *data );
void *do_zend_execute( void *data );
int set_context( char *domain, char *range TSRMLS_DC );
void filter_http_globals(zval *array_ptr TSRMLS_DC);
int check_read_permission( zend_file_handle *handle );
void selix_debug( const char *docref TSRMLS_DC, const char *format, ... );

int zend_selix_initialised = 0;

/*
 * Every user visible function must have an entry in selix_functions[].
 */
const zend_function_entry selix_functions[] = {
	{NULL, NULL, NULL}
};

zend_module_entry selix_module_entry = {
	STANDARD_MODULE_HEADER,
	"selix",
	selix_functions,
	PHP_MINIT(selix),
	PHP_MSHUTDOWN(selix),
	PHP_RINIT(selix),
	PHP_RSHUTDOWN(selix),
	PHP_MINFO(selix),
	"0.1",
	PHP_MODULE_GLOBALS(selix),
	PHP_GINIT(selix),
	NULL,
	NULL,
	STANDARD_MODULE_PROPERTIES_EX
};

#ifdef COMPILE_DL_SELIX
ZEND_GET_MODULE(selix)
#endif

// ini settings
PHP_INI_BEGIN()
STD_PHP_INI_BOOLEAN("selix.force_context_change", "0", PHP_INI_SYSTEM, OnUpdateBool, force_context_change, zend_selix_globals, selix_globals)
STD_PHP_INI_BOOLEAN("selix.verbose", "0", PHP_INI_ALL, OnUpdateBool, verbose, zend_selix_globals, selix_globals)
STD_PHP_INI_ENTRY("selix.domain_env", "SELINUX_DOMAIN", PHP_INI_SYSTEM, OnUpdateString, domain_env, zend_selix_globals, selix_globals)
STD_PHP_INI_ENTRY("selix.range_env", "SELINUX_RANGE", PHP_INI_SYSTEM, OnUpdateString, range_env, zend_selix_globals, selix_globals)
STD_PHP_INI_ENTRY("selix.compile_domain_env", "SELINUX_COMPILE_DOMAIN", PHP_INI_SYSTEM, OnUpdateString, compile_domain_env, zend_selix_globals, selix_globals)
STD_PHP_INI_ENTRY("selix.compile_range_env", "SELINUX_COMPILE_RANGE", PHP_INI_SYSTEM, OnUpdateString, compile_range_env, zend_selix_globals, selix_globals)

PHP_INI_END()

/*
 * Called to initialize a module's globals before PHP_MINIT_FUNCTION. 
 */
static PHP_GINIT_FUNCTION(selix)
{
	// selix_globals->force_context_change = 0;
}

PHP_MINIT_FUNCTION(selix)
{
	int ret;
	zend_bool jit_initialization = PG(auto_globals_jit);
	
	REGISTER_INI_ENTRIES();
	
	if (SELIX_G(domain_env) && strlen(SELIX_G(domain_env)) > 0)
		SELIX_G(separams_names[SCP_DOMAIN_IDX]) = SELIX_G(domain_env);
	if (SELIX_G(range_env) && strlen(SELIX_G(range_env)) > 0)
		SELIX_G(separams_names[SCP_RANGE_IDX]) = SELIX_G(range_env);
	if (SELIX_G(compile_domain_env) && strlen(SELIX_G(compile_domain_env)) > 0)
		SELIX_G(separams_names[SCP_CDOMAIN_IDX]) = SELIX_G(compile_domain_env);
	if (SELIX_G(compile_range_env) && strlen(SELIX_G(compile_range_env)) > 0)
		SELIX_G(separams_names[SCP_CRANGE_IDX]) = SELIX_G(compile_range_env);

	if (zend_selix_initialised == 0)
	{
		zend_error(E_ERROR, "selix extension MUST be loaded as a Zend extension!");
		return FAILURE;
	}
	
	/* 
	 * auto_globals_jit needs to be off in order to be able to get environment variables
	 * before zend_compile and zend_execute calls.
	 * http://www.php.net/manual/en/ini.core.php#ini.auto-globals-jit
	 */
	if (jit_initialization)
	{
		zend_error(E_ERROR, "Can't enable SELinux support with auto_globals_jit enabled!");
		return FAILURE;
	}
	
	ret = is_selinux_enabled();
	if (!ret)
		zend_error(E_WARNING, "SELinux is not enabled on the system. This causes selix extension to be off");
	else if (ret < 0)
	{
		zend_error(E_ERROR, "is_selinux_enabled() failed. Check your SELinux installation or disable selix extension" );
		return FAILURE;
	}
	// SELinux enabled
	
	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(selix)
{
	UNREGISTER_INI_ENTRIES();
	
	return SUCCESS;
}

PHP_RINIT_FUNCTION(selix)
{
	int i;
	
	// Initialize parameters
	for (i=0; i < SCP_COUNT; i++)
		SELIX_G(separams_values[i]) = NULL;
	
	/* Override zend_compile_file to check read permission on it for currenct SELinux domain */
	old_zend_compile_file = zend_compile_file;
	zend_compile_file = selix_zend_compile_file;

	/* Override zend_execute to execute it in a SELinux context */
	old_zend_execute = zend_execute;
	zend_execute = selix_zend_execute;
	
	return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(selix)
{
	int i;
	
	// Dealloc parameters
	for (i=0; i < SCP_COUNT; i++)
		if (SELIX_G(separams_values[i]))
			efree( SELIX_G(separams_values[i]) );

	// Restore handlers
	zend_compile_file = old_zend_compile_file;
	zend_execute = old_zend_execute;
	
	return SUCCESS;
}

PHP_MINFO_FUNCTION(selix)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "SELinux support", "enabled");
	php_info_print_table_row(2, "Version", SELIX_VERSION );
	php_info_print_table_row(2, "Compiled on", __DATE__ " at " __TIME__);
	php_info_print_table_row(2, "selix.domain_env", SELIX_G(domain_env));
	php_info_print_table_row(2, "selix.range_env", SELIX_G(range_env));
	php_info_print_table_row(2, "selix.compile_domain_env", SELIX_G(compile_domain_env));
	php_info_print_table_row(2, "selix.compile_range_env", SELIX_G(compile_range_env));
	php_info_print_table_row(2, "selix.force_context_change", SELIX_G(force_context_change)? "On":"Off");
	php_info_print_table_row(2, "selix.verbose", SELIX_G(verbose)? "On":"Off");
	php_info_print_table_end();
}

/*
 * zend_compile_file() handler
 */
zend_op_array *selix_zend_compile_file( zend_file_handle *file_handle, int type TSRMLS_DC )
{
	pthread_t compile_thread;
	zend_compile_args args;
	zend_compile_retval *retval;
	zend_op_array *compiled_op_array;
	int bailout;
	zval *server = PG(http_globals)[TRACK_VARS_SERVER]; // TRACK_VARS_ENV;
	// php_var_dump(&server, 1 TSRMLS_CC);
	
	// Call the original handler if SELinux is disabled
	if (is_selinux_enabled() < 1)
		return old_zend_compile_file( file_handle, type TSRMLS_CC );
	
	/*
	 * First script compilation is done with EG(in_execution)=0 
	 * then subsequent calls (include/require) with EG(in_execution)=1
	 */
	if (!EG(in_execution))
		/* 
		 * TODO
		 * With cli environment variables are replicated in $_SERVER array,
		 * this means $_ENV array must be filtered to hide SELinux parameters.
		 */
		filter_http_globals( PG(http_globals)[TRACK_VARS_SERVER] );
	
	memset( &args, 0, sizeof(zend_compile_args) );
#ifndef ZTS
	args.file_handle = file_handle;
	args.type = type;
#ifdef ZTS
	args.tsrm_ls = TSRMLS_C;
#endif
	
	if (pthread_create( &compile_thread, NULL, do_zend_compile_file, &args ))
		zend_error(E_CORE_ERROR, "pthread_create() error");
	
	if (pthread_join( compile_thread, (void *)&retval ))
		zend_error(E_CORE_ERROR, "pthread_join() error");
	
	assert(retval != NULL);
	compiled_op_array = retval->op_array;
	bailout = retval->bailout;
	efree( retval );
	
	// On compile error it propagates the exception to caller
	if (bailout)
		zend_bailout();
	
#else /* ifndef ZTS */
	compiled_op_array = old_zend_compile_file( file_handle, type TSRMLS_CC );
#endif /* ifndef ZTS */

	return compiled_op_array;
}

/*
 * Executed in a thread.
 * It uses set_context in order to transition to the proper security context,
 * then calls zend_compile_file()
 */
void *do_zend_compile_file( void *data )
{
	zend_compile_args *args = (zend_compile_args *)data;
	zend_compile_retval *retval = emalloc( sizeof(zend_compile_retval) );
	
	memset( retval, 0, sizeof(zend_compile_retval) );
	
#ifdef ZTS
	TSRMLS_FETCH(); // void ***tsrm_ls = (void ***) ts_resource_ex(0, NULL)
	*TSRMLS_C = *(args->tsrm_ls); // (*tsrm_ls) = *(args->tsrm_ls)
#endif
	set_context( SELIX_G(separams_values[SCP_CDOMAIN_IDX]), SELIX_G(separams_values[SCP_CRANGE_IDX]) TSRMLS_CC );	

	/*
	 * Caller may have already opened the file in previous context.
	 * Permissions must be re-checked.
	 */
	if (check_read_permission( args->file_handle ) == FAILURE)
	{
		if (args->type == ZEND_REQUIRE)
		{
			zend_message_dispatcher(ZMSG_FAILED_REQUIRE_FOPEN, args->file_handle->filename TSRMLS_CC);
			retval->bailout = 1;
		}
		else
			zend_message_dispatcher(ZMSG_FAILED_INCLUDE_FOPEN, args->file_handle->filename TSRMLS_CC);
					
		retval->op_array = NULL;
	}
	else {
		// Catch compile errors
		zend_try {
			retval->op_array = old_zend_compile_file( args->file_handle, args->type TSRMLS_CC );
		} zend_catch {
			retval->bailout = 1;
		} zend_end_try();
	}
		
	return retval;
}

/*
 * zend_execute() handler
 */
void selix_zend_execute( zend_op_array *op_array TSRMLS_DC )
{
	zend_execute_retval *retval;
	int bailout;
	
	// Nested calls are already executed in proper security context
	if (!EG(in_execution) && is_selinux_enabled() == 1)
	{
		pthread_t execute_thread;
		sigset_t sigmask, old_sigmask;
		zend_execute_args args;
	
		// selix_debug(NULL TSRMLS_CC, "[*] (%u/%u) Executing in new security context %s<br>", CG(in_compilation), EG(in_execution), op_array->filename );
	
		memset( &args, 0, sizeof(zend_execute_args) );
		args.op_array = op_array;
		args.sigmask = &old_sigmask;
#ifdef ZTS
		args.tsrm_ls = TSRMLS_C;
#endif
		/*
		 * Signals must be trasparently delivered to execution thread,
		 * thus parent thread must mask them all and child thread use parent's mask.
		 */
		sigfillset( &sigmask );
		pthread_sigmask( SIG_SETMASK, &sigmask, &old_sigmask );
		
		if (pthread_create( &execute_thread, NULL, do_zend_execute, &args ))
			zend_error(E_CORE_ERROR, "pthread_create() error");

		if (pthread_join( execute_thread, (void *)&retval ))
			zend_error(E_CORE_ERROR, "pthread_join() error");
		
		// Restore signal mask
		pthread_sigmask( SIG_SETMASK, &old_sigmask, NULL );

		assert(retval != NULL);
		bailout = retval->bailout;
		efree( retval );

		// On execution error it propagates the exception to caller
		if (bailout)
			zend_bailout();
		
		return;
	}
	else
		return old_zend_execute( op_array );
}

/*
 * Executed in a thread.
 * It uses set_context in order to transition to the proper security context,
 * then calls zend_execute()
 */
void *do_zend_execute( void *data )
{
	zend_execute_args *args = (zend_execute_args *)data;
	zend_compile_retval *retval = emalloc( sizeof(zend_compile_retval) );

	memset( retval, 0, sizeof(zend_compile_retval) );
	
	// Set parent's signal mask
	pthread_sigmask( SIG_SETMASK, args->sigmask, NULL );

#ifdef ZTS
	TSRMLS_FETCH(); // void ***tsrm_ls = (void ***) ts_resource_ex(0, NULL)
	*TSRMLS_C = *(args->tsrm_ls); // (*tsrm_ls) = *(args->tsrm_ls)
#endif
	set_context( SELIX_G(separams_values[SCP_DOMAIN_IDX]), SELIX_G(separams_values[SCP_RANGE_IDX]) TSRMLS_CC );
	
	// Catch errors
	zend_try {
		old_zend_execute( args->op_array );
	} zend_catch {
		retval->bailout = 1;
	} zend_end_try();
	
	return retval;
}

/*
 * It sets the security context of the calling thread to the new one received from
 * environment variables.
 * Returns 0 on success, 1 if no context changes are made (current == new).
 */
int set_context( char *domain, char *range TSRMLS_DC )
{
	security_context_t current_ctx, new_ctx;
	context_t context;
	
	// Get current context
	if (getcon( &current_ctx ) < 0)
	{
		zend_error(E_ERROR, "getcon() failed");
		return 1;
	}
	
	// Allocates a new context_t (i.e. malloc)
	context = context_new( current_ctx );
	if (!context)
	{
		freecon( current_ctx );
		zend_error(E_ERROR, "context_new() failed");
		return 1;
	}
	
	// Sets values for the new context
	if (domain && strlen(domain) > 0 && range && strlen(range) > 0)
	{
		// Both domain and range
		context_type_set( context, domain );
		context_range_set( context, range );	
	}
	else if (domain && strlen(domain) > 0 && (!range || strlen(range) < 1))
	{
		// Domain only
		context_type_set( context, domain );		
	}
	else if ((!domain || strlen(domain) < 1) && range && strlen(range) > 0)
	{
		// Range only
		context_range_set( context, range );
	}
	else
	{
		// Execute in default security context if neither domain nor range is defined
		if (SELIX_G(force_context_change))
			zend_error(E_CORE_ERROR, "Executing scripts in default security context is disabled. See selix.force_context_change");
	}	
	
	// Gets a pointer to a string representing the context_t
	new_ctx = context_str( context );
	if (!new_ctx)
	{
		freecon( current_ctx );
		context_free( context );
		zend_error(E_ERROR, "context_str() failed");
		return 1;
	}
	
	if (!strcmp( current_ctx, new_ctx ))
	{
		// selix_debug(NULL TSRMLS_CC, "[SC] No context chages made<br>", new_ctx );
		context_free( context );
		freecon( current_ctx );
		return 1;
	}

	// Set new context
	if (setcon( new_ctx ) < 0)
	{
		freecon( current_ctx );
		context_free( context );
		zend_errorf(E_ERROR, "setcon() failed");
		return 1;
	}	
	selix_debug(NULL TSRMLS_CC, "[SC] %s (from %s)<br>", new_ctx, current_ctx );
	
	// Free previously allocated context_t and so the new_ctx pointer isn't valid anymore
	context_free( context );
	freecon( current_ctx );
	return 0;
}

/*
 * It gets SELinux related values from environment variables.
 */
void filter_http_globals( zval *array_ptr TSRMLS_DC )
{
	zval **data;
	HashTable *ht;
	int i;
	char *str;
	
	if (!array_ptr || Z_TYPE_P(array_ptr) != IS_ARRAY)
		return;
	
	ht = Z_ARRVAL_P(array_ptr);
	for (i=0; i < SCP_COUNT; i++)
	{
		char *env_name = SELIX_G(separams_names[i]);
		int env_name_length = strlen( env_name );
		int redirect_len = strlen("REDIRECT_") + strlen( SELIX_G(separams_names[i]) ) + 1;
		char *redirect_param = (char *) emalloc( redirect_len );

		memset( redirect_param, 0, redirect_len );
		strcat( redirect_param, "REDIRECT_" );
		strcat( redirect_param, SELIX_G(separams_names[i]) );
		
		if (zend_hash_find( ht, env_name, env_name_length + 1, (void **)&data ) == SUCCESS)
		{
			if (Z_TYPE_PP(data) == IS_STRING)
				SELIX_G(separams_values[i]) = estrdup( Z_STRVAL_PP(data) );
			
			// selix_debug(NULL TSRMLS_CC, "[*] Got %s => %s <br>", SELIX_G(separams_names[i]), SELIX_G(separams_values[i]) );
			
			// Do not expose SELinux security context to scripts
			zend_hash_del( ht, env_name, env_name_length + 1 );
			zend_hash_del( ht, redirect_param, redirect_len );
		}
		
		efree( redirect_param );
	}
}

/*
 * It calls php's wrapper to force a open/read on the file.
 * This is used to verify whether the current context has the permissions to read the file.
 */
int check_read_permission( zend_file_handle *handle )
{
	int retval = 0;
	char *opened_path;
	php_stream *stream = php_stream_open_wrapper((char *)handle->filename, "rb", 
			USE_PATH|REPORT_ERRORS|STREAM_OPEN_FOR_INCLUDE, &opened_path);
	
	if (stream)
	{
		if (opened_path) {
			efree(opened_path);
			opened_path = NULL;
		}
		php_stream_close(stream);
		return SUCCESS;
	}
	
	return FAILURE;
}

void selix_debug( const char *docref TSRMLS_DC, const char *format, ... )
{
	va_list args;
	char *str;

	if (!SELIX_G(verbose))
		return;

	va_start(args, format);
	vasprintf( &str, format, args );
	php_write( str, strlen(str) TSRMLS_CC );
	free(str);
	va_end(args);
}

ZEND_DLEXPORT int selix_zend_startup(zend_extension *extension)
{
	zend_selix_initialised = 1;
	return zend_startup_module(&selix_module_entry);
}

ZEND_DLEXPORT void selix_zend_shutdown(zend_extension *extension)
{
	// Nothing
}

/* This is a Zend extension */
#ifndef ZEND_EXT_API
#define ZEND_EXT_API    ZEND_DLEXPORT
#endif
ZEND_EXTENSION();

ZEND_DLEXPORT zend_extension zend_extension_entry = {
	SELIX_NAME,
	SELIX_VERSION,
	SELIX_AUTHOR,
	SELIX_URL,
	SELIX_COPYRIGHT,
	selix_zend_startup, 	// startup_func_t
	selix_zend_shutdown,	// shutdown_func_t
	NULL,					// activate_func_t
	NULL,					// deactivate_func_t
	NULL,					// message_handler_func_t
	NULL,					// op_array_handler_func_t
	NULL,					// statement_handler_func_t
	NULL,					// fcall_begin_handler_func_t
	NULL,					// fcall_end_handler_func_t
	NULL,					// op_array_ctor_func_t
	NULL,					// op_array_dtor_func_t
	STANDARD_ZEND_EXTENSION_PROPERTIES
};