#include <pthread.h>
#include <selinux/selinux.h>
#include <selinux/context.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "php.h"
#include "php_variables.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_selix.h"

ZEND_DECLARE_MODULE_GLOBALS(selix)

void (*old_php_import_environment_variables)(zval *array_ptr TSRMLS_DC);
void selinux_php_import_environment_variables(zval *array_ptr TSRMLS_DC);

void (*old_zend_execute)(zend_op_array *op_array TSRMLS_DC);
void selinux_zend_execute(zend_op_array *op_array TSRMLS_DC);

zend_op_array *(*old_zend_compile_file)(zend_file_handle *file_handle, int type TSRMLS_DC);
zend_op_array *selinux_zend_compile_file(zend_file_handle *file_handle, int type TSRMLS_DC);

void *do_zend_compile_file( void *data );
void *do_zend_execute( void *data );
int set_context( char *domain, char *range );

/*
 * Every user visible function must have an entry in selix_functions[].
 */
const zend_function_entry selix_functions[] = {
	{NULL, NULL, NULL}
};

zend_module_entry selix_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"selix",
	selix_functions,
	PHP_MINIT(selix),
	PHP_MSHUTDOWN(selix),
	PHP_RINIT(selix),
	PHP_RSHUTDOWN(selix),
	PHP_MINFO(selix),
#if ZEND_MODULE_API_NO >= 20010901
	"0.1",
#endif
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_SELIX
ZEND_GET_MODULE(selix)
#endif

PHP_MINIT_FUNCTION(selix)
{
	int ret;
	zend_bool jit_initialization = (PG(auto_globals_jit) && !PG(register_globals) && !PG(register_long_arrays));

	// Adds FastCGI parameters to catch
	SELIX_G(separams_names[PARAM_DOMAIN_IDX]) = PARAM_DOMAIN_NAME;
	SELIX_G(separams_names[PARAM_RANGE_IDX]) = PARAM_RANGE_NAME;

	ret = is_selinux_enabled();
	if (!ret)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "SELinux is not enabled on the system! This causes PHP-SELinux to be off");
		return SUCCESS;
	}
	else if (ret < 0)
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "is_selinux_enabled() failed. Check your SELinux installation" );		
	
	// SELinux enabled
	
	/* 
	 * auto_globals_jit needs to be off in order to be able to get environment variables
	 * before zend_compile and zend_execute calls.
	 * http://www.php.net/manual/en/ini.core.php#ini.auto-globals-jit
	 */
	if (jit_initialization)
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "Can't enable PHP-SELinux support with auto_globals_jit enabled!");

	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(selix)
{
	return SUCCESS;
}

PHP_RINIT_FUNCTION(selix)
{
	if (is_selinux_enabled() < 1)
		return SUCCESS;
	
	/* Override php_import_environment_variables ( main/php_variables.c:824 ) */
	old_php_import_environment_variables = php_import_environment_variables;
	php_import_environment_variables = selinux_php_import_environment_variables;

	/* Override zend_execute to execute it in a SELinux context */
	old_zend_execute = zend_execute;
	zend_execute = selinux_zend_execute;
	
	/* Override zend_compile_file to check read permission on it for currenct SELinux domain */
	old_zend_compile_file = zend_compile_file;
	zend_compile_file = selinux_zend_compile_file;
		
	return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(selix)
{
	int i;
	
	// Dealloc parameters
	for (i=0; i < SELINUX_PARAMS_COUNT; i++)
		if (SELIX_G(separams_values[i]))
			efree( SELIX_G(separams_values[i]) );
	
	if (is_selinux_enabled() < 1)
		return SUCCESS;
	
	// Restore handlers
	php_import_environment_variables = old_php_import_environment_variables;
	zend_execute = old_zend_execute;
	zend_compile_file = old_zend_compile_file;
	
	return SUCCESS;
}

PHP_MINFO_FUNCTION(selix)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "SELinux support", "enabled");
	php_info_print_table_end();
}

/*
 * zend_compile_file() handler
 */
zend_op_array *selinux_zend_compile_file(zend_file_handle *file_handle, int type TSRMLS_DC)
{
	zend_bool jit_initialization = (PG(auto_globals_jit) && !PG(register_globals) && !PG(register_long_arrays));
	zend_compile_args args;
	void *compiled_op_array;
	pthread_t execute_thread;
	char *str;
	
	if (jit_initialization)
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "Can't enable PHP-SELinux support with auto_globals_jit enabled!");
	
	// Forces import of environment variables
 	if (php_request_startup_for_hook(TSRMLS_C) == FAILURE)
 		php_error_docref(NULL TSRMLS_CC, E_ERROR, "php_request_startup_for_hook() error");
	
	// @DEBUG
	asprintf( &str, "[*] Compiling %s <br>", file_handle->filename );
	php_write( str, strlen(str) );
	free(str);
	
	args.file_handle = file_handle;
	args.type = type;
	if (pthread_create( &execute_thread, NULL, do_zend_compile_file, &args ))
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "pthread_create() error");

	if (pthread_join( execute_thread, &compiled_op_array ))
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "pthread_join() error");

	return (zend_op_array *)compiled_op_array;
}

/*
 * Executed in a thread.
 * It uses selinux_set_domain in order to transition to the proper security domain,
 * then calls zend_compile_file()
 */
void *do_zend_compile_file( void *data )
{
	zend_compile_args *args = (zend_compile_args *)data;
	
	set_context( SELIX_G(separams_values[PARAM_DOMAIN_IDX]), SELIX_G(separams_values[PARAM_RANGE_IDX]) );
	
	return old_zend_compile_file( args->file_handle, args->type TSRMLS_CC );
}


/*
 * zend_execute() handler
 */
void selinux_zend_execute(zend_op_array *op_array TSRMLS_DC)
{
	static int nesting = 0;
	pthread_t execute_thread;
	char *str;
	
	// Nested calls are already executed in proper security context
	if (nesting++ > 0)
		return old_zend_execute( op_array TSRMLS_CC );
	
	// Environment variables already imported during compile
	
	// @DEBUG
	asprintf( &str, "[*] Executing in proper security context %s<br>", op_array->filename );
	php_write( str, strlen(str) );
	free(str);
	
	if (pthread_create( &execute_thread, NULL, do_zend_execute, op_array ))
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "pthread_create() error");

	if (pthread_join( execute_thread, NULL ))
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "pthread_join() error");
	
	nesting = 0;
}

/*
 * Executed in a thread.
 * It uses selinux_set_domain in order to transition to the proper security domain,
 * then calls zend_execute()
 */
void *do_zend_execute( void *data )
{
	zend_op_array *op_array = (zend_op_array *)data;
	
	set_context( SELIX_G(separams_values[PARAM_DOMAIN_IDX]), SELIX_G(separams_values[PARAM_RANGE_IDX]) );
	old_zend_execute( op_array TSRMLS_CC );
	
	return NULL;
}

/*
 * It sets the security context of the calling thread to the new one received from
 * environment variables.
 */
int set_context( char *domain, char *range )
{
	security_context_t current_ctx, new_ctx;
	context_t context;
	char *str;
	
	// Get current context
	if (getcon( &current_ctx ) < 0)
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "getcon() failed");
	
	// Allocates a new context_t (i.e. malloc)
	context = context_new( current_ctx );
	if (!context)
	{
		freecon( current_ctx );
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "context_new() failed");
	}
	
	// @DEBUG
	asprintf( &str, "[SC] Current context: %s<br>", current_ctx );
	php_write( str, strlen(str) );
	free(str);
	
	// Sets values for the new context
	context_type_set( context, domain );
	context_range_set( context,  range );
	
	// Gets a pointer to a string representing the context_t
	new_ctx = context_str( context );
	if (!new_ctx)
	{
		freecon( current_ctx );
		context_free( context );
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "context_str() failed");
	}
	
	if (!strcmp( current_ctx, new_ctx ))
	{
		// @DEBUG
		asprintf( &str, "[SC] No context chages made<br>", new_ctx );
		php_write( str, strlen(str) );
		free(str);

		context_free( context );
		freecon( current_ctx );
		return 0;
	}

	// Set new context
	if (setcon( new_ctx ) < 0)
	{
		freecon( current_ctx );
		context_free( context );
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "setcon() failed");
	}
	
	// @DEBUG
	asprintf( &str, "[SC] New context: %s<br>", new_ctx );
	php_write( str, strlen(str) );
	free(str);
	
	// Free previously allocated context_t and so the new_ctx pointer isn't valid anymore
	context_free( context );
	freecon( current_ctx );
	return 0;
}

/*
 * It gets SELinux related values from environment variables.
 */
void selinux_php_import_environment_variables(zval *array_ptr TSRMLS_DC)
{
	zval **data;
	HashTable *arr_hash;
	HashPosition pointer;
	int i;
	char *str;
	
	if (!array_ptr)
		return;
	
	/* call php's original import as a catch-all */
	old_php_import_environment_variables( array_ptr TSRMLS_CC );
	
	arr_hash = Z_ARRVAL_P(array_ptr);
	for (zend_hash_internal_pointer_reset_ex(arr_hash, &pointer ); 
		zend_hash_get_current_data_ex(arr_hash, (void**) &data, &pointer) == SUCCESS; 
		zend_hash_move_forward_ex(arr_hash, &pointer))
	{
		char *key;
		int key_len;
		long index;
		
		if (zend_hash_get_current_key_ex(arr_hash, &key, &key_len, &index, 0, &pointer) == HASH_KEY_IS_STRING)
		{
			for (i=0; i < SELINUX_PARAMS_COUNT; i++)
			{
				/*
				 * Apache mod_fastcgi adds a parameter for every SetEnv <name> <value>
				 * in the form of "REDIRECT_<name>". These need to be hidden too.
				 */
				int redirect_len = strlen("REDIRECT_") + strlen( SELIX_G(separams_names[i]) ) + 1;
				char *redirect_param = (char *) emalloc( redirect_len );
				
				memset( redirect_param, 0, redirect_len );
				strcat( redirect_param, "REDIRECT_" );
				strcat( redirect_param, SELIX_G(separams_names[i]) );
					
				if (!strncmp( key, SELIX_G(separams_names[i]), strlen( SELIX_G(separams_names[i]) )))
				{
					// TODO handle of other types (int, null, etc) if needed
					if (Z_TYPE_PP(data) == IS_STRING)
					SELIX_G(separams_values[i]) = estrdup( Z_STRVAL_PP(data) );
					
					// @DEBUG
					// asprintf( &str, "[*] Got %s => %s <br>", SELIX_G(separams_names[i]), SELIX_G(separams_values[i]) );
					// php_write( str, strlen(str) );
					// free(str);
					
					// Hide <selinux_param>
					zend_hash_del(arr_hash, key, strlen(key) + 1);
				}
				
				// Hide REDIRECT_<selinux_param> entries
				if (!strncmp( key, redirect_param, redirect_len ))
					zend_hash_del(arr_hash, key, strlen(key) + 1);
				
				efree( redirect_param );
			}
		}
	}
}
