#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <assert.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "php.h"
#include "zend.h"
#include "php_selix.h"

#ifdef HAVE_LTTNGUST
#include "selix_trace_provider.h"
#endif
#include "selix_utils.h"

/*
 * It compares the current security context to a new one obtained by
 * setting domain and range fields from the current.
 * Returns 0 if equal, 1 if different and < 0 on error.
 */
int compare_current_context_to( char *domain, char *range TSRMLS_DC )
{
	security_context_t current_ctx, new_ctx; // String representation
	context_t context;
	int res;
	
	/*
	 * Comparing context is not defined implicates the one derived from current
	 * context is the same.
	 */
	if ((!domain || strlen(domain) < 1) && (!range || strlen(range) < 1))
		return 0;
	
	// Get current context
	if (getcon( &current_ctx ) < 0)
		zend_error(E_CORE_ERROR, "getcon() failed");
	
	// Allocates a new context_t (i.e. malloc)
	context = context_new( current_ctx );
	if (!context)
	{
		freecon( current_ctx );
		zend_error(E_CORE_ERROR, "context_new() failed");
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
	
	// Gets a pointer to a string representing the context_t
	new_ctx = context_str( context );
	if (!new_ctx)
	{
		freecon( current_ctx );
		context_free( context );
		zend_error(E_CORE_ERROR, "context_str() failed");
	}
	
	res = strcmp( current_ctx, new_ctx );
	freecon( current_ctx );
	context_free( context );
	return res;
}

/*
 * It sets the security context of the calling thread to the new one received from
 * environment variables.
 * Returns 0 on success, 1 if no context changes are made (current == new).
 */
int set_context( char *domain, char *range TSRMLS_DC )
{
	security_context_t current_ctx, new_ctx; // String representation
	context_t context;
	
	if ((!domain || strlen(domain) < 1) && (!range || strlen(range) < 1))
		return 0;
	
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
		// No context chages made
		context_free( context );
		freecon( current_ctx );
		return 1;
	}

	// Set new context
	if (setcon( new_ctx ) < 0)
	{
		freecon( current_ctx );
		context_free( context );
		zend_error(E_ERROR, "setcon() failed");
		return 1;
	}
#ifdef HAVE_LTTNGUST
	tracepoint(PHP_selix, security_context_change, new_ctx, current_ctx);
#endif
	
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
#ifdef HAVE_LTTNGUST
			tracepoint(PHP_selix, read_security_context, SELIX_G(separams_names[i]), SELIX_G(separams_values[i]));
#endif
			// Do not expose SELinux security context to scripts
			zend_hash_del( ht, env_name, env_name_length + 1 );
			zend_hash_del( ht, redirect_param, redirect_len );
		}
		
		efree( redirect_param );
	}
}

/*
 * It calls php wrapper to open/read the file pointed by handle's filename.
 * TODO: investigate remote includes PG(allow_url_fopen)
 */
int check_read_permission( zend_file_handle *handle )
{
	int fd;
		
#ifdef HAVE_LTTNGUST
	char *type = "UNKNOWN";
	switch (handle->type) {
		case ZEND_HANDLE_FILENAME:
			type = "ZEND_HANDLE_FILENAME";
			break;
		case ZEND_HANDLE_FD:
			type = "ZEND_HANDLE_FD";
			break;
		case ZEND_HANDLE_FP:
			type = "ZEND_HANDLE_FP";
			break;
		case ZEND_HANDLE_STREAM:
			type = "ZEND_HANDLE_STREAM";
			break;
		case ZEND_HANDLE_MAPPED:
			type = "ZEND_HANDLE_MAPPED";
			break;
	}
	tracepoint(PHP_selix, check_read_permission, type, handle->filename, (handle->opened_path ? handle->opened_path : "NULL"));
#endif

	switch (handle->type) {
		case ZEND_HANDLE_FILENAME:
			/* 
			 * Stream is going to be opened by zend_compile_file which will execute
			 * in caller's security context (i.e. do_zend_compile_file).
			 */
			return SUCCESS;	
		case ZEND_HANDLE_FD:
			if (handle->handle.fd == STDIN_FILENO || handle->handle.fd == STDOUT_FILENO ||
			 		handle->handle.fd == STDERR_FILENO)
				return SUCCESS;
		case ZEND_HANDLE_FP:
			if (handle->handle.fp == stdin || handle->handle.fp == stdout || handle->handle.fp == stderr)
				return SUCCESS;		
		case ZEND_HANDLE_STREAM:
		case ZEND_HANDLE_MAPPED:
			/*
			 * File descriptor already opened in pre-zend_compile_file security context.
			 * It must be checked for read permission.
			 */	
			assert( handle->opened_path && strlen(handle->opened_path) > 0 );
			fd = open( handle->opened_path, O_RDONLY, 0666 );
			if (fd == -1)
				return FAILURE;

			close(fd);
			return SUCCESS;
	}
	
	return FAILURE;
}
