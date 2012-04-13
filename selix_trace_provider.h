#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER PHP_selix

#undef TRACEPOINT_INCLUDE_FILE
#define TRACEPOINT_INCLUDE_FILE ./selix_trace_provider.h

#if !defined(_PHP_SELIX_PROVIDER_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _PHP_SELIX_PROVIDER_H
#include <lttng/tracepoint.h>

/* Tracepoints */
TRACEPOINT_EVENT( PHP_selix, check_read_permission,
	TP_ARGS(const char *, fname, char *, opened),
	TP_FIELDS(
		ctf_string(path, fname)
		ctf_string(opened_path, opened)
	)
)
TRACEPOINT_EVENT( PHP_selix, read_security_context,
	TP_ARGS(const char *, name, const char *, value),
	TP_FIELDS(
		ctf_string(attribute, name)
		ctf_string(value, value)
	)
)
TRACEPOINT_EVENT( PHP_selix, security_context_change,
	TP_ARGS(const char *, newctx, const char *, oldctx),
	TP_FIELDS(
		ctf_string(new, newctx)
		ctf_string(old, oldctx)
	)
)
TRACEPOINT_EVENT( PHP_selix, zend_execute,
	TP_ARGS(const char *, fname, zend_uint, lineno, zend_bool, exec),
	TP_FIELDS(
		ctf_string(path, fname)
		ctf_integer(zend_uint, line, lineno)
		ctf_integer(zend_bool, in_execution, exec)
	)
)
TRACEPOINT_EVENT( PHP_selix, zend_compile_file,
	TP_ARGS(const char *, fname, char *, opened, zend_bool, exec),
	TP_FIELDS(
		ctf_string(path, fname)
		ctf_string(opened_path, opened)
		ctf_integer(zend_bool, in_execution, exec)
	)
)

/* Log levels */
TRACEPOINT_LOGLEVEL( PHP_selix, check_read_permission, TRACE_DEBUG_FUNCTION)
TRACEPOINT_LOGLEVEL( PHP_selix, read_security_context, TRACE_DEBUG_MODULE)
TRACEPOINT_LOGLEVEL( PHP_selix, security_context_change, TRACE_DEBUG_FUNCTION)
TRACEPOINT_LOGLEVEL( PHP_selix, zend_execute, TRACE_DEBUG_FUNCTION)
TRACEPOINT_LOGLEVEL( PHP_selix, zend_compile_file, TRACE_DEBUG_FUNCTION)

#endif

#include <lttng/tracepoint-event.h>
