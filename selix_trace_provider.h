#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER PHP_selix

#undef TRACEPOINT_INCLUDE_FILE
#define TRACEPOINT_INCLUDE_FILE ./selix_trace_provider.h

#if !defined(_PHP_SELIX_PROVIDER_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _PHP_SELIX_PROVIDER_H
#include <lttng/tracepoint.h>

/* Tracepoints */
TRACEPOINT_EVENT( PHP_selix, check_read_permission,
	TP_ARGS(const char *, fname),
	TP_FIELDS(
		ctf_string(file, fname)
	)
)

/* Log levels */
TRACEPOINT_LOGLEVEL( PHP_selix, check_read_permission, TRACE_INFO)

#endif

#include <lttng/tracepoint-event.h>
