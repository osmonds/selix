#ifndef SELIX_UTILS_H
#define SELIX_UTILS_H

int set_context( char *domain, char *range TSRMLS_DC );
void filter_http_globals(zval *array_ptr TSRMLS_DC);
int check_read_permission( zend_file_handle *handle );
int compare_current_context_to( char *domain, char *range TSRMLS_DC );

#endif /* SELIX_UTILS_H */
