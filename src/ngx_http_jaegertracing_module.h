#ifndef _NGX_HTTP_JAEGERTRACING_MODULE_H_INCLUDED_
#define _NGX_HTTP_JAEGERTRACING_MODULE_H_INCLUDED_

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t ngx_http_jaegertracing_is_enabled(ngx_http_request_t *r);
void *ngx_http_jaegertracing_get_request_span(ngx_http_request_t *r);
void *ngx_http_jaegertracing_span_start(ngx_http_request_t *r, void *parent, const char *operation_name);
void *ngx_http_jaegertracing_span_start2(ngx_http_request_t *r, void *parent, const char *operation_name, size_t operation_name_len);
uint64_t ngx_http_jaegertracing_span_id(ngx_http_request_t *r, void *span, uint64_t *trace_id_hi, uint64_t *trace_id_lo);
void *ngx_http_jaegertracing_span_start_from(ngx_http_request_t *r, uint64_t trace_id_hi, uint64_t trace_id_lo, uint64_t parent_id, const char *operation_name, size_t operation_name_len);
void ngx_http_jaegertracing_span_finish(ngx_http_request_t *r, void *span);
void ngx_http_jaegertracing_span_log(ngx_http_request_t *r, void *span, const char *key, const char *value);
void ngx_http_jaegertracing_span_log2(ngx_http_request_t *r, void *span, const char *key, size_t key_len, const char *value, size_t value_len);

#endif
