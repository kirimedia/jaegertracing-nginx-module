#ifndef _NGX_HTTP_JAEGERTRACING_MODULE_H_INCLUDED_
#define _NGX_HTTP_JAEGERTRACING_MODULE_H_INCLUDED_

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t ngx_http_jaegertracing_is_enabled(ngx_http_request_t *r);
void *ngx_http_jaegertracing_get_request_span(ngx_http_request_t *r);
void *ngx_http_jaegertracing_span_start(ngx_http_request_t *r, void *parent, const char *operation_name);
void ngx_http_jaegertracing_span_finish(ngx_http_request_t *r, void *span);
void ngx_http_jaegertracing_span_log(ngx_http_request_t *r, void *span, const char *key, const char *value);

#endif
