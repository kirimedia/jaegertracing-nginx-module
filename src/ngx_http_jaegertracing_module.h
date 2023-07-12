#ifndef _NGX_HTTP_JAEGERTRACING_MODULE_H_INCLUDED_
#define _NGX_HTTP_JAEGERTRACING_MODULE_H_INCLUDED_

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdbool.h>
#include <cjaeger.h>

ngx_int_t ngx_http_jaegertracing_is_enabled(ngx_http_request_t *r);
void *ngx_http_jaegertracing_get_request_span(ngx_http_request_t *r);
void *ngx_http_jaegertracing_span_start(ngx_http_request_t *r, void *parent, const char *operation_name);
void *ngx_http_jaegertracing_span_start2(ngx_http_request_t *r, void *parent, const char *operation_name, size_t operation_name_len);
uint64_t ngx_http_jaegertracing_span_id(ngx_http_request_t *r, void *span, uint64_t *trace_id_hi, uint64_t *trace_id_lo);
int ngx_http_jaegertracing_span_debug(ngx_http_request_t *r, void *span);
void *ngx_http_jaegertracing_span_start_from(ngx_http_request_t *r, uint64_t trace_id_hi, uint64_t trace_id_lo, uint64_t parent_id, const char *operation_name, size_t operation_name_len);
int ngx_http_jaegertracing_span_headers_set(ngx_http_request_t *r, void *span, cjaeger_header_set header_set, void *header_set_arg);
void *ngx_http_jaegertracing_span_start_headers(ngx_http_request_t *r, cjaeger_header_trav_start trav_start, cjaeger_header_trav_each trav_each, void *trav_arg, const char *operation_name, size_t operation_name_len);
void ngx_http_jaegertracing_span_finish(ngx_http_request_t *r, void *span);
void ngx_http_jaegertracing_span_log(ngx_http_request_t *r, void *span, const char *key, const char *value);
void ngx_http_jaegertracing_span_log2(ngx_http_request_t *r, void *span, const char *key, size_t key_len, const char *value, size_t value_len);
void ngx_http_jaegertracing_span_logd(ngx_http_request_t *r, void *span, const char *key, size_t key_len, int64_t value);
void ngx_http_jaegertracing_span_logu(ngx_http_request_t *r, void *span, const char *key, size_t key_len, uint64_t value);
void ngx_http_jaegertracing_span_logfp(ngx_http_request_t *r, void *span, const char *key, size_t key_len, double value);
void ngx_http_jaegertracing_span_logb(ngx_http_request_t *r, void *span, const char *key, size_t key_len, bool value);

typedef struct {
    ngx_str_t service_name;
    ngx_str_t agent_addr;
    ngx_str_t collector_endpoint;
    ngx_flag_t traceid_128bit;
    cjaeger_tracer_headers_config headers_config;
    unsigned flags;
} ngx_http_jaegertracing_main_conf_t;

typedef struct {
    ngx_array_t              *from;     /* array of ngx_cidr_t */
    ngx_array_t              *parent_from; /* array of ngx_cidr_t */
    ngx_http_complex_value_t *variable;
    double                    sample;
    ngx_flag_t                parent;
} ngx_http_jaegertracing_loc_conf_t;

typedef struct {
    ngx_int_t tracing;
    void *request_span;
} ngx_http_jaegertracing_ctx_t;

extern ngx_module_t ngx_http_jaegertracing_module;

#endif
