#ifndef NGX_HTTP_LUA_JAEGERTRACING_H
#define NGX_HTTP_LUA_JAEGERTRACING_H

#include "ngx_http_lua_common.h"
#include <unistd.h>


void ngx_http_lua_inject_jaegertracing_api(lua_State *L);

void ngx_http_lua_jaegertracing_span_start_helper(void *data, const char *operation_name);
void ngx_http_lua_jaegertracing_span_start_helper2(void *data, const char *operation_name, size_t operation_name_len);
void ngx_http_lua_jaegertracing_span_finish_helper(void *data);
void ngx_http_lua_jaegertracing_span_log_helper(void *data, const char *key, const char *value);
void ngx_http_lua_jaegertracing_span_log_helper2(void *data, const char *key, size_t key_len, const char *value, size_t value_len);

#endif /* NGX_HTTP_LUA_JAEGERTRACING_H */

