#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_jaegertracing_module.h"
#include "ngx_http_lua_jaegertracing.h"
#include "ngx_http_lua_util.h"


static int ngx_http_lua_jaegertracing_is_enabled(lua_State *L);
static int ngx_http_lua_jaegertracing_span_start(lua_State *L);
static int ngx_http_lua_jaegertracing_span_finish(lua_State *L);
static int ngx_http_lua_jaegertracing_span_log(lua_State *L);


void
ngx_http_lua_inject_jaegertracing_api(lua_State *L)
{
    lua_createtable(L, 0, 1);

    lua_pushcfunction(L, ngx_http_lua_jaegertracing_is_enabled);
    lua_setfield(L, -2, "is_enabled");

    lua_pushcfunction(L, ngx_http_lua_jaegertracing_span_start);
    lua_setfield(L, -2, "span_start");

    lua_pushcfunction(L, ngx_http_lua_jaegertracing_span_finish);
    lua_setfield(L, -2, "span_finish");

    lua_pushcfunction(L, ngx_http_lua_jaegertracing_span_log);
    lua_setfield(L, -2, "span_log");

    lua_setfield(L, -2, "tracing");
}

static char ngx_http_lua_spans_key;

static void
ngx_http_lua_jaegertracing_get_spans(lua_State *L, void *key) {

    lua_pushlightuserdata(L, ngx_http_lua_lightudata_mask(spans_key));
    lua_rawget(L, LUA_REGISTRYINDEX);

    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushlightuserdata(L, ngx_http_lua_lightudata_mask(spans_key));
        lua_pushvalue(L, -2);
        lua_rawset(L, LUA_REGISTRYINDEX);
    }

    lua_pushlightuserdata(L, key);
    lua_rawget(L, -2);
    return;
}

static void *
ngx_http_lua_jaegertracing_span_peek(lua_State *L) {
    void *span = NULL;

    ngx_http_lua_jaegertracing_get_spans(L, L);

    lua_State *P = L;
    while (lua_isnil(L, -1) || luaL_getn(L, -1) == 0) {
        ngx_http_request_t *r = ngx_http_lua_get_req(L);
        ngx_http_lua_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
        ngx_http_lua_co_ctx_t *coctx = ngx_http_lua_get_co_ctx(P, ctx);
        if (coctx && coctx->parent_co_ctx) {
            lua_pop(L, 2);
            P = coctx->parent_co_ctx->co;
            ngx_http_lua_jaegertracing_get_spans(L, P);
        }
        else {
            break;
        }
    }

    if (!lua_isnil(L, -1) && luaL_getn(L, -1) != 0) {
        lua_rawgeti(L, -1, luaL_getn(L, -1));
        span = lua_touserdata(L, -1);
        lua_pop(L, 1);
    }
    lua_pop(L, 2);

    if (!span) {
        ngx_http_request_t *r = ngx_http_lua_get_req(L);
        span = ngx_http_jaegertracing_get_request_span(r);
    }

    return span;
}

static void
ngx_http_lua_jaegertracing_span_push(lua_State *L, void *span) {

    ngx_http_lua_jaegertracing_get_spans(L, L);

    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_createtable(L, 1, 0);
        lua_pushlightuserdata(L, L);
        lua_pushvalue(L, -2);
        lua_rawset(L, -4);
    }

    lua_pushlightuserdata(L, span);
    lua_rawseti(L, -2, luaL_getn(L, -2) + 1);
    lua_pop(L, 2);
}

static void
ngx_http_lua_jaegertracing_span_pop(lua_State *L) {

    ngx_http_lua_jaegertracing_get_spans(L, L);

    if (lua_isnil(L, -1)) {
        lua_pop(L, 2);
        return;
    }

    size_t n = luaL_getn(L, -1);
    if (n > 0) {
        lua_pushnil(L);
        lua_rawseti(L, -2, luaL_getn(L, -2));
    }
    lua_pop(L, 2);
}

void
ngx_http_lua_jaegertracing_span_start_helper(void *data, const char *operation_name) {
    lua_State *L = (lua_State*)data;

    ngx_http_request_t *r;
    r = ngx_http_lua_get_req(L);

    if (r == NULL) {
        luaL_error(L, "no request object found");
    }

    if (!ngx_http_jaegertracing_is_enabled(r))
        return;

    void *parent = ngx_http_lua_jaegertracing_span_peek(L);
    void *span = ngx_http_jaegertracing_span_start(r, parent, operation_name);
    if (span == NULL)
        return;

    ngx_http_lua_jaegertracing_span_push(L, span);
    return;
}

void
ngx_http_lua_jaegertracing_span_finish_helper(void *data) {
    lua_State *L = (lua_State*)data;

    ngx_http_request_t *r;
    r = ngx_http_lua_get_req(L);

    if (r == NULL) {
        luaL_error(L, "no request object found");
    }

    if (!ngx_http_jaegertracing_is_enabled(r))
        return;

    void *span = ngx_http_lua_jaegertracing_span_peek(L);
    if (!span)
        return;

    ngx_http_jaegertracing_span_finish(r, span);

    ngx_http_lua_jaegertracing_span_pop(L);
    return;
}

void
ngx_http_lua_jaegertracing_span_log_helper(void *data, const char *key, const char *value) {
    lua_State *L = (lua_State*)data;

    ngx_http_request_t *r;
    r = ngx_http_lua_get_req(L);

    if (r == NULL) {
        luaL_error(L, "no request object found");
    }

    if (!ngx_http_jaegertracing_is_enabled(r))
        return;

    void *span = ngx_http_lua_jaegertracing_span_peek(L);
    if (!span)
        return;

    ngx_http_jaegertracing_span_log(r, span, key, value);
    return;
}

static int
ngx_http_lua_jaegertracing_is_enabled(lua_State *L) {
    ngx_http_request_t *r;
    r = ngx_http_lua_get_req(L);

    if (r == NULL) {
        luaL_error(L, "no request object found");
    }

    lua_pushboolean(L, ngx_http_jaegertracing_is_enabled(r));
    return 1;
}

static int
ngx_http_lua_jaegertracing_span_start(lua_State *L) {
    const char *operation_name = luaL_checkstring(L, 1);
    ngx_http_lua_jaegertracing_span_start_helper(L, operation_name);
    return 0;
}


static int
ngx_http_lua_jaegertracing_span_finish(lua_State *L) {
    ngx_http_lua_jaegertracing_span_finish_helper(L);;
    return 0;
}

static int
ngx_http_lua_jaegertracing_span_log(lua_State *L) {
    const char *key = luaL_checkstring(L, 1);
    const char *value = lua_tostring(L, 2);
    ngx_http_lua_jaegertracing_span_log_helper(L, key, value ? value : "nil");
    return 0;
}
