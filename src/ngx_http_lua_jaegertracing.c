#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_jaegertracing_module.h"
#include "ngx_http_lua_jaegertracing.h"
#include "ngx_http_lua_util.h"

#include <stdbool.h>
#include <inttypes.h>
#include <cjaeger.h>

static int ngx_http_lua_jaegertracing_is_enabled(lua_State *L);
static int ngx_http_lua_jaegertracing_span_start(lua_State *L);
static int ngx_http_lua_jaegertracing_span_id(lua_State *L);
static int ngx_http_lua_jaegertracing_span_headers(lua_State *L);
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

    lua_pushcfunction(L, ngx_http_lua_jaegertracing_span_id);
    lua_setfield(L, -2, "span_id");

    lua_pushcfunction(L, ngx_http_lua_jaegertracing_span_headers);
    lua_setfield(L, -2, "span_headers");

    lua_pushcfunction(L, ngx_http_lua_jaegertracing_span_finish);
    lua_setfield(L, -2, "span_finish");

    lua_pushcfunction(L, ngx_http_lua_jaegertracing_span_log);
    lua_setfield(L, -2, "span_log");

    lua_setfield(L, -2, "tracing");
}

static char ngx_http_lua_spans_key;

static bool
ngx_http_lua_jaegertracing_hextouint64(const char *str_, size_t len, uint64_t *num) {
    static const uint8_t hextouint64_map[256] = {
        [0 ... 0x2f] = 0xff,
        ['0'] = 0, ['1'] = 1, ['2'] = 2, ['3'] = 3, ['4'] = 4, ['5'] = 5, ['6'] = 6, ['7'] = 7, ['8'] = 8, ['9'] = 9,
        [0x3a ... 0x40] = 0xff,
        ['A'] = 0xA, ['B'] = 0xB, ['C'] = 0xC, ['D'] = 0xD, ['E'] = 0xE, ['F'] = 0xF,
        [0x47 ... 0x60] = 0xff,
        ['a'] = 0xA, ['b'] = 0xB, ['c'] = 0xC, ['d'] = 0xD, ['e'] = 0xE, ['f'] = 0xF,
        [0x67 ... 0xff] = 0xff,
    };
    uint64_t n = 0;
    const uint8_t *str = (const uint8_t*)str_;
    const uint8_t *end = str + len;

    for (; str < end; str++) {
        uint8_t ch = hextouint64_map[*str];
        if (ch == 0xff)
            return false;
        n = (n << 4) | ch;
    }
    if (num != NULL)
        *num = n;
    return true;
}

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
    ngx_http_lua_jaegertracing_span_start_helper2(data, operation_name, strlen(operation_name));
}

void
ngx_http_lua_jaegertracing_span_start_helper2(void *data, const char *operation_name, size_t operation_name_len) {
    lua_State *L = (lua_State*)data;

    ngx_http_request_t *r;
    r = ngx_http_lua_get_req(L);

    if (r == NULL) {
        luaL_error(L, "no request object found");
    }

    if (!ngx_http_jaegertracing_is_enabled(r))
        return;

    void *parent = ngx_http_lua_jaegertracing_span_peek(L);
    void *span = ngx_http_jaegertracing_span_start2(r, parent, operation_name, operation_name_len);
    if (span == NULL)
        return;

    ngx_http_lua_jaegertracing_span_push(L, span);
    return;
}

void
ngx_http_lua_jaegertracing_span_start_from_helper(void *data, uint64_t trace_id_hi, uint64_t trace_id_lo, uint64_t parent_id, const char *operation_name, size_t operation_name_len) {
    lua_State *L = (lua_State*)data;

    ngx_http_request_t *r;
    r = ngx_http_lua_get_req(L);

    if (r == NULL) {
        luaL_error(L, "no request object found");
    }

    void *span = ngx_http_jaegertracing_span_start_from(r, trace_id_hi, trace_id_lo, parent_id, operation_name, operation_name_len);
    if (span == NULL)
        return;

    ngx_http_lua_jaegertracing_span_push(L, span);
    return;
}

static int ngx_http_lua_jaegertracing_header_trav_start(void *arg) {
    lua_State *L = arg;

    /* here we allow to restart traversal from the middle */
    lua_pop(L, 1);
    lua_pushnil(L);

    return 0;
}

static int ngx_http_lua_jaegertracing_header_trav_each(const char **name, size_t *name_len, const char **value, size_t *value_len, void *arg) {
    lua_State *L = arg;

    if (lua_next(L, -2) == 0) {
        /* remain the stack size unchanged */
        lua_pushnil(L);
        return 1;
    }
    if (!lua_isstring(L, -2))
        return -1;
    *name = lua_tolstring(L, -2, name_len);
    *value = lua_tolstring(L, -1, value_len);
    if (*value == NULL) {
        lua_pop(L, 1);
        return -1;
    }
    lua_pop(L, 1);

    return 0;
}

static void
ngx_http_lua_jaegertracing_span_start_headers_helper(lua_State *L, int headers, const char *operation_name, size_t operation_name_len) {

    ngx_http_request_t *r;
    r = ngx_http_lua_get_req(L);

    if (r == NULL) {
        luaL_error(L, "no request object found");
    }

    lua_rawgeti(L, LUA_REGISTRYINDEX, headers);
    lua_pushnil(L);
    void *span = ngx_http_jaegertracing_span_start_headers(r, ngx_http_lua_jaegertracing_header_trav_start, ngx_http_lua_jaegertracing_header_trav_each, L, operation_name, operation_name_len);
    lua_pop(L, 2);
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
ngx_http_lua_jaegertracing_span_log_helper2(void *data, const char *key, size_t key_len, const char *value, size_t value_len) {
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

    ngx_http_jaegertracing_span_log2(r, span, key, key_len, value, value_len);
    return;
}

void
ngx_http_lua_jaegertracing_span_log_helper(void *data, const char *key, const char *value) {
    ngx_http_lua_jaegertracing_span_log_helper2(data, key, key != NULL ? strlen(key) : 0, value, value != NULL ? strlen(value) : 0);
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
    size_t operation_name_len;
    const char *operation_name = luaL_checklstring(L, 1, &operation_name_len);
    int nargs = lua_gettop(L);
    if (nargs > 1 && lua_istable(L, 2)) {
        lua_pushvalue(L, 2);
        int headers = luaL_ref(L, LUA_REGISTRYINDEX);
        ngx_http_lua_jaegertracing_span_start_headers_helper(L, headers, operation_name, operation_name_len);
        luaL_unref(L, LUA_REGISTRYINDEX, headers);
        return 0;
    }
    uint64_t trace_id_hi = 0, trace_id_lo = 0, parent_id = 0;
    if (nargs > 1) {
        size_t id_len;
        const char *id = lua_tolstring(L, 2, &id_len);
        if (id != NULL) {
            if (id_len == 16) {
                if (!ngx_http_lua_jaegertracing_hextouint64(id, 16, &trace_id_lo))
                    return luaL_error(L, "trace_id must be a hexadecimal string");
            } else if (id_len == 32) {
                if (!ngx_http_lua_jaegertracing_hextouint64(id, 16, &trace_id_hi)
                    || !ngx_http_lua_jaegertracing_hextouint64(id + 16, 16, &trace_id_lo))
                    return luaL_error(L, "trace_id must be a hexadecimal string");
            } else
                return luaL_error(L, "trace_id length must be equal to 16 or 32");
        }
    }
    if (nargs > 2) {
        size_t id_len;
        const char *id = lua_tolstring(L, 3, &id_len);
        if (id != NULL) {
            if (id_len != 16)
                return luaL_error(L, "parent_id length must be equal to 16");
            if (!ngx_http_lua_jaegertracing_hextouint64(id, 16, &parent_id))
                return luaL_error(L, "parent_id must be a hexadecimal string");
        }
    }

    if (trace_id_lo == 0)
        ngx_http_lua_jaegertracing_span_start_helper2(L, operation_name, operation_name_len);
    else
        ngx_http_lua_jaegertracing_span_start_from_helper(L, trace_id_hi, trace_id_lo, parent_id, operation_name, operation_name_len);
    return 0;
}

static int
ngx_http_lua_jaegertracing_span_id(lua_State *L) {
    ngx_http_request_t *r;
    r = ngx_http_lua_get_req(L);

    if (r == NULL) {
        luaL_error(L, "no request object found");
    }

    if (!ngx_http_jaegertracing_is_enabled(r))
        return 0;

    void *span = ngx_http_lua_jaegertracing_span_peek(L);
    if (!span)
        return 0;

    uint64_t trace_id_hi, trace_id_lo, span_id;

    span_id = ngx_http_jaegertracing_span_id(r, span, &trace_id_hi, &trace_id_lo);
    if (!span_id)
        return 0;

    char trace_id_buf[33], span_id_buf[17];
    size_t trace_id_len = 0;

    snprintf(span_id_buf, sizeof(span_id_buf), "%016"PRIx64, span_id);
    if (trace_id_hi != 0)
        trace_id_len += snprintf(trace_id_buf + trace_id_len, sizeof(trace_id_buf) - trace_id_len, "%016"PRIx64, trace_id_hi);
    trace_id_len += snprintf(trace_id_buf + trace_id_len, sizeof(trace_id_buf) - trace_id_len, "%016"PRIx64, trace_id_lo);

    lua_pushlstring(L, trace_id_buf, trace_id_len);
    lua_pushlstring(L, span_id_buf, 16);

    return 2;
}

static int ngx_http_lua_jaegertracing_header_set(const char *name, size_t name_len, const char *value, size_t value_len, void *arg) {
    lua_State *L = arg;

    lua_pushlstring(L, name, name_len);
    lua_pushlstring(L, value, value_len);
    lua_settable(L, -3);
    return 0;
}

static int
ngx_http_lua_jaegertracing_span_headers(lua_State *L) {
    ngx_http_request_t *r;
    r = ngx_http_lua_get_req(L);

    if (r == NULL) {
        luaL_error(L, "no request object found");
    }

    if (!ngx_http_jaegertracing_is_enabled(r))
        return 0;

    void *span = ngx_http_lua_jaegertracing_span_peek(L);
    if (!span)
        return 0;

    lua_newtable(L);
    if (ngx_http_jaegertracing_span_headers_set(r, span, ngx_http_lua_jaegertracing_header_set, L) < 0)
        return 0;
    return 1;
}

static int
ngx_http_lua_jaegertracing_span_finish(lua_State *L) {
    ngx_http_lua_jaegertracing_span_finish_helper(L);;
    return 0;
}

static int
ngx_http_lua_jaegertracing_span_log(lua_State *L) {
    size_t key_len, value_len;
    const char *key = luaL_checklstring(L, 1, &key_len);
    const char *value = lua_tolstring(L, 2, &value_len);
    if (value == NULL) {
        value = "nil";
        value_len = 3;
    }
    ngx_http_lua_jaegertracing_span_log_helper2(L, key, key_len, value, value_len);
    return 0;
}
