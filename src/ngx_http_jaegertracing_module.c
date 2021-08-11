#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <cjaeger.h>

typedef struct {
    ngx_str_t service_name;
    ngx_str_t agent_addr;
} ngx_http_jaegertracing_main_conf_t;

typedef struct {
    ngx_array_t              *from;     /* array of ngx_cidr_t */
    ngx_http_complex_value_t *variable;
} ngx_http_jaegertracing_loc_conf_t;

typedef struct {
    ngx_int_t tracing;
    void *request_span;
} ngx_http_jaegertracing_ctx_t;

static ngx_int_t ngx_http_jaegertracing_init_process(ngx_cycle_t *cycle);
static void ngx_http_jaegertracing_exit_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_jaegertracing_init(ngx_conf_t *cf);
static void *ngx_http_jaegertracing_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_jaegertracing_init_main_conf(ngx_conf_t* cf, void *conf);
static void *ngx_http_jaegertracing_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_jaegertracing_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_set_jaegertracing_from(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_set_jaegertracing_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_http_jaegertracing_commands[] = {

    { ngx_string("jaegertracing_service_name"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_jaegertracing_main_conf_t, service_name),
      NULL },

    { ngx_string("jaegertracing_agent_addr"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_jaegertracing_main_conf_t, agent_addr),
      NULL },

    { ngx_string("set_jaegertracing_from"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_jaegertracing_from,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("set_jaegertracing"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_jaegertracing_variable,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t ngx_http_jaegertracing_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_jaegertracing_init,           /* postconfiguration */

    ngx_http_jaegertracing_create_main_conf,/* create main configuration */
    ngx_http_jaegertracing_init_main_conf,  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_jaegertracing_create_loc_conf,/* create location configuration */
    ngx_http_jaegertracing_merge_loc_conf, /* merge location configuration */
};


ngx_module_t ngx_http_jaegertracing_module = {
    NGX_MODULE_V1,
    &ngx_http_jaegertracing_module_ctx,    /* module context */
    ngx_http_jaegertracing_commands,       /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_jaegertracing_init_process,   /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_jaegertracing_exit_process,   /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *tracer;

static ngx_int_t
ngx_http_jaegertracing_init_process(ngx_cycle_t *cycle) {
    ngx_http_jaegertracing_main_conf_t *jmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_jaegertracing_module);
    if (jmcf->service_name.data && jmcf->agent_addr.data) {
        char service_name[jmcf->service_name.len + 1];
        ngx_sprintf((u_char*)service_name, "%V%Z", &jmcf->service_name);
        char agent_addr[jmcf->agent_addr.len + 1];
        ngx_sprintf((u_char*)agent_addr, "%V%Z", &jmcf->agent_addr);
        tracer = cjaeger_tracer_create(service_name, agent_addr);
    }
    return NGX_OK;
}

static void
ngx_http_jaegertracing_exit_process(ngx_cycle_t *cycle) {
    if (tracer) {
        cjaeger_tracer_destroy(tracer);
        tracer = NULL;
    }
}

static void *
ngx_http_jaegertracing_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_jaegertracing_main_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_jaegertracing_main_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
};

static char *
ngx_http_jaegertracing_init_main_conf(ngx_conf_t* cf, void *conf)
{
    ngx_http_jaegertracing_main_conf_t *jmcf = conf;
    if (jmcf->agent_addr.len == 0) {
        ngx_str_set(&jmcf->agent_addr, "127.0.0.1:6831");
    }
    return NGX_CONF_OK;
}

static void *
ngx_http_jaegertracing_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_jaegertracing_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_jaegertracing_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_jaegertracing_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_jaegertracing_loc_conf_t *prev = parent;
    ngx_http_jaegertracing_loc_conf_t *conf = child;

    if (conf->from == NULL) {
        conf->from = prev->from;
    }

    if (conf->variable == NULL) {
        conf->variable = prev->variable;
    }

    return NGX_CONF_OK;
}

static void
ngx_http_jaegertracing_cleanup(void *data)
{
}

static ngx_http_jaegertracing_ctx_t *
ngx_http_jaegertracing_get_module_ctx(ngx_http_request_t *r)
{
    ngx_pool_cleanup_t           *cln;
    ngx_http_jaegertracing_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_jaegertracing_module);

    if (ctx == NULL && (r->internal || r->filter_finalize)) {

        /*
         * if module context was reset, the original address
         * can still be found in the cleanup handler
         */

        for (cln = r->pool->cleanup; cln; cln = cln->next) {
            if (cln->handler == ngx_http_jaegertracing_cleanup) {
                ctx = cln->data;
                break;
            }
        }
        if (ctx)
            ngx_http_set_ctx(r, ctx, ngx_http_jaegertracing_module);
    }

    return ctx;
}

static ngx_int_t
ngx_http_jaegertracing_handler(ngx_http_request_t *r)
{
    ngx_http_jaegertracing_ctx_t       *ctx;
    ngx_http_jaegertracing_loc_conf_t  *jlcf;
    ngx_pool_cleanup_t                 *cln;

    jlcf = ngx_http_get_module_loc_conf(r, ngx_http_jaegertracing_module);
    if (jlcf->variable == NULL) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_jaegertracing_get_module_ctx(r);

    if (ctx) {
        return NGX_DECLINED;
    }

    ngx_str_t value = ngx_null_string;

    if (jlcf->from == NULL || ngx_cidr_match(r->connection->sockaddr, jlcf->from) == NGX_OK) {

        ngx_http_complex_value_t *cv = jlcf->variable;
        if (ngx_http_complex_value(r, cv, &value) != NGX_OK)
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_jaegertracing_ctx_t));
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = cln->data;
    ngx_memzero(ctx, sizeof(ngx_http_jaegertracing_ctx_t));

    if (value.len != 0 && *value.data != '0') {
        ctx->tracing = 1;
    }

    cln->handler = ngx_http_jaegertracing_cleanup;

    ngx_http_set_ctx(r, ctx, ngx_http_jaegertracing_module);

    if (ctx->tracing) {
        ctx->request_span = cjaeger_span_start(tracer, NULL, "request");
        if (ctx->request_span) {
            cjaeger_span_log2(ctx->request_span, "uri", (char*)r->uri.data, r->uri.len);
            cjaeger_span_log2(ctx->request_span, "args", (char*)r->args.data, r->args.len);
        }
    }

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_jaegertracing_log(ngx_http_request_t *r)
{
    ngx_http_jaegertracing_ctx_t       *ctx;

    ctx = ngx_http_jaegertracing_get_module_ctx(r);
    if (!ctx || !ctx->tracing)
        return NGX_OK;

    cjaeger_span_finish(ctx->request_span);
    return NGX_OK;
}


static ngx_int_t
ngx_http_jaegertracing_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *jmcf;

    jmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&jmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_jaegertracing_handler;

    h = ngx_array_push(&jmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_jaegertracing_handler;

    h = ngx_array_push(&jmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_jaegertracing_log;

    return NGX_OK;
}

static char*
ngx_http_set_jaegertracing_from(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    ngx_http_jaegertracing_loc_conf_t *jlcf = conf;

    ngx_int_t                rc;
    ngx_str_t               *value;
    ngx_cidr_t              *cidr;

    value = cf->args->elts;

    if (jlcf->from == NULL) {
        jlcf->from = ngx_array_create(cf->pool, 2,
                                      sizeof(ngx_cidr_t));
        if (jlcf->from == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    cidr = ngx_array_push(jlcf->from);
    if (cidr == NULL) {
        return NGX_CONF_ERROR;
    }

#if (NGX_HAVE_UNIX_DOMAIN)

    if (ngx_strcmp(value[1].data, "unix:") == 0) {
        cidr->family = AF_UNIX;
        return NGX_CONF_OK;
    }

#endif

    rc = ngx_ptocidr(&value[1], cidr);

    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "low address bits of %V are meaningless", &value[1]);
    }

    return NGX_CONF_OK;
}

static char*
ngx_http_set_jaegertracing_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    ngx_http_jaegertracing_loc_conf_t *jlcf = conf;
    if (jlcf->variable) {
        return "is duplicate";
    }

    jlcf->variable = ngx_pcalloc(cf->pool, sizeof(ngx_http_complex_value_t));

    ngx_http_compile_complex_value_t  ccv;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &((ngx_str_t*)cf->args->elts)[1];
    ccv.complex_value = jlcf->variable;
    if (ccv.complex_value == NULL)
        return NGX_CONF_ERROR;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK)
        return NGX_CONF_ERROR;

    return NGX_CONF_OK;
}

ngx_int_t
ngx_http_jaegertracing_is_enabled(ngx_http_request_t *r)
{
    ngx_http_jaegertracing_ctx_t       *ctx;

    ctx = ngx_http_jaegertracing_get_module_ctx(r);

    if (!ctx || !ctx->tracing)
        return 0;

    if (!tracer)
         return 0;

    return 1;
}

void *
ngx_http_jaegertracing_get_request_span(ngx_http_request_t *r) {
    ngx_http_jaegertracing_ctx_t       *ctx;

    if (!ngx_http_jaegertracing_is_enabled(r)) {
        return NULL;
    }

    ctx = ngx_http_jaegertracing_get_module_ctx(r);
    return ctx->request_span;
}

void *
ngx_http_jaegertracing_span_start(ngx_http_request_t *r, void *parent, const char *operation_name) {

    if (!ngx_http_jaegertracing_is_enabled(r)) {
        return NULL;
    }

    void *span = cjaeger_span_start(tracer, parent, operation_name);
    return span;
}

void
ngx_http_jaegertracing_span_finish(ngx_http_request_t *r, void *span) {

    if (!ngx_http_jaegertracing_is_enabled(r)) {
        return;
    }

    cjaeger_span_finish(span);
}

void
ngx_http_jaegertracing_span_log(ngx_http_request_t *r, void *span, const char *key, const char *value) {

    if (!ngx_http_jaegertracing_is_enabled(r)) {
        return;
    }

    cjaeger_span_log(span, key, value);
}
