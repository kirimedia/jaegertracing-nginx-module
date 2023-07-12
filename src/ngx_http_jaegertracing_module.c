#include "ngx_http_jaegertracing_module.h"

static const ngx_str_t ngx_http_jaegertracing_request_name = ngx_string("request");

static ngx_int_t ngx_http_jaegertracing_init_process(ngx_cycle_t *cycle);
static void ngx_http_jaegertracing_exit_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_jaegertracing_init(ngx_conf_t *cf);
static void *ngx_http_jaegertracing_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_jaegertracing_init_main_conf(ngx_conf_t* cf, void *conf);
static void *ngx_http_jaegertracing_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_jaegertracing_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_set_jaegertracing_propagation_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_set_jaegertracing_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_set_jaegertracing_from(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_set_jaegertracing_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_set_jaegertracing_sample(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

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

    { ngx_string("jaegertracing_collector_endpoint"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_jaegertracing_main_conf_t, collector_endpoint),
      NULL },

    { ngx_string("jaegertracing_traceid_128bit"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_jaegertracing_main_conf_t, traceid_128bit),
      NULL },

    { ngx_string("jaegertracing_propagation_format"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_set_jaegertracing_propagation_format,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("jaegertracing_header_context"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_set_jaegertracing_header,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_jaegertracing_main_conf_t, headers_config.trace_context_header_name),
      NULL },

    { ngx_string("set_jaegertracing_from"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_jaegertracing_from,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_jaegertracing_loc_conf_t, from),
      NULL },

    { ngx_string("set_jaegertracing"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_jaegertracing_variable,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("set_jaegertracing_sample"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_jaegertracing_sample,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("set_jaegertracing_parent"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_jaegertracing_loc_conf_t, parent),
      NULL },

    { ngx_string("set_jaegertracing_parent_from"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_jaegertracing_from,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_jaegertracing_loc_conf_t, parent_from),
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
    if (jmcf->service_name.data && (jmcf->agent_addr.data || jmcf->collector_endpoint.data)) {
        char service_name[jmcf->service_name.len + 1];
        ngx_sprintf((u_char*)service_name, "%V%Z", &jmcf->service_name);
        char agent_addr[jmcf->agent_addr.len + 1];
        ngx_sprintf((u_char*)agent_addr, "%V%Z", &jmcf->agent_addr);
        char collector_endpoint[jmcf->collector_endpoint.len + 1];
        ngx_sprintf((u_char*)collector_endpoint, "%V%Z", &jmcf->collector_endpoint);
        tracer = cjaeger_tracer_create3(service_name, agent_addr, collector_endpoint, jmcf->flags, &jmcf->headers_config);
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
    conf->traceid_128bit = NGX_CONF_UNSET;
    conf->headers_config.jaeger_debug_header = "";
    conf->headers_config.jaeger_baggage_header = "";
    conf->headers_config.trace_context_header_name = "";
    conf->headers_config.trace_baggage_header_prefix = "";

    return conf;
};

static char *
ngx_http_jaegertracing_init_main_conf(ngx_conf_t* cf, void *conf)
{
    ngx_http_jaegertracing_main_conf_t *jmcf = conf;
    if (jmcf->agent_addr.len == 0) {
        ngx_str_set(&jmcf->agent_addr, "127.0.0.1:6831");
    }
    if (jmcf->traceid_128bit > 0)
        jmcf->flags |= CJAEGER_TRACEID_128BIT;

    if (!(jmcf->flags & CJAEGER_PROPAGATION_ANY)) {
        if (   *jmcf->headers_config.jaeger_debug_header != '\0'
            || *jmcf->headers_config.jaeger_baggage_header != '\0'
            || *jmcf->headers_config.trace_context_header_name != '\0'
            || *jmcf->headers_config.trace_baggage_header_prefix != '\0')

            jmcf->flags |= CJAEGER_PROPAGATION_JAEGER;
        else
            jmcf->flags |= CJAEGER_PROPAGATION_W3C;
    }

    if (!!(jmcf->flags & CJAEGER_PROPAGATION_W3C)) {
        /*
         * It is a hack. jmcf->headers_config is not used by jaeger when W3C
         * propagation is enabled (jaeger just uses constant names below), but
         * we do use it while headers filtering in
         * ngx_http_jaegertracing_header_known().
         */
        jmcf->headers_config.trace_context_header_name = "traceparent";
        jmcf->headers_config.jaeger_debug_header = "tracestate";
        jmcf->headers_config.jaeger_baggage_header = "";
        jmcf->headers_config.trace_baggage_header_prefix = "";
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
    conf->sample = -1;
    conf->parent = NGX_CONF_UNSET;

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

    ngx_conf_merge_value(conf->parent, prev->parent, 0);

    if (conf->parent_from == NULL) {
        conf->parent_from = prev->parent_from;
    }

    if (conf->variable == NULL) {
        conf->variable = prev->variable;
    }

    if (conf->sample < 0)
        conf->sample = (prev->sample < 0) ? 0 : prev->sample;

    return NGX_CONF_OK;
}

static void
ngx_http_jaegertracing_cleanup(void *data)
{
    ngx_http_jaegertracing_ctx_t *ctx = data;

    if (ctx->request_span != NULL)
        cjaeger_span_finish(ctx->request_span);
}

static ngx_http_jaegertracing_ctx_t *
ngx_http_jaegertracing_get_module_ctx(ngx_http_request_t *r)
{
    ngx_http_jaegertracing_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r->main, ngx_http_jaegertracing_module);

    return ctx;
}

static ngx_http_jaegertracing_ctx_t *
ngx_http_jaegertracing_add_module_ctx(ngx_http_request_t *r)
{
    ngx_http_jaegertracing_ctx_t       *ctx;
    ngx_pool_cleanup_t                 *cln;

    cln = ngx_pool_cleanup_add(r->pool, sizeof(*ctx));
    if (cln == NULL)
        return NULL;

    ctx = cln->data;
    ngx_memzero(ctx, sizeof(*ctx));

    cln->handler = ngx_http_jaegertracing_cleanup;

    ngx_http_set_ctx(r, ctx, ngx_http_jaegertracing_module);

    return ctx;
}

static void
ngx_http_jaegertracing_request_log(ngx_http_request_t *r, void *span)
{
    static const ngx_str_t x_request_id_name = ngx_string("x_request_id");
    static ngx_uint_t x_request_id_hash;
    const ngx_http_variable_value_t *x_request_id;

    if (!x_request_id_hash)
        x_request_id_hash = ngx_hash_key(x_request_id_name.data, x_request_id_name.len);

    cjaeger_span_log2(span, "uri", (char*)r->uri.data, r->uri.len);
    cjaeger_span_log2(span, "args", (char*)r->args.data, r->args.len);

    x_request_id = ngx_http_get_variable(r, (ngx_str_t *)&x_request_id_name, x_request_id_hash);
    if (x_request_id != NULL && x_request_id->len != 0)
        cjaeger_span_log2(span, "x_request_id", (char*)x_request_id->data, x_request_id->len);
}

struct ngx_http_jaegertracing_parent_trav {
    ngx_http_request_t *r;
    ngx_list_part_t *part;
    ngx_uint_t i;
};

static int
ngx_http_jaegertracing_parent_trav_start(void *arg)
{
    struct ngx_http_jaegertracing_parent_trav *ctx = arg;

    ctx->part = &ctx->r->headers_in.headers.part;
    ctx->i = 0;
    return 0;
}

static int
ngx_http_jaegertracing_parent_trav_each(const char **name, size_t *name_len, const char **value, size_t *value_len, void *arg)
{
    struct ngx_http_jaegertracing_parent_trav *trav = arg;

    if (trav->i >= trav->part->nelts) {
        ngx_list_part_t *next = trav->part->next;
        if (next == NULL)
            return 1;
        trav->part = next;
        trav->i = 0;
    }
    ngx_table_elt_t *header = trav->part->elts;
    header += trav->i;
    *name = (char *)header->key.data;
    *name_len = header->key.len;
    *value = (char *)header->value.data;
    *value_len = header->value.len;

    trav->i++;

    return 0;
}

static ngx_int_t
ngx_http_jaegertracing_parent(ngx_http_request_t *r, ngx_http_jaegertracing_loc_conf_t *jlcf)
{
    if (jlcf->parent_from != NULL && ngx_cidr_match(r->connection->sockaddr, jlcf->parent_from) != NGX_OK)
        return NGX_DECLINED;

    struct ngx_http_jaegertracing_parent_trav trav;

    trav.r = r;

    void *span = ngx_http_jaegertracing_span_start_headers(r, ngx_http_jaegertracing_parent_trav_start, ngx_http_jaegertracing_parent_trav_each, &trav,
        (char*)ngx_http_jaegertracing_request_name.data, ngx_http_jaegertracing_request_name.len);

    if (span == NULL)
        return NGX_DECLINED;

    ngx_http_jaegertracing_request_log(r, span);
    cjaeger_span_logb(span, "parent", 6, true);

    return NGX_OK;
}

static ngx_int_t
ngx_http_jaegertracing_handler(ngx_http_request_t *r)
{
    ngx_http_jaegertracing_ctx_t       *ctx;
    ngx_http_jaegertracing_loc_conf_t  *jlcf;

    if (!tracer) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_jaegertracing_get_module_ctx(r);

    if (ctx) {
        return NGX_DECLINED;
    }

    jlcf = ngx_http_get_module_loc_conf(r, ngx_http_jaegertracing_module);

    if (jlcf->parent) {
        ngx_int_t rc = ngx_http_jaegertracing_parent(r, jlcf);

        if (rc != NGX_DECLINED) {
            return rc == NGX_OK ? NGX_DECLINED : rc;
        }
    }

    if (jlcf->variable == NULL) {
        return NGX_DECLINED;
    }

    unsigned tracing_level = 0;
    int sample = 0;
    unsigned span_flags = 0;

    if (jlcf->from == NULL || ngx_cidr_match(r->connection->sockaddr, jlcf->from) == NGX_OK) {

        ngx_str_t value = ngx_null_string;
        ngx_http_complex_value_t *cv = jlcf->variable;
        if (ngx_http_complex_value(r, cv, &value) != NGX_OK)
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        if (value.len > 1)
            tracing_level = 1;
        else if (value.len == 1 && *value.data != '0') {
            tracing_level = 1;
            if (*value.data >= '2' && *value.data <= '9') {
                tracing_level = 2;
                span_flags |= CJAEGER_SPAN_DEBUG;
            }
        }
    }
    if (tracing_level == 0 && jlcf->sample > 0) {
        sample = (ngx_random() / (double)((uint64_t)RAND_MAX + 1)) < jlcf->sample;
    }

    ctx = ngx_http_jaegertracing_add_module_ctx(r);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (tracing_level > 0 || sample) {
        ctx->tracing = 1;
        ctx->request_span = cjaeger_span_start3(tracer, NULL, (char*)ngx_http_jaegertracing_request_name.data, ngx_http_jaegertracing_request_name.len, span_flags);
        if (ctx->request_span) {
            ngx_http_jaegertracing_request_log(r, ctx->request_span);

            if (tracing_level > 0)
                cjaeger_span_logb(ctx->request_span, "user", 4, true);
            else
                cjaeger_span_logb(ctx->request_span, "sample", 6, true);
        }
    }

    return NGX_DECLINED;
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

    return NGX_OK;
}

static char*
ngx_http_set_jaegertracing_propagation_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    ngx_http_jaegertracing_main_conf_t *jmcf = conf;
    ngx_str_t *value = cf->args->elts;

    if (!!(jmcf->flags & CJAEGER_PROPAGATION_ANY))
        return "is duplicate";

    if (!ngx_strcasecmp(value[1].data, (u_char *)"jaeger"))
        jmcf->flags |= CJAEGER_PROPAGATION_JAEGER;
    else if (!ngx_strcasecmp(value[1].data, (u_char *)"w3c"))
        jmcf->flags |= CJAEGER_PROPAGATION_W3C;
    else
        return "is invalid";

    return NGX_CONF_OK;
}

static char*
ngx_http_set_jaegertracing_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    ngx_str_t *value = cf->args->elts;
    char **field = (char**)(conf + cmd->offset);

    ngx_strlow(value[1].data, value[1].data, value[1].len);
    *field = (char*)value[1].data;

    return NGX_CONF_OK;
}

static char*
ngx_http_set_jaegertracing_from(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    ngx_array_t **parray = conf + cmd->offset;

    ngx_int_t                rc;
    ngx_str_t               *value;
    ngx_cidr_t              *cidr;

    value = cf->args->elts;

    if (*parray == NULL) {
        *parray = ngx_array_create(cf->pool, 2,
                                      sizeof(ngx_cidr_t));
        if (*parray == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    cidr = ngx_array_push(*parray);
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

static char*
ngx_http_set_jaegertracing_sample(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    ngx_http_jaegertracing_loc_conf_t *jlcf = conf;
    ngx_str_t *value = cf->args->elts;

    if (jlcf->sample >= 0)
        return "is duplicate";

    ngx_int_t sample_i = ngx_atofp(value[1].data, value[1].len, 9);
    if (sample_i < 0 || sample_i > 1000000000)
        return "is invalid";

    jlcf->sample = sample_i / (double)1000000000;

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

void *
ngx_http_jaegertracing_span_start2(ngx_http_request_t *r, void *parent, const char *operation_name, size_t operation_name_len) {

    void *span = cjaeger_span_start2(tracer, parent, operation_name, operation_name_len);
    return span;
}

uint64_t
ngx_http_jaegertracing_span_id(ngx_http_request_t *r, void *span, uint64_t *trace_id_hi, uint64_t *trace_id_lo) {

    if (!ngx_http_jaegertracing_is_enabled(r)) {
        return 0;
    }
    return cjaeger_span_id(span, trace_id_hi, trace_id_lo);
}

int ngx_http_jaegertracing_span_debug(ngx_http_request_t *r, void *span) {

    return span != NULL && cjaeger_span_debug(span);
}

void *
ngx_http_jaegertracing_span_start_from(ngx_http_request_t *r, uint64_t trace_id_hi, uint64_t trace_id_lo, uint64_t parent_id, const char *operation_name, size_t operation_name_len) {

    if (!ngx_http_jaegertracing_is_enabled(r)) {
        return NULL;
    }

    void *span = cjaeger_span_start_from(tracer, trace_id_hi, trace_id_lo, parent_id, operation_name, operation_name_len);
    return span;
}

static bool
ngx_http_jaegertracing_header_known(ngx_http_jaegertracing_main_conf_t *jmcf, const char *name, size_t name_len) {
    cjaeger_tracer_headers_config *hcf = &jmcf->headers_config;

    struct {
        const char *name;
        bool prefix;
    } headers[] = {
        {.name = hcf->trace_context_header_name},
        {.name = hcf->jaeger_debug_header},
        {.name = hcf->jaeger_baggage_header},
        {.name = hcf->trace_baggage_header_prefix, .prefix = true},
    };
    size_t i;

    for (i = 0; i < sizeof(headers) / sizeof(headers[0]); i++) {
        const char *ptr = headers[i].name;

        if (ngx_strncasecmp((u_char*)name, (u_char*)ptr, name_len) != 0)
            continue;
        if (!headers[i].prefix && ptr[name_len] != '\0')
            continue;
        return true;
    }
    return false;
}

typedef struct ngx_http_jaegertracing_span_headers_set_ctx {
    ngx_http_jaegertracing_main_conf_t *jmcf;
    cjaeger_header_set header_set;
    void *header_set_arg;
} ngx_http_jaegertracing_span_headers_set_ctx;

static int
ngx_http_jaegertracing_span_header_set(const char *name, size_t name_len, const char *value, size_t value_len, void *arg) {
    ngx_http_jaegertracing_span_headers_set_ctx *ctx = arg;

    if (!ngx_http_jaegertracing_header_known(ctx->jmcf, name, name_len))
        return 0;
    return ctx->header_set(name, name_len, value, value_len, ctx->header_set_arg);
}

int
ngx_http_jaegertracing_span_headers_set(ngx_http_request_t *r, void *span, cjaeger_header_set header_set, void *header_set_arg) {
    if (!ngx_http_jaegertracing_is_enabled(r))
        return -1;

    ngx_http_jaegertracing_span_headers_set_ctx ctx;
    ctx.jmcf = ngx_http_get_module_main_conf(r, ngx_http_jaegertracing_module);
    ctx.header_set = header_set;
    ctx.header_set_arg = header_set_arg;
    return cjaeger_span_headers_set(span, ngx_http_jaegertracing_span_header_set, &ctx);
}

typedef struct ngx_http_jaegertracing_trav_ctx {
    ngx_http_jaegertracing_main_conf_t *jmcf;
    cjaeger_header_trav_start trav_start;
    cjaeger_header_trav_each trav_each;
    void *trav_arg;
} ngx_http_jaegertracing_trav_ctx;

static int
ngx_http_jaegertracing_trav_start(void *arg) {
    ngx_http_jaegertracing_trav_ctx *ctx = arg;

    return ctx->trav_start(ctx->trav_arg);
}

static int
ngx_http_jaegertracing_trav_each(const char **name, size_t *name_len, const char **value, size_t *value_len, void *arg) {
    ngx_http_jaegertracing_trav_ctx *ctx = arg;

    while (true) {
        int rv = ctx->trav_each(name, name_len, value, value_len, ctx->trav_arg);

        if (rv != 0)
            return rv;
        if (ngx_http_jaegertracing_header_known(ctx->jmcf, *name, *name_len))
            return 0;
    }
    /* unreachable */
    return -1;
}

void *
ngx_http_jaegertracing_span_start_headers(ngx_http_request_t *r, cjaeger_header_trav_start trav_start, cjaeger_header_trav_each trav_each, void *trav_arg, const char *operation_name, size_t operation_name_len)
{
    ngx_http_jaegertracing_trav_ctx tctx;
    tctx.jmcf = ngx_http_get_module_main_conf(r, ngx_http_jaegertracing_module);
    tctx.trav_start = trav_start;
    tctx.trav_each = trav_each;
    tctx.trav_arg = trav_arg;

    void *span = cjaeger_span_start_headers(tracer, ngx_http_jaegertracing_trav_start, ngx_http_jaegertracing_trav_each, &tctx, operation_name, operation_name_len);
    if (span == NULL)
        return NULL;

    ngx_http_jaegertracing_ctx_t *ctx = ngx_http_jaegertracing_get_module_ctx(r);
    if (ctx == NULL) {
        if ((ctx = ngx_http_jaegertracing_add_module_ctx(r)) == NULL) {
            cjaeger_span_finish(span);
            return NULL;
        }
    }
    if (ctx->request_span == NULL)
        ctx->request_span = span;
    ctx->tracing = 1;

    return span;
}

void
ngx_http_jaegertracing_span_finish(ngx_http_request_t *r, void *span) {

    if (!ngx_http_jaegertracing_is_enabled(r)) {
        return;
    }

    ngx_http_jaegertracing_ctx_t *ctx = ngx_http_jaegertracing_get_module_ctx(r);
    void *request_span = ctx->request_span;

    cjaeger_span_finish(span);

    if (span == request_span) {
        ctx->request_span = NULL;
        ctx->tracing = 0;
    }
}

void ngx_http_jaegertracing_span_log2(ngx_http_request_t *r, void *span, const char *key, size_t key_len, const char *value, size_t value_len) {

    if (!ngx_http_jaegertracing_is_enabled(r)) {
        return;
    }

    cjaeger_span_log3(span, key, key_len, value, value_len);
}

#define NGX_HTTP_JAEGERTRACING_SPAN_LOG_TRIV_IMPL(name, type) \
void ngx_http_jaegertracing_span_log ## name(ngx_http_request_t *r, void *span, const char *key, size_t key_len, type value) { \
 \
    if (!ngx_http_jaegertracing_is_enabled(r)) { \
        return; \
    } \
 \
    cjaeger_span_log ## name(span, key, key_len, value); \
}

NGX_HTTP_JAEGERTRACING_SPAN_LOG_TRIV_IMPL(d, int64_t)
NGX_HTTP_JAEGERTRACING_SPAN_LOG_TRIV_IMPL(u, uint64_t)
NGX_HTTP_JAEGERTRACING_SPAN_LOG_TRIV_IMPL(fp, double)
NGX_HTTP_JAEGERTRACING_SPAN_LOG_TRIV_IMPL(b, bool)

void
ngx_http_jaegertracing_span_log(ngx_http_request_t *r, void *span, const char *key, const char *value) {

    if (!ngx_http_jaegertracing_is_enabled(r)) {
        return;
    }

    cjaeger_span_log(span, key, value);
}
