/*
 * policy-to-c.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfSentry.
 *
 * wolfSentry is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* Loads a JSON policy with the wolfSentry loader and prints a C function that
 * rebuilds the same events, routes, defaults, and user values through the
 * public API, so fixed-policy devices can omit the configuration loader.
 */

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_USER_BASE

#include "src/wolfsentry_internal.h"
#include "wolfsentry/wolfsentry_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_STUB_ACTIONS 64

static FILE *arrays_out;
static FILE *body_out;
static unsigned int array_count;
static int uses_double;

static wolfsentry_errcode_t stub_action(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_action *action,
    void *handler_arg,
    void *caller_arg,
    const struct wolfsentry_event *trigger_event,
    wolfsentry_action_type_t action_type,
    const struct wolfsentry_route *trigger_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results)
{
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    (void)action;
    (void)handler_arg;
    (void)caller_arg;
    (void)trigger_event;
    (void)action_type;
    (void)trigger_route;
    (void)route_table;
    (void)rule_route;
    (void)action_results;
    WOLFSENTRY_RETURN_OK;
}

static void emit_string(FILE *f, const char *s, size_t len)
{
    size_t i;
    fputc('"', f);
    for (i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)s[i];
        if ((c == '"') || (c == '\\'))
            fprintf(f, "\\%c", c);
        else if ((c >= 0x20) && (c < 0x7f) && (c != '?'))
            fputc(c, f);
        else
            fprintf(f, "\\%03o", c);
    }
    fputc('"', f);
}

static void emit_u64(FILE *f, uint64_t v)
{
    fprintf(f, "POLICY_U64(0x%08lxU, 0x%08lxU)",
            (unsigned long)(v >> 32U), (unsigned long)(v & 0xffffffffU));
}

static unsigned int emit_bytes(const byte *data, size_t len)
{
    size_t i;
    unsigned int n = array_count++;
    fprintf(arrays_out, "static const byte policy_bytes_%u[] = {", n);
    if (len == 0)
        fprintf(arrays_out, " 0");
    for (i = 0; i < len; ++i)
        fprintf(arrays_out, "%s0x%02x", (i == 0) ? "\n    " : ((i % 12U) ? ", " : ",\n    "), data[i]);
    fprintf(arrays_out, "\n};\n");
    return n;
}

/* A field is emitted only when it loaded identically into both hosts, whose
 * initial defaults differ, so fields the policy left alone keep the target's
 * own defaults.
 */
static void emit_config_fields(
    const struct wolfsentry_eventconfig *a,
    const struct wolfsentry_eventconfig *b,
    const struct wolfsentry_eventconfig *a0,
    const struct wolfsentry_eventconfig *b0)
{
#define EMIT_NUMBER(field) do {                                          \
        if (a->field == b->field)                                       \
            fprintf(body_out, "    config." #field " = %luU;\n", (unsigned long)a->field); \
    } while (0)
#define EMIT_TIME(field) do {                                            \
        if (a->field == b->field) {                                     \
            fprintf(body_out, "    config." #field " = (wolfsentry_time_t)"); \
            emit_u64(body_out, (uint64_t)a->field);                     \
            fprintf(body_out, ";\n");                                   \
        }                                                               \
    } while (0)
#define EMIT_BITS(field) do {                                            \
        unsigned long mask_ = (unsigned long)((a0->field ^ b0->field) & ~(a->field ^ b->field)); \
        if (mask_ != 0)                                                 \
            fprintf(body_out, "    config." #field " = (config." #field " & ~0x%lxU) | 0x%lxU;\n", \
                    mask_, (unsigned long)a->field & mask_);            \
    } while (0)
#define EMIT_OR(field) do {                                              \
        if (a->field != 0)                                              \
            fprintf(body_out, "    config." #field " |= 0x%lxU;\n", (unsigned long)a->field); \
    } while (0)
    EMIT_NUMBER(max_connection_count);
    EMIT_NUMBER(derogatory_threshold_for_penaltybox);
    EMIT_TIME(penaltybox_duration);
    EMIT_TIME(route_idle_time_for_purge);
    EMIT_BITS(flags);
    /* the loader ORs these lists into the inherited value */
    EMIT_OR(route_flags_to_add_on_insert);
    EMIT_OR(route_flags_to_clear_on_insert);
    EMIT_OR(action_res_filter_bits_set);
    EMIT_OR(action_res_filter_bits_unset);
    EMIT_OR(action_res_bits_to_add);
    EMIT_OR(action_res_bits_to_clear);
#undef EMIT_NUMBER
#undef EMIT_TIME
#undef EMIT_BITS
#undef EMIT_OR
}

static int emit_defaults(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_context *other,
                         const struct wolfsentry_eventconfig *a0, const struct wolfsentry_eventconfig *b0)
{
    struct wolfsentry_eventconfig a, b;
    struct wolfsentry_route_table *ta, *tb;
    wolfsentry_action_res_t pa, pb;
    wolfsentry_hitcount_t ra, rb;
    wolfsentry_time_t ia, ib;

    if ((wolfsentry_defaultconfig_get(WOLFSENTRY_CONTEXT_ARGS_OUT, &a) < 0) ||
        (wolfsentry_defaultconfig_get(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), &b) < 0) ||
        (wolfsentry_route_get_main_table(WOLFSENTRY_CONTEXT_ARGS_OUT, &ta) < 0) ||
        (wolfsentry_route_get_main_table(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), &tb) < 0) ||
        (wolfsentry_route_table_default_policy_get(WOLFSENTRY_CONTEXT_ARGS_OUT, ta, &pa) < 0) ||
        (wolfsentry_route_table_default_policy_get(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), tb, &pb) < 0) ||
        (wolfsentry_route_table_max_purgeable_routes_get(WOLFSENTRY_CONTEXT_ARGS_OUT, ta, &ra) < 0) ||
        (wolfsentry_route_table_max_purgeable_routes_get(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), tb, &rb) < 0) ||
        (wolfsentry_route_table_max_purgeable_idle_time_get(WOLFSENTRY_CONTEXT_ARGS_OUT, ta, &ia) < 0) ||
        (wolfsentry_route_table_max_purgeable_idle_time_get(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), tb, &ib) < 0))
    {
        return -1;
    }
    fprintf(body_out, "    config = initial_config;\n");
    emit_config_fields(&a, &b, a0, b0);
    fprintf(body_out, "    POLICY_CALL(wolfsentry_defaultconfig_update(WOLFSENTRY_CONTEXT_ARGS_OUT, &config));\n");
    fprintf(body_out, "    if (! (initial_config.flags & WOLFSENTRY_EVENTCONFIG_FLAG_INHIBIT_ACTIONS)) {\n");
    fprintf(body_out, "        POLICY_CALL(wolfsentry_context_inhibit_actions(WOLFSENTRY_CONTEXT_ARGS_OUT));\n");
    fprintf(body_out, "        inhibited = 1;\n    }\n");
    if (pa == pb)
        fprintf(body_out, "    POLICY_CALL(wolfsentry_route_table_default_policy_set(WOLFSENTRY_CONTEXT_ARGS_OUT, table, 0x%xU));\n", (unsigned int)pa);
    if (ra == rb)
        fprintf(body_out, "    POLICY_CALL(wolfsentry_route_table_max_purgeable_routes_set(WOLFSENTRY_CONTEXT_ARGS_OUT, table, %luU));\n", (unsigned long)ra);
    if (ia == ib) {
        fprintf(body_out, "    POLICY_CALL(wolfsentry_route_table_max_purgeable_idle_time_set(WOLFSENTRY_CONTEXT_ARGS_OUT, table, (wolfsentry_time_t)");
        emit_u64(body_out, (uint64_t)ia);
        fprintf(body_out, "));\n");
    }
    return 0;
}

static void emit_default_event(WOLFSENTRY_CONTEXT_ARGS_IN)
{
    const struct wolfsentry_event *event = wolfsentry->routes->default_event;
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    if (event != NULL) {
        fprintf(body_out, "    POLICY_CALL(wolfsentry_route_table_set_default_event(WOLFSENTRY_CONTEXT_ARGS_OUT, table, ");
        emit_string(body_out, event->label, event->label_len);
        fprintf(body_out, ", %d));\n", (int)event->label_len);
    }
}

static int emit_events(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_context *other,
                       const struct wolfsentry_eventconfig *a0, const struct wolfsentry_eventconfig *b0)
{
    static const struct {
        wolfsentry_action_type_t type;
        const char *name;
    } lists[] = {
        { WOLFSENTRY_ACTION_TYPE_POST, "WOLFSENTRY_ACTION_TYPE_POST" },
        { WOLFSENTRY_ACTION_TYPE_INSERT, "WOLFSENTRY_ACTION_TYPE_INSERT" },
        { WOLFSENTRY_ACTION_TYPE_MATCH, "WOLFSENTRY_ACTION_TYPE_MATCH" },
        { WOLFSENTRY_ACTION_TYPE_UPDATE, "WOLFSENTRY_ACTION_TYPE_UPDATE" },
        { WOLFSENTRY_ACTION_TYPE_DELETE, "WOLFSENTRY_ACTION_TYPE_DELETE" },
        { WOLFSENTRY_ACTION_TYPE_DECISION, "WOLFSENTRY_ACTION_TYPE_DECISION" }
    };
    struct wolfsentry_cursor cursor;
    struct wolfsentry_table_ent_header *ent;
    struct wolfsentry_event *event;
    struct wolfsentry_eventconfig a, b;
    struct wolfsentry_action_list_ent *action_cursor = NULL;
    const char *action_label = NULL;
    int action_label_len = 0;
    wolfsentry_errcode_t ret;
    size_t i;

    if (wolfsentry_table_cursor_init(WOLFSENTRY_CONTEXT_ARGS_OUT, &cursor) < 0)
        return -1;
    wolfsentry_table_cursor_seek_to_head(&wolfsentry->events->header, &cursor);
    for (ent = wolfsentry_table_cursor_current(&cursor); ent != NULL; ent = wolfsentry_table_cursor_next(&cursor)) {
        event = (struct wolfsentry_event *)ent;
        if (event->config != NULL) {
            if ((wolfsentry_event_get_config(WOLFSENTRY_CONTEXT_ARGS_OUT, event->label, event->label_len, &a) < 0) ||
                (wolfsentry_event_get_config(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), event->label, event->label_len, &b) < 0))
            {
                return -1;
            }
            fprintf(body_out, "    config = initial_config;\n");
            emit_config_fields(&a, &b, a0, b0);
        }
        fprintf(body_out, "    POLICY_CALL(wolfsentry_event_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, ");
        emit_string(body_out, event->label, event->label_len);
        fprintf(body_out, ", %d, %u, %s, WOLFSENTRY_EVENT_FLAG_NONE, &id));\n",
                (int)event->label_len, (unsigned int)event->priority,
                (event->config != NULL) ? "&config" : "NULL");
    }

    wolfsentry_table_cursor_seek_to_head(&wolfsentry->events->header, &cursor);
    for (ent = wolfsentry_table_cursor_current(&cursor); ent != NULL; ent = wolfsentry_table_cursor_next(&cursor)) {
        event = (struct wolfsentry_event *)ent;
        if (event->aux_event != NULL) {
            fprintf(body_out, "    POLICY_CALL(wolfsentry_event_set_aux_event(WOLFSENTRY_CONTEXT_ARGS_OUT, ");
            emit_string(body_out, event->label, event->label_len);
            fprintf(body_out, ", %d, ", (int)event->label_len);
            emit_string(body_out, event->aux_event->label, event->aux_event->label_len);
            fprintf(body_out, ", %d));\n", (int)event->aux_event->label_len);
        }
        for (i = 0; i < sizeof lists / sizeof lists[0]; ++i) {
            ret = wolfsentry_event_action_list_start(WOLFSENTRY_CONTEXT_ARGS_OUT, event->label, event->label_len, lists[i].type, &action_cursor);
            if (WOLFSENTRY_ERROR_CODE_IS(ret, ITEM_NOT_FOUND))
                continue;
            if (ret < 0)
                return -1;
            while (wolfsentry_event_action_list_next(WOLFSENTRY_CONTEXT_ARGS_OUT, &action_cursor, &action_label, &action_label_len) >= 0) {
                fprintf(body_out, "    POLICY_CALL(wolfsentry_event_action_append(WOLFSENTRY_CONTEXT_ARGS_OUT, ");
                emit_string(body_out, event->label, event->label_len);
                fprintf(body_out, ", %d, %s, ", (int)event->label_len, lists[i].name);
                emit_string(body_out, action_label, (size_t)action_label_len);
                fprintf(body_out, ", %d));\n", action_label_len);
            }
            if (wolfsentry_event_action_list_done(WOLFSENTRY_CONTEXT_ARGS_OUT, &action_cursor) < 0)
                return -1;
        }
    }
    return 0;
}

static void emit_endpoint(const char *name, const struct wolfsentry_route_endpoint *e, const byte *addr)
{
    unsigned int n = emit_bytes(addr, WOLFSENTRY_BITS_TO_BYTES(e->addr_len));
    fprintf(body_out, "    route.%s.sa_port = %u;\n", name, (unsigned int)e->sa_port);
    fprintf(body_out, "    route.%s.addr_len = %u;\n", name, (unsigned int)e->addr_len);
    fprintf(body_out, "    route.%s.interface = %u;\n", name, (unsigned int)e->interface);
    fprintf(body_out, "    route.%s_address = policy_bytes_%u;\n", name, n);
}

static int emit_routes(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_route_table *table)
{
    struct wolfsentry_cursor *cursor = NULL;
    struct wolfsentry_route *route;
    struct wolfsentry_route_exports exports;
    wolfsentry_errcode_t ret;

    if (wolfsentry_route_table_iterate_start(WOLFSENTRY_CONTEXT_ARGS_OUT, table, &cursor) < 0)
        return -1;
    for (ret = wolfsentry_route_table_iterate_current(table, cursor, &route);
         ret >= 0;
         ret = wolfsentry_route_table_iterate_next(table, cursor, &route))
    {
        if (wolfsentry_route_export(WOLFSENTRY_CONTEXT_ARGS_OUT, route, &exports) < 0)
            break;
        if ((exports.private_data_size != 0) && (exports.private_data != NULL)) {
            fprintf(stderr, "routes with private data are not supported\n");
            break;
        }
        fprintf(body_out, "    memset(&route, 0, sizeof route);\n");
        if (exports.parent_event_label != NULL) {
            fprintf(body_out, "    route.parent_event_label = ");
            emit_string(body_out, exports.parent_event_label, (size_t)exports.parent_event_label_len);
            fprintf(body_out, ";\n    route.parent_event_label_len = %d;\n", exports.parent_event_label_len);
        }
        fprintf(body_out, "    route.flags = 0x%xU;\n", (unsigned int)(exports.flags & ~WOLFSENTRY_ROUTE_INTERNAL_FLAGS));
        fprintf(body_out, "    route.sa_family = %u;\n", (unsigned int)exports.sa_family);
        fprintf(body_out, "    route.sa_proto = %u;\n", (unsigned int)exports.sa_proto);
        emit_endpoint("remote", &exports.remote, exports.remote_address);
        emit_endpoint("local", &exports.local, exports.local_address);
        fprintf(body_out, "    POLICY_CALL(wolfsentry_route_insert_by_exports(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL, &route, &id, &action_results));\n");
    }
    if (wolfsentry_route_table_iterate_end(WOLFSENTRY_CONTEXT_ARGS_OUT, table, &cursor) < 0)
        return -1;
    return WOLFSENTRY_ERROR_CODE_IS(ret, ITEM_NOT_FOUND) ? 0 : -1;
}

static int emit_user_values(WOLFSENTRY_CONTEXT_ARGS_IN, int skip_json)
{
    struct wolfsentry_cursor *cursor = NULL;
    struct wolfsentry_kv_pair_internal *kv_ref;
    const struct wolfsentry_kv_pair *kv;
    wolfsentry_errcode_t ret;
    int failed = 0;
    unsigned int n;
#ifndef WOLFSENTRY_NO_DOUBLE
    uint64_t bits;
#endif

    if (wolfsentry_user_values_iterate_start(WOLFSENTRY_CONTEXT_ARGS_OUT, &cursor) < 0)
        return -1;
    for (ret = wolfsentry_user_values_iterate_current(WOLFSENTRY_CONTEXT_ARGS_OUT, cursor, &kv_ref);
         (ret >= 0) && (! failed);
         ret = wolfsentry_user_values_iterate_next(WOLFSENTRY_CONTEXT_ARGS_OUT, cursor, &kv_ref))
    {
        if (wolfsentry_kv_pair_export(WOLFSENTRY_CONTEXT_ARGS_OUT, kv_ref, &kv) < 0) {
            failed = 1;
            break;
        }
        switch (WOLFSENTRY_KV_TYPE(kv)) {
        case WOLFSENTRY_KV_NULL:
            fprintf(body_out, "    POLICY_CALL(wolfsentry_user_value_store_null(WOLFSENTRY_CONTEXT_ARGS_OUT, ");
            emit_string(body_out, WOLFSENTRY_KV_KEY(kv), (size_t)WOLFSENTRY_KV_KEY_LEN(kv));
            fprintf(body_out, ", %d, 0));\n", (int)WOLFSENTRY_KV_KEY_LEN(kv));
            break;
        case WOLFSENTRY_KV_TRUE:
        case WOLFSENTRY_KV_FALSE:
            fprintf(body_out, "    POLICY_CALL(wolfsentry_user_value_store_bool(WOLFSENTRY_CONTEXT_ARGS_OUT, ");
            emit_string(body_out, WOLFSENTRY_KV_KEY(kv), (size_t)WOLFSENTRY_KV_KEY_LEN(kv));
            fprintf(body_out, ", %d, %s, 0));\n", (int)WOLFSENTRY_KV_KEY_LEN(kv),
                    (WOLFSENTRY_KV_TYPE(kv) == WOLFSENTRY_KV_TRUE) ? "WOLFSENTRY_KV_TRUE" : "WOLFSENTRY_KV_FALSE");
            break;
        case WOLFSENTRY_KV_UINT:
        case WOLFSENTRY_KV_SINT:
            fprintf(body_out, "    POLICY_CALL(wolfsentry_user_value_store_%s(WOLFSENTRY_CONTEXT_ARGS_OUT, ",
                    (WOLFSENTRY_KV_TYPE(kv) == WOLFSENTRY_KV_UINT) ? "uint" : "sint");
            emit_string(body_out, WOLFSENTRY_KV_KEY(kv), (size_t)WOLFSENTRY_KV_KEY_LEN(kv));
            fprintf(body_out, ", %d, %s", (int)WOLFSENTRY_KV_KEY_LEN(kv),
                    (WOLFSENTRY_KV_TYPE(kv) == WOLFSENTRY_KV_UINT) ? "" : "(int64_t)");
            emit_u64(body_out, WOLFSENTRY_KV_V_UINT(kv));
            fprintf(body_out, ", 0));\n");
            break;
#ifndef WOLFSENTRY_NO_DOUBLE
        case WOLFSENTRY_KV_FLOAT:
            fprintf(body_out, "    POLICY_CALL(wolfsentry_user_value_store_double(WOLFSENTRY_CONTEXT_ARGS_OUT, ");
            emit_string(body_out, WOLFSENTRY_KV_KEY(kv), (size_t)WOLFSENTRY_KV_KEY_LEN(kv));
            fprintf(body_out, ", %d, policy_double(", (int)WOLFSENTRY_KV_KEY_LEN(kv));
            memcpy(&bits, &WOLFSENTRY_KV_V_FLOAT(kv), sizeof bits);
            emit_u64(body_out, bits);
            fprintf(body_out, "), 0));\n");
            uses_double = 1;
            break;
#endif
        case WOLFSENTRY_KV_STRING:
            fprintf(body_out, "    POLICY_CALL(wolfsentry_user_value_store_string(WOLFSENTRY_CONTEXT_ARGS_OUT, ");
            emit_string(body_out, WOLFSENTRY_KV_KEY(kv), (size_t)WOLFSENTRY_KV_KEY_LEN(kv));
            fprintf(body_out, ", %d, ", (int)WOLFSENTRY_KV_KEY_LEN(kv));
            emit_string(body_out, WOLFSENTRY_KV_V_STRING(kv), (size_t)WOLFSENTRY_KV_V_STRING_LEN(kv));
            fprintf(body_out, ", %d, 0));\n", (int)WOLFSENTRY_KV_V_STRING_LEN(kv));
            break;
        case WOLFSENTRY_KV_BYTES:
            n = emit_bytes(WOLFSENTRY_KV_V_BYTES(kv), (size_t)WOLFSENTRY_KV_V_BYTES_LEN(kv));
            fprintf(body_out, "    POLICY_CALL(wolfsentry_user_value_store_bytes(WOLFSENTRY_CONTEXT_ARGS_OUT, ");
            emit_string(body_out, WOLFSENTRY_KV_KEY(kv), (size_t)WOLFSENTRY_KV_KEY_LEN(kv));
            fprintf(body_out, ", %d, policy_bytes_%u, %d, 0));\n", (int)WOLFSENTRY_KV_KEY_LEN(kv), n, (int)WOLFSENTRY_KV_V_BYTES_LEN(kv));
            break;
        default:
            if (skip_json && (WOLFSENTRY_KV_TYPE(kv) == WOLFSENTRY_KV_JSON))
                continue;
            fprintf(stderr, "user value \"%.*s\" has an unsupported type\n",
                    (int)WOLFSENTRY_KV_KEY_LEN(kv), WOLFSENTRY_KV_KEY(kv));
            failed = 1;
            continue;
        }
        if (kv->v_type & WOLFSENTRY_KV_FLAG_READONLY) {
            fprintf(body_out, "    POLICY_CALL(wolfsentry_user_value_set_mutability(WOLFSENTRY_CONTEXT_ARGS_OUT, ");
            emit_string(body_out, WOLFSENTRY_KV_KEY(kv), (size_t)WOLFSENTRY_KV_KEY_LEN(kv));
            fprintf(body_out, ", %d, 0));\n", (int)WOLFSENTRY_KV_KEY_LEN(kv));
        }
    }
    if (wolfsentry_user_values_iterate_end(WOLFSENTRY_CONTEXT_ARGS_OUT, &cursor) < 0)
        return -1;
    return failed ? -1 : 0;
}

static int copy_stream(FILE *from, FILE *to)
{
    char buf[4096];
    size_t n;
    rewind(from);
    while ((n = fread(buf, 1, sizeof buf, from)) > 0) {
        if (fwrite(buf, 1, n, to) != n)
            return -1;
    }
    return ferror(from) ? -1 : 0;
}

static unsigned char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf = NULL;
    long size;
    if (f == NULL)
        return NULL;
    if ((fseek(f, 0, SEEK_END) == 0) && ((size = ftell(f)) >= 0) && (fseek(f, 0, SEEK_SET) == 0)) {
        buf = (unsigned char *)malloc((size_t)size + 1U);
        if ((buf != NULL) && (fread(buf, 1, (size_t)size, f) != (size_t)size)) {
            free(buf);
            buf = NULL;
        }
        *len = (size_t)size;
    }
    fclose(f);
    return buf;
}

static int is_c_identifier(const char *s)
{
    static const char *const keywords[] = {
        "alignas", "alignof", "auto", "bool", "break", "case", "char", "const",
        "constexpr", "continue", "default", "do", "double", "else", "enum",
        "extern", "false", "float", "for", "goto", "if", "inline", "int", "long",
        "nullptr", "register", "restrict", "return", "short", "signed", "sizeof",
        "static", "static_assert", "struct", "switch", "thread_local", "true",
        "typedef", "typeof", "typeof_unqual", "union", "unsigned", "void",
        "volatile", "while"
    };
    size_t i;
    if ((s[0] == 0) || ((s[0] >= '0') && (s[0] <= '9')) || (s[0] == '_'))
        return 0;
    for (i = 0; i < sizeof keywords / sizeof keywords[0]; ++i) {
        if (strcmp(s, keywords[i]) == 0)
            return 0;
    }
    for (i = 0; s[i] != 0; ++i) {
        if (! (((s[i] >= 'a') && (s[i] <= 'z')) || ((s[i] >= 'A') && (s[i] <= 'Z')) ||
               ((s[i] >= '0') && (s[i] <= '9')) || (s[i] == '_')))
        {
            return 0;
        }
    }
    return 1;
}

/* sentinel != 0 loads with distinctive defaults; see emit_config_fields() */
static int load_host(
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_context **ctx),
    int sentinel,
    const char **stub_labels,
    int n_stubs,
    const unsigned char *policy,
    size_t policy_len,
    const char *path,
    struct wolfsentry_eventconfig *initial)
{
    struct wolfsentry_eventconfig config;
    struct wolfsentry_route_table *table;
    wolfsentry_action_res_t policy_default;
    wolfsentry_ent_id_t id;
    char err[512];
    int i;

    memset(&config, 0, sizeof config);
    if (sentinel) {
        config.max_connection_count = 0x7ffffff1U;
        config.derogatory_threshold_for_penaltybox = 0xfff1U;
        config.penaltybox_duration = 999983;
        config.route_idle_time_for_purge = 999979;
        config.flags = WOLFSENTRY_EVENTCONFIG_FLAG_DEROGATORY_THRESHOLD_IGNORE_COMMENDABLE |
            WOLFSENTRY_EVENTCONFIG_FLAG_COMMENDABLE_CLEARS_DEROGATORY;
    }
    if (wolfsentry_init(wolfsentry_build_settings, WOLFSENTRY_CONTEXT_ARGS_OUT_EX(NULL), sentinel ? &config : NULL, ctx) < 0) {
        fprintf(stderr, "wolfsentry_init failed\n");
        return -1;
    }
    if (wolfsentry_defaultconfig_get(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*ctx), initial) < 0)
        return -1;
    if (sentinel) {
        if ((wolfsentry_context_lock_mutex(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*ctx)) < 0) ||
            (wolfsentry_route_get_main_table(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*ctx), &table) < 0) ||
            (wolfsentry_route_table_default_policy_get(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*ctx), table, &policy_default) < 0) ||
            (wolfsentry_route_table_default_policy_set(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*ctx), table,
                (policy_default == WOLFSENTRY_ACTION_RES_ACCEPT) ? WOLFSENTRY_ACTION_RES_REJECT : WOLFSENTRY_ACTION_RES_ACCEPT) < 0) ||
            (wolfsentry_route_table_max_purgeable_routes_set(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*ctx), table, 0x7ff1U) < 0) ||
            (wolfsentry_route_table_max_purgeable_idle_time_set(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*ctx), table, 777) < 0) ||
            (wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*ctx)) < 0))
        {
            return -1;
        }
    }
    for (i = 0; i < n_stubs; ++i) {
        if (wolfsentry_action_insert(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*ctx), stub_labels[i], WOLFSENTRY_LENGTH_NULL_TERMINATED,
                                     WOLFSENTRY_ACTION_FLAG_NONE, stub_action, NULL, &id) < 0)
        {
            fprintf(stderr, "cannot register action %s\n", stub_labels[i]);
            return -1;
        }
    }
    if (wolfsentry_config_json_oneshot(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*ctx), policy, policy_len,
                                       WOLFSENTRY_CONFIG_LOAD_FLAG_NONE, err, sizeof err) < 0)
    {
        fprintf(stderr, "%s: %s\n", path, err);
        return -1;
    }
    return 0;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [-a action-label]... [-n function-name] [-j] policy.json\n"
            "  -a  register a placeholder for an application action named in the policy\n"
            "  -n  name of the generated function (default wolfsentry_policy_install)\n"
            "  -j  skip JSON-typed user values instead of failing\n",
            argv0);
}

int main(int argc, char **argv)
{
    const char *stub_labels[MAX_STUB_ACTIONS];
    const char *function_name = "wolfsentry_policy_install";
    const char *path = NULL;
    int n_stubs = 0, skip_json = 0, i, status = 1;
    unsigned char *policy = NULL;
    size_t policy_len = 0;
    struct wolfsentry_context *wolfsentry = NULL;
    struct wolfsentry_context *other = NULL;
    struct wolfsentry_eventconfig a0, b0;
    struct wolfsentry_route_table *table;
    int locked = 0, other_locked = 0;
    WOLFSENTRY_THREAD_HEADER_DECLS

    for (i = 1; i < argc; ++i) {
        if ((strcmp(argv[i], "-a") == 0) && (i + 1 < argc) && (n_stubs < MAX_STUB_ACTIONS))
            stub_labels[n_stubs++] = argv[++i];
        else if ((strcmp(argv[i], "-n") == 0) && (i + 1 < argc))
            function_name = argv[++i];
        else if (strcmp(argv[i], "-j") == 0)
            skip_json = 1;
        else if ((argv[i][0] != '-') && (path == NULL))
            path = argv[i];
        else {
            usage(argv[0]);
            return 2;
        }
    }
    if ((path == NULL) || (! is_c_identifier(function_name))) {
        usage(argv[0]);
        return 2;
    }
    if ((policy = read_file(path, &policy_len)) == NULL) {
        fprintf(stderr, "cannot read %s\n", path);
        return 1;
    }

    if (WOLFSENTRY_THREAD_HEADER_INIT(WOLFSENTRY_THREAD_FLAG_NONE) < 0) {
        free(policy);
        return 1;
    }
    if ((load_host(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(&wolfsentry), 0, stub_labels, n_stubs, policy, policy_len, path, &a0) < 0) ||
        (load_host(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(&other), 1, stub_labels, n_stubs, policy, policy_len, path, &b0) < 0))
    {
        goto out;
    }

    arrays_out = tmpfile();
    body_out = tmpfile();
    if ((arrays_out == NULL) || (body_out == NULL))
        goto out;
    if (wolfsentry_context_lock_shared(WOLFSENTRY_CONTEXT_ARGS_OUT) < 0)
        goto out;
    locked = 1;
    if (wolfsentry_context_lock_shared(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other)) < 0)
        goto out;
    other_locked = 1;
    if (wolfsentry_route_get_main_table(WOLFSENTRY_CONTEXT_ARGS_OUT, &table) < 0)
        goto out;
    if (emit_defaults(WOLFSENTRY_CONTEXT_ARGS_OUT, other, &a0, &b0) < 0) {
        fprintf(stderr, "%s: cannot convert the default configuration\n", path);
        goto out;
    }
    if (emit_events(WOLFSENTRY_CONTEXT_ARGS_OUT, other, &a0, &b0) < 0) {
        fprintf(stderr, "%s: cannot convert the events\n", path);
        goto out;
    }
    emit_default_event(WOLFSENTRY_CONTEXT_ARGS_OUT);
    if (emit_user_values(WOLFSENTRY_CONTEXT_ARGS_OUT, skip_json) < 0) {
        fprintf(stderr, "%s: cannot convert the user values\n", path);
        goto out;
    }
    if (emit_routes(WOLFSENTRY_CONTEXT_ARGS_OUT, table) < 0) {
        fprintf(stderr, "%s: cannot convert the routes\n", path);
        goto out;
    }

    if (ferror(arrays_out) || ferror(body_out))
        goto out;
    printf("/* Generated by wolfsentry-policy-to-c.  Do not edit. */\n\n");
    printf("#ifndef WOLFSENTRY_SOURCE_ID\n#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_USER_BASE\n#endif\n\n");
    printf("#include <wolfsentry/wolfsentry.h>\n\n");
    printf("#define POLICY_U64(hi, lo) (((uint64_t)(hi) << 32U) | (uint64_t)(lo))\n");
    printf("#define POLICY_CALL(x) do { ret = (x); if (ret < 0) goto out; } while (0)\n\n");
    if (uses_double) {
        printf("static double policy_double(uint64_t bits)\n{\n    double value;\n");
        printf("    memcpy(&value, &bits, sizeof value);\n    return value;\n}\n\n");
    }
    fflush(stdout);
    if (copy_stream(arrays_out, stdout) < 0)
        goto out;
    printf("\nwolfsentry_errcode_t %s(WOLFSENTRY_CONTEXT_ARGS_IN);\n\n", function_name);
    printf("wolfsentry_errcode_t %s(WOLFSENTRY_CONTEXT_ARGS_IN)\n{\n", function_name);
    printf("    struct wolfsentry_eventconfig initial_config;\n");
    printf("    struct wolfsentry_eventconfig config;\n");
    printf("    struct wolfsentry_route_exports route;\n");
    printf("    struct wolfsentry_route_table *table = NULL;\n");
    printf("    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;\n");
    printf("    wolfsentry_ent_id_t id;\n");
    printf("    wolfsentry_errcode_t ret;\n");
    printf("    wolfsentry_errcode_t cleanup_ret;\n");
    printf("    int inhibited = 0;\n\n");
    printf("    (void)route;\n");
    printf("    (void)id;\n");
    printf("    ret = wolfsentry_context_lock_mutex(WOLFSENTRY_CONTEXT_ARGS_OUT);\n");
    printf("    if (ret < 0)\n        return ret;\n");
    printf("    POLICY_CALL(wolfsentry_defaultconfig_get(WOLFSENTRY_CONTEXT_ARGS_OUT, &initial_config));\n");
    printf("    POLICY_CALL(wolfsentry_context_flush(WOLFSENTRY_CONTEXT_ARGS_OUT));\n");
    printf("    POLICY_CALL(wolfsentry_route_get_main_table(WOLFSENTRY_CONTEXT_ARGS_OUT, &table));\n");
    fflush(stdout);
    if (copy_stream(body_out, stdout) < 0)
        goto out;
    printf("    if (inhibited) {\n");
    printf("        inhibited = 0;\n");
    printf("        POLICY_CALL(wolfsentry_context_enable_actions(WOLFSENTRY_CONTEXT_ARGS_OUT));\n");
    printf("        POLICY_CALL(wolfsentry_route_bulk_insert_actions(WOLFSENTRY_CONTEXT_ARGS_OUT, &action_results));\n    }\n");
    printf("\n  out:\n");
    printf("    if (inhibited) {\n");
    printf("        cleanup_ret = wolfsentry_context_enable_actions(WOLFSENTRY_CONTEXT_ARGS_OUT);\n");
    printf("        if (ret >= 0)\n            ret = cleanup_ret;\n    }\n");
    printf("    cleanup_ret = wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT);\n");
    printf("    if (ret >= 0)\n        ret = cleanup_ret;\n");
    printf("    return ret;\n}\n");
    status = (fflush(stdout) == 0) ? 0 : 1;

  out:
    if (other_locked && (wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other)) < 0))
        status = 1;
    if (locked && (wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT) < 0))
        status = 1;
    if ((wolfsentry != NULL) && (wolfsentry_shutdown(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(&wolfsentry)) < 0))
        status = 1;
    if ((other != NULL) && (wolfsentry_shutdown(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(&other)) < 0))
        status = 1;
    if (WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        status = 1;
    if (arrays_out != NULL)
        fclose(arrays_out);
    if (body_out != NULL)
        fclose(body_out);
    free(policy);
    return status;
}
