/*
 * policy-to-c-check.c
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

/* Verifies that a policy compiled by wolfsentry-policy-to-c rebuilds the same
 * state as loading the original JSON policy.
 */

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_USER_BASE

#include "src/wolfsentry_internal.h"
#include "wolfsentry/wolfsentry_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_STUB_ACTIONS 64

wolfsentry_errcode_t wolfsentry_policy_install(WOLFSENTRY_CONTEXT_ARGS_IN);

#define CHECK(cond) do { if (! (cond)) { fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #cond); return -1; } } while (0)

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

static int same_config(const struct wolfsentry_eventconfig *a, const struct wolfsentry_eventconfig *b)
{
    return (a->route_private_data_size == b->route_private_data_size) &&
        (a->route_private_data_alignment == b->route_private_data_alignment) &&
        (a->max_connection_count == b->max_connection_count) &&
        (a->derogatory_threshold_for_penaltybox == b->derogatory_threshold_for_penaltybox) &&
        (a->penaltybox_duration == b->penaltybox_duration) &&
        (a->route_idle_time_for_purge == b->route_idle_time_for_purge) &&
        (a->flags == b->flags) &&
        (a->route_flags_to_add_on_insert == b->route_flags_to_add_on_insert) &&
        (a->route_flags_to_clear_on_insert == b->route_flags_to_clear_on_insert) &&
        (a->action_res_filter_bits_set == b->action_res_filter_bits_set) &&
        (a->action_res_filter_bits_unset == b->action_res_filter_bits_unset) &&
        (a->action_res_bits_to_add == b->action_res_bits_to_add) &&
        (a->action_res_bits_to_clear == b->action_res_bits_to_clear);
}

static int compare_defaults(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_context *other)
{
    struct wolfsentry_eventconfig a, b;
    struct wolfsentry_route_table *ta, *tb;
    wolfsentry_action_res_t pa, pb;
    wolfsentry_hitcount_t ra, rb;
    wolfsentry_time_t ia, ib;
    const struct wolfsentry_event *da, *db;

    CHECK(wolfsentry_defaultconfig_get(WOLFSENTRY_CONTEXT_ARGS_OUT, &a) >= 0);
    CHECK(wolfsentry_defaultconfig_get(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), &b) >= 0);
    CHECK(same_config(&a, &b));
    CHECK(wolfsentry_route_get_main_table(WOLFSENTRY_CONTEXT_ARGS_OUT, &ta) >= 0);
    CHECK(wolfsentry_route_get_main_table(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), &tb) >= 0);
    CHECK(wolfsentry_route_table_default_policy_get(WOLFSENTRY_CONTEXT_ARGS_OUT, ta, &pa) >= 0);
    CHECK(wolfsentry_route_table_default_policy_get(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), tb, &pb) >= 0);
    CHECK(pa == pb);
    CHECK(wolfsentry_route_table_max_purgeable_routes_get(WOLFSENTRY_CONTEXT_ARGS_OUT, ta, &ra) >= 0);
    CHECK(wolfsentry_route_table_max_purgeable_routes_get(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), tb, &rb) >= 0);
    CHECK(ra == rb);
    CHECK(wolfsentry_route_table_max_purgeable_idle_time_get(WOLFSENTRY_CONTEXT_ARGS_OUT, ta, &ia) >= 0);
    CHECK(wolfsentry_route_table_max_purgeable_idle_time_get(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), tb, &ib) >= 0);
    CHECK(ia == ib);
    da = ta->default_event;
    db = tb->default_event;
    CHECK((da == NULL) == (db == NULL));
    if (da != NULL)
        CHECK((da->label_len == db->label_len) && (memcmp(da->label, db->label, da->label_len) == 0));
    return 0;
}

static int compare_action_lists(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_context *other, const struct wolfsentry_event *event)
{
    wolfsentry_action_type_t type;
    struct wolfsentry_action_list_ent *ca = NULL, *cb = NULL;
    const char *la = NULL, *lb = NULL;
    int lla = 0, llb = 0;
    wolfsentry_errcode_t ea, eb;

    for (type = WOLFSENTRY_ACTION_TYPE_POST; type <= WOLFSENTRY_ACTION_TYPE_DECISION; ++type) {
        ea = wolfsentry_event_action_list_start(WOLFSENTRY_CONTEXT_ARGS_OUT, event->label, event->label_len, type, &ca);
        eb = wolfsentry_event_action_list_start(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), event->label, event->label_len, type, &cb);
        CHECK(WOLFSENTRY_ERROR_DECODE_ERROR_CODE(ea) == WOLFSENTRY_ERROR_DECODE_ERROR_CODE(eb));
        if (WOLFSENTRY_ERROR_CODE_IS(ea, ITEM_NOT_FOUND))
            continue;
        CHECK(ea >= 0);
        for (;;) {
            ea = wolfsentry_event_action_list_next(WOLFSENTRY_CONTEXT_ARGS_OUT, &ca, &la, &lla);
            eb = wolfsentry_event_action_list_next(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), &cb, &lb, &llb);
            CHECK((ea >= 0) == (eb >= 0));
            if (ea < 0)
                break;
            CHECK((lla == llb) && (memcmp(la, lb, (size_t)lla) == 0));
        }
        CHECK(wolfsentry_event_action_list_done(WOLFSENTRY_CONTEXT_ARGS_OUT, &ca) >= 0);
        CHECK(wolfsentry_event_action_list_done(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), &cb) >= 0);
    }
    return 0;
}

static int compare_events(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_context *other)
{
    struct wolfsentry_cursor ca, cb;
    struct wolfsentry_table_ent_header *a, *b;
    const struct wolfsentry_event *ea, *eb;
    struct wolfsentry_eventconfig xa, xb;

    CHECK(wolfsentry_table_cursor_init(WOLFSENTRY_CONTEXT_ARGS_OUT, &ca) >= 0);
    CHECK(wolfsentry_table_cursor_init(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), &cb) >= 0);
    wolfsentry_table_cursor_seek_to_head(&wolfsentry->events->header, &ca);
    wolfsentry_table_cursor_seek_to_head(&other->events->header, &cb);
    for (a = wolfsentry_table_cursor_current(&ca), b = wolfsentry_table_cursor_current(&cb);
         (a != NULL) || (b != NULL);
         a = wolfsentry_table_cursor_next(&ca), b = wolfsentry_table_cursor_next(&cb))
    {
        CHECK((a != NULL) && (b != NULL));
        ea = (const struct wolfsentry_event *)a;
        eb = (const struct wolfsentry_event *)b;
        CHECK((ea->label_len == eb->label_len) && (memcmp(ea->label, eb->label, ea->label_len) == 0));
        CHECK(ea->priority == eb->priority);
        CHECK(ea->flags == eb->flags);
        CHECK((ea->config == NULL) == (eb->config == NULL));
        if (ea->config != NULL) {
            xa = ea->config->config;
            xb = eb->config->config;
            CHECK(same_config(&xa, &xb));
        }
        CHECK((ea->aux_event == NULL) == (eb->aux_event == NULL));
        if (ea->aux_event != NULL)
            CHECK((ea->aux_event->label_len == eb->aux_event->label_len) &&
                  (memcmp(ea->aux_event->label, eb->aux_event->label, ea->aux_event->label_len) == 0));
        CHECK(compare_action_lists(WOLFSENTRY_CONTEXT_ARGS_OUT, other, ea) == 0);
    }
    return 0;
}

static int same_endpoint(const struct wolfsentry_route_endpoint *a, const byte *aa, const struct wolfsentry_route_endpoint *b, const byte *ba)
{
    return (a->sa_port == b->sa_port) && (a->addr_len == b->addr_len) && (a->interface == b->interface) &&
        (memcmp(aa, ba, WOLFSENTRY_BITS_TO_BYTES(a->addr_len)) == 0);
}

static int compare_routes(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_context *other)
{
    struct wolfsentry_route_table *ta, *tb;
    struct wolfsentry_cursor *ca = NULL, *cb = NULL;
    struct wolfsentry_route *ra, *rb;
    struct wolfsentry_route_exports xa, xb;
    wolfsentry_errcode_t ea, eb;
    int n = 0;

    CHECK(wolfsentry_route_get_main_table(WOLFSENTRY_CONTEXT_ARGS_OUT, &ta) >= 0);
    CHECK(wolfsentry_route_get_main_table(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), &tb) >= 0);
    CHECK(wolfsentry_route_table_iterate_start(WOLFSENTRY_CONTEXT_ARGS_OUT, ta, &ca) >= 0);
    CHECK(wolfsentry_route_table_iterate_start(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), tb, &cb) >= 0);
    for (ea = wolfsentry_route_table_iterate_current(ta, ca, &ra), eb = wolfsentry_route_table_iterate_current(tb, cb, &rb);
         (ea >= 0) || (eb >= 0);
         ea = wolfsentry_route_table_iterate_next(ta, ca, &ra), eb = wolfsentry_route_table_iterate_next(tb, cb, &rb))
    {
        CHECK((ea >= 0) && (eb >= 0));
        CHECK(wolfsentry_route_export(WOLFSENTRY_CONTEXT_ARGS_OUT, ra, &xa) >= 0);
        CHECK(wolfsentry_route_export(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), rb, &xb) >= 0);
        CHECK((xa.parent_event_label == NULL) == (xb.parent_event_label == NULL));
        if (xa.parent_event_label != NULL)
            CHECK((xa.parent_event_label_len == xb.parent_event_label_len) &&
                  (memcmp(xa.parent_event_label, xb.parent_event_label, (size_t)xa.parent_event_label_len) == 0));
        CHECK(xa.flags == xb.flags);
        CHECK((xa.sa_family == xb.sa_family) && (xa.sa_proto == xb.sa_proto));
        CHECK(same_endpoint(&xa.remote, xa.remote_address, &xb.remote, xb.remote_address));
        CHECK(same_endpoint(&xa.local, xa.local_address, &xb.local, xb.local_address));
        ++n;
    }
    CHECK(wolfsentry_route_table_iterate_end(WOLFSENTRY_CONTEXT_ARGS_OUT, ta, &ca) >= 0);
    CHECK(wolfsentry_route_table_iterate_end(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), tb, &cb) >= 0);
    printf("  %d routes match\n", n);
    return 0;
}

static int next_comparable_value(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_cursor *cursor, wolfsentry_errcode_t ret, const struct wolfsentry_kv_pair **kv)
{
    struct wolfsentry_kv_pair_internal *ref;
    for (;;) {
        if (ret == 0)
            ret = wolfsentry_user_values_iterate_current(WOLFSENTRY_CONTEXT_ARGS_OUT, cursor, &ref);
        else
            ret = wolfsentry_user_values_iterate_next(WOLFSENTRY_CONTEXT_ARGS_OUT, cursor, &ref);
        if (ret < 0)
            return 0;
        if (wolfsentry_kv_pair_export(WOLFSENTRY_CONTEXT_ARGS_OUT, ref, kv) < 0)
            return -1;
        if (WOLFSENTRY_KV_TYPE(*kv) != WOLFSENTRY_KV_JSON)
            return 1;
        ret = 1;
    }
}

static int compare_user_values(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_context *other)
{
    struct wolfsentry_cursor *ca = NULL, *cb = NULL;
    const struct wolfsentry_kv_pair *a, *b;
    int ha, hb, first = 1;

    CHECK(wolfsentry_user_values_iterate_start(WOLFSENTRY_CONTEXT_ARGS_OUT, &ca) >= 0);
    CHECK(wolfsentry_user_values_iterate_start(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), &cb) >= 0);
    for (;;) {
        ha = next_comparable_value(WOLFSENTRY_CONTEXT_ARGS_OUT, ca, first ? 0 : 1, &a);
        hb = next_comparable_value(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), cb, first ? 0 : 1, &b);
        first = 0;
        CHECK((ha >= 0) && (hb >= 0) && (ha == hb));
        if (ha == 0)
            break;
        CHECK((WOLFSENTRY_KV_KEY_LEN(a) == WOLFSENTRY_KV_KEY_LEN(b)) &&
              (memcmp(WOLFSENTRY_KV_KEY(a), WOLFSENTRY_KV_KEY(b), (size_t)WOLFSENTRY_KV_KEY_LEN(a)) == 0));
        CHECK(a->v_type == b->v_type);
        switch (WOLFSENTRY_KV_TYPE(a)) {
        case WOLFSENTRY_KV_UINT:
        case WOLFSENTRY_KV_SINT:
            CHECK(WOLFSENTRY_KV_V_UINT(a) == WOLFSENTRY_KV_V_UINT(b));
            break;
#ifndef WOLFSENTRY_NO_DOUBLE
        case WOLFSENTRY_KV_FLOAT:
            CHECK(memcmp(&WOLFSENTRY_KV_V_FLOAT(a), &WOLFSENTRY_KV_V_FLOAT(b), sizeof(double)) == 0);
            break;
#endif
        case WOLFSENTRY_KV_STRING:
            CHECK((WOLFSENTRY_KV_V_STRING_LEN(a) == WOLFSENTRY_KV_V_STRING_LEN(b)) &&
                  (memcmp(WOLFSENTRY_KV_V_STRING(a), WOLFSENTRY_KV_V_STRING(b), WOLFSENTRY_KV_V_STRING_LEN(a)) == 0));
            break;
        case WOLFSENTRY_KV_BYTES:
            CHECK((WOLFSENTRY_KV_V_BYTES_LEN(a) == WOLFSENTRY_KV_V_BYTES_LEN(b)) &&
                  (memcmp(WOLFSENTRY_KV_V_BYTES(a), WOLFSENTRY_KV_V_BYTES(b), WOLFSENTRY_KV_V_BYTES_LEN(a)) == 0));
            break;
        default:
            break;
        }
    }
    CHECK(wolfsentry_user_values_iterate_end(WOLFSENTRY_CONTEXT_ARGS_OUT, &ca) >= 0);
    CHECK(wolfsentry_user_values_iterate_end(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(other), &cb) >= 0);
    return 0;
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

static int add_stub_actions(WOLFSENTRY_CONTEXT_ARGS_IN, int argc, char **argv)
{
    wolfsentry_ent_id_t id;
    int i;
    for (i = 2; i < argc; ++i)
        CHECK(wolfsentry_action_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, argv[i], WOLFSENTRY_LENGTH_NULL_TERMINATED,
                                       WOLFSENTRY_ACTION_FLAG_NONE, stub_action, NULL, &id) >= 0);
    return 0;
}

int main(int argc, char **argv)
{
    struct wolfsentry_context *wolfsentry = NULL;
    struct wolfsentry_context *loaded = NULL;
    unsigned char *policy;
    size_t policy_len = 0;
    struct wolfsentry_eventconfig config;
    char err[512];
    int status = 1;
    wolfsentry_errcode_t ret;
    WOLFSENTRY_THREAD_HEADER_DECLS

    if (argc < 2) {
        fprintf(stderr, "usage: %s policy.json [action-label]...\n", argv[0]);
        return 2;
    }
    if ((policy = read_file(argv[1], &policy_len)) == NULL) {
        fprintf(stderr, "cannot read %s\n", argv[1]);
        return 1;
    }
    if (WOLFSENTRY_THREAD_HEADER_INIT(WOLFSENTRY_THREAD_FLAG_NONE) < 0) {
        free(policy);
        return 1;
    }

    /* non-default initial settings catch fields the installer overwrites */
    memset(&config, 0, sizeof config);
    config.max_connection_count = 17;
    config.derogatory_threshold_for_penaltybox = 9;
    config.penaltybox_duration = 33;
    config.route_idle_time_for_purge = 0;
    config.flags = WOLFSENTRY_EVENTCONFIG_FLAG_COMMENDABLE_CLEARS_DEROGATORY;
    if ((wolfsentry_init(wolfsentry_build_settings, WOLFSENTRY_CONTEXT_ARGS_OUT_EX(NULL), &config, &wolfsentry) < 0) ||
        (wolfsentry_init(wolfsentry_build_settings, WOLFSENTRY_CONTEXT_ARGS_OUT_EX(NULL), &config, &loaded) < 0) ||
        (add_stub_actions(WOLFSENTRY_CONTEXT_ARGS_OUT, argc, argv) < 0) ||
        (add_stub_actions(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(loaded), argc, argv) < 0))
    {
        fprintf(stderr, "setup failed\n");
        goto out;
    }
    /* the installer replaces existing state the same way a default JSON load does */
    if (wolfsentry_user_value_store_uint(WOLFSENTRY_CONTEXT_ARGS_OUT, "stale-value", WOLFSENTRY_LENGTH_NULL_TERMINATED, 1, 0) < 0)
        goto out;
    ret = wolfsentry_policy_install(WOLFSENTRY_CONTEXT_ARGS_OUT);
    if (ret < 0) {
        fprintf(stderr, "generated policy failed to install: " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        goto out;
    }
    if (wolfsentry_config_json_oneshot(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(loaded), policy, policy_len,
                                       WOLFSENTRY_CONFIG_LOAD_FLAG_NONE, err, sizeof err) < 0)
    {
        fprintf(stderr, "%s: %s\n", argv[1], err);
        goto out;
    }
    if ((wolfsentry_context_lock_shared(WOLFSENTRY_CONTEXT_ARGS_OUT) < 0) ||
        (wolfsentry_context_lock_shared(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(loaded)) < 0))
    {
        goto out;
    }
    if ((compare_defaults(WOLFSENTRY_CONTEXT_ARGS_OUT, loaded) == 0) &&
        (compare_events(WOLFSENTRY_CONTEXT_ARGS_OUT, loaded) == 0) &&
        (compare_routes(WOLFSENTRY_CONTEXT_ARGS_OUT, loaded) == 0) &&
        (compare_user_values(WOLFSENTRY_CONTEXT_ARGS_OUT, loaded) == 0))
    {
        status = 0;
    }
    if ((wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(loaded)) < 0) ||
        (wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT) < 0))
    {
        status = 1;
    }

  out:
    if ((loaded != NULL) && (wolfsentry_shutdown(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(&loaded)) < 0))
        status = 1;
    if ((wolfsentry != NULL) && (wolfsentry_shutdown(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(&wolfsentry)) < 0))
        status = 1;
    if (WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        status = 1;
    free(policy);
    if (status == 0)
        printf("  %s: compiled policy matches the JSON load\n", argv[1]);
    return status;
}
