/*
 * footprint.c
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

/* Minimal application used by footprint-test to measure linked flash size. */

#include <wolfsentry/wolfsentry.h>
#if defined(FOOTPRINT_JSON)
#include <wolfsentry/wolfsentry_json.h>
#elif defined(FOOTPRINT_CBOR)
#include <wolfsentry/wolfsentry_cbor.h>
#endif

static volatile unsigned char footprint_policy[256];
static volatile int footprint_result;

int main(void)
{
    struct wolfsentry_context *wolfsentry = NULL;
    WOLFSENTRY_SOCKADDR(32) remote;
    WOLFSENTRY_SOCKADDR(32) local;
    wolfsentry_ent_id_t id = 0;
    wolfsentry_route_flags_t inexact = 0;
    wolfsentry_action_res_t res = WOLFSENTRY_ACTION_RES_NONE;
    wolfsentry_errcode_t ret;
#if defined(FOOTPRINT_JSON) || defined(FOOTPRINT_CBOR)
    char err[64];
#endif

    memset(&remote, 0, sizeof remote);
    memset(&local, 0, sizeof local);
    ret = wolfsentry_init(wolfsentry_build_settings, NULL, NULL, &wolfsentry);
#if defined(FOOTPRINT_JSON)
    ret |= wolfsentry_config_json_oneshot(wolfsentry,
        (const unsigned char *)footprint_policy, sizeof footprint_policy,
        WOLFSENTRY_CONFIG_LOAD_FLAG_NONE, err, sizeof err);
#elif defined(FOOTPRINT_CBOR)
    ret |= wolfsentry_config_cbor_oneshot(wolfsentry,
        (const unsigned char *)footprint_policy, sizeof footprint_policy,
        WOLFSENTRY_CONFIG_LOAD_FLAG_NONE, err, sizeof err);
#else
    ret |= wolfsentry_route_insert(wolfsentry, NULL,
        (const struct wolfsentry_sockaddr *)&remote,
        (const struct wolfsentry_sockaddr *)&local,
        WOLFSENTRY_ROUTE_FLAG_NONE, NULL, 0, &id, &res);
#endif
    ret |= wolfsentry_route_event_dispatch(wolfsentry,
        (const struct wolfsentry_sockaddr *)&remote,
        (const struct wolfsentry_sockaddr *)&local,
        WOLFSENTRY_ROUTE_FLAG_NONE, NULL, 0, NULL, &id, &inexact, &res);
    ret |= wolfsentry_shutdown(&wolfsentry);
    footprint_result = ret;
    return 0;
}
