/*
    SSSD

    IPA Identity Backend Module for sub-domains

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2012 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <errno.h>

#include "util/util.h"
#include "util/strtonum.h"
#include "db/sysdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ipa/ipa_id.h"
#include "providers/ad/ad_id.h"
#include "providers/ipa/ipa_subdomains.h"

struct ipa_get_subdom_acct {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sdap_id_op *op;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    int entry_type;
    const char *filter;
    int filter_type;

    int dp_error;
};

static void ipa_get_subdom_acct_connected(struct tevent_req *subreq);
static void ipa_get_subdom_acct_done(struct tevent_req *subreq);

struct tevent_req *ipa_get_subdom_acct_send(TALLOC_CTX *memctx,
                                            struct tevent_context *ev,
                                            struct sdap_id_ctx *ctx,
                                            struct be_acct_req *ar)
{
    struct tevent_req *req;
    struct ipa_get_subdom_acct *state;
    struct tevent_req *subreq;
    int ret;

    req = tevent_req_create(memctx, &state, struct ipa_get_subdom_acct);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->dp_error = DP_ERR_FATAL;

    state->op = sdap_id_op_create(state, state->ctx->conn->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_id_op_create failed\n"));
        ret = ENOMEM;
        goto fail;
    }

    state->domain = find_subdomain_by_name(state->ctx->be->domain,
                                           ar->domain, true);
    if (state->domain == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("find_subdomain_by_name failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    state->sysdb = state->domain->sysdb;

    state->entry_type = (ar->entry_type & BE_REQ_TYPE_MASK);
    state->filter = ar->filter_value;
    state->filter_type = ar->filter_type;

    switch (state->entry_type) {
        case BE_REQ_USER:
        case BE_REQ_GROUP:
        case BE_REQ_BY_SECID:
        case BE_REQ_USER_AND_GROUP:
            ret = EOK;
            break;
        case BE_REQ_INITGROUPS:
            ret = ENOTSUP;
            DEBUG(SSSDBG_TRACE_FUNC, ("Initgroups requests are not handled " \
                                      "by the IPA provider but are resolved " \
                                      "by the responder directly from the " \
                                      "cache.\n"));
            break;
        default:
            ret = EINVAL;
            DEBUG(SSSDBG_OP_FAILURE, ("Invalid sub-domain request type.\n"));
    }
    if (ret != EOK) goto fail;

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (!subreq) {
        goto fail;
    }
    tevent_req_set_callback(subreq, ipa_get_subdom_acct_connected, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ipa_get_subdom_acct_connected(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_get_subdom_acct *state = tevent_req_data(req,
                                                struct ipa_get_subdom_acct);
    int dp_error = DP_ERR_FATAL;
    int ret;
    char *endptr;
    struct req_input *req_input;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    req_input = talloc(state, struct req_input);
    if (req_input == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc failed.\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }

    switch (state->filter_type) {
        case BE_FILTER_NAME:
            req_input->type = REQ_INP_NAME;
            req_input->inp.name = talloc_strdup(req_input, state->filter);
            if (req_input->inp.name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
                tevent_req_error(req, ENOMEM);
                return;
            }
            break;
        case BE_FILTER_IDNUM:
            req_input->type = REQ_INP_ID;
            req_input->inp.id = strtouint32(state->filter, &endptr, 10);
            if (errno || *endptr || (state->filter == endptr)) {
                tevent_req_error(req, errno ? errno : EINVAL);
                return;
            }
            break;
        case BE_FILTER_SECID:
            req_input->type = REQ_INP_SECID;
            req_input->inp.secid = talloc_strdup(req_input, state->filter);
            if (req_input->inp.secid == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
                tevent_req_error(req, ENOMEM);
                return;
            }
            break;
        default:
            DEBUG(SSSDBG_OP_FAILURE, ("Invalid sub-domain filter type.\n"));
            state->dp_error = dp_error;
            tevent_req_error(req, EINVAL);
            return;
    }

    subreq = ipa_s2n_get_acct_info_send(state,
                                        state->ev,
                                        state->ctx->opts,
                                        state->domain,
                                        sdap_id_op_handle(state->op),
                                        state->entry_type,
                                        req_input);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ipa_get_subdom_acct_done, req);

    return;
}

static void ipa_get_subdom_acct_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_get_subdom_acct *state = tevent_req_data(req,
                                                struct ipa_get_subdom_acct);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = ipa_s2n_get_acct_info_recv(subreq);
    talloc_zfree(subreq);

    ret = sdap_id_op_done(state->op, ret, &dp_error);
    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        subreq = sdap_id_op_connect_send(state->op, state, &ret);
        if (!subreq) {
            tevent_req_error(req, ret);
            return;
        }
        tevent_req_set_callback(subreq, ipa_get_subdom_acct_connected, req);
        return;
    }

    if (ret && ret != ENOENT) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    /* FIXME: do we need some special handling of ENOENT */

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
}

int ipa_get_subdom_acct_recv(struct tevent_req *req, int *dp_error_out)
{
    struct ipa_get_subdom_acct *state = tevent_req_data(req,
                                                struct ipa_get_subdom_acct);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* IPA lookup for server mode. Directly to AD. */
struct ipa_get_ad_acct_state {
    int dp_error;
    struct tevent_context *ev;
    struct ipa_id_ctx *ipa_ctx;
    struct be_req *be_req;
    struct be_acct_req *ar;
    struct sss_domain_info *user_dom;
};

static void ipa_get_ad_acct_ad_part_done(struct tevent_req *subreq);
static void ipa_get_ad_acct_done(struct tevent_req *subreq);
static struct ad_id_ctx *ipa_get_ad_id_ctx(struct ipa_id_ctx *ipa_ctx,
                                           struct sss_domain_info *dom);

struct tevent_req *
ipa_get_ad_acct_send(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct ipa_id_ctx *ipa_ctx,
                     struct be_req *be_req,
                     struct be_acct_req *ar)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ipa_get_ad_acct_state *state;
    struct sdap_domain *sdom;
    struct sdap_id_conn_ctx **clist;
    struct sdap_id_ctx *sdap_id_ctx;;
    struct ad_id_ctx *ad_id_ctx;

    req = tevent_req_create(mem_ctx, &state, struct ipa_get_ad_acct_state);
    if (req == NULL) return NULL;

    state->dp_error = -1;
    state->ev = ev;
    state->ipa_ctx = ipa_ctx;
    state->be_req = be_req;
    state->ar = ar;

    /* This can only be a subdomain request, verify subdomain */
    state->user_dom = find_subdomain_by_name(ipa_ctx->sdap_id_ctx->be->domain,
                                             ar->domain, true);
    if (state->user_dom == NULL) {
        ret = EINVAL;
        goto fail;
    }

    /* Let's see if this subdomain has a ad_id_ctx */
    ad_id_ctx = ipa_get_ad_id_ctx(ipa_ctx, state->user_dom);
    if (ad_id_ctx == NULL) {
        ret = EINVAL;
        goto fail;
    }
    sdap_id_ctx = ad_id_ctx->sdap_id_ctx;

    /* Currently only LDAP port for AD is used because POSIX
     * attributes are not replicated to GC by default
     */
    clist = talloc_zero_array(req, struct sdap_id_conn_ctx *, 2);
    if (clist == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    clist[0] = ad_id_ctx->ldap_ctx;
    clist[1] = NULL;

    /* Now we already need ad_id_ctx in particular sdap_id_conn_ctx */
    sdom = sdap_domain_get(sdap_id_ctx->opts, state->user_dom);
    if (sdom == NULL) {
        ret = EIO;
        goto fail;
    }

    subreq = ad_handle_acct_info_send(req, be_req, ar, sdap_id_ctx,
                                      sdom, clist);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, ipa_get_ad_acct_ad_part_done, req);
    return req;

fail:
    state->dp_error = DP_ERR_FATAL;
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static struct ad_id_ctx *
ipa_get_ad_id_ctx(struct ipa_id_ctx *ipa_ctx,
                  struct sss_domain_info *dom)
{
    struct ipa_ad_server_ctx *iter;

    DLIST_FOR_EACH(iter, ipa_ctx->server_mode->trusts) {
        if (iter->dom == dom) break;
    }

    return (iter) ? iter->ad_id_ctx : NULL;
}

static void
ipa_get_ad_acct_ad_part_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_get_ad_acct_state *state = tevent_req_data(req,
                                                struct ipa_get_ad_acct_state);
    errno_t ret;

    ret = ad_handle_acct_info_recv(subreq, &state->dp_error, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("AD lookup failed: %d\n", ret));
        tevent_req_error(req, ret);
        return;
    }

    if ((state->ar->entry_type & BE_REQ_TYPE_MASK) != BE_REQ_INITGROUPS) {
        tevent_req_done(req);
        return;
    }

    /* For initgroups request we have to check IPA group memberships of AD
     * users. */
    subreq = ipa_get_ad_memberships_send(state, state->ev, state->ar,
                                         state->ipa_ctx->server_mode,
                                         state->user_dom,
                                         state->ipa_ctx->sdap_id_ctx,
                                         state->ipa_ctx->server_mode->realm);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, ipa_get_ad_acct_done, req);

    return;

fail:
    state->dp_error = DP_ERR_FATAL;
    tevent_req_error(req, ret);
    tevent_req_post(req, state->ev);
    return;
}

static void
ipa_get_ad_acct_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_get_ad_acct_state *state = tevent_req_data(req,
                                                struct ipa_get_ad_acct_state);
    errno_t ret;

    ret = ipa_get_ad_memberships_recv(subreq, &state->dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("IPA external groups lookup failed: %d\n",
                                  ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t
ipa_get_ad_acct_recv(struct tevent_req *req, int *dp_error_out)
{
    struct ipa_get_ad_acct_state *state = tevent_req_data(req,
                                                struct ipa_get_ad_acct_state);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
