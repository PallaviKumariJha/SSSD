/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

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

#include <talloc.h>
#include <tevent.h>
#include <dbus/dbus.h>
#include "sbus/sssd_dbus.h"

#include "util/util.h"
#include "sbus/sbus_client.h"
#include "providers/data_provider.h"
#include "responder/common/responder.h"
#include "responder/ssh/sshsrv_private.h"

struct sss_dp_get_ssh_host_info {
    struct sss_domain_info *dom;

    bool fast_reply;
    const char *name;
    const char *alias;
};

static DBusMessage *
sss_dp_get_ssh_host_msg(void *pvt);

struct tevent_req *
sss_dp_get_ssh_host_send(TALLOC_CTX *mem_ctx,
                         struct resp_ctx *rctx,
                         struct sss_domain_info *dom,
                         bool fast_reply,
                         const char *name,
                         const char *alias)
{
    errno_t ret;
    struct tevent_req *req;
    struct sss_dp_get_ssh_host_info *info;
    struct sss_dp_req_state *state;
    char *key;

    req = tevent_req_create(mem_ctx, &state, struct sss_dp_req_state);
    if (!req) {
        ret = ENOMEM;
        goto error;
    }

    if (!dom) {
        ret = EINVAL;
        goto error;
    }

    info = talloc_zero(state, struct sss_dp_get_ssh_host_info);
    info->fast_reply = fast_reply;
    info->name = name;
    info->alias = alias;
    info->dom = dom;

    if (alias) {
        key = talloc_asprintf(state, "%s:%s@%s", name, alias, dom->name);
    } else {
        key = talloc_asprintf(state, "%s@%s", name, dom->name);
    }
    if (!key) {
        ret = ENOMEM;
        goto error;
    }

    ret = sss_dp_issue_request(state, rctx, key, dom, sss_dp_get_ssh_host_msg,
                               info, req);
    talloc_free(key);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not issue DP request [%d]: %s\n",
               ret, strerror(ret)));
        goto error;
    }

    return req;

error:
    tevent_req_error(req, ret);
    tevent_req_post(req, rctx->ev);
    return req;
}

static DBusMessage *
sss_dp_get_ssh_host_msg(void *pvt)
{
    DBusMessage *msg;
    dbus_bool_t dbret;
    struct sss_dp_get_ssh_host_info *info;
    uint32_t be_type = 0;
    char *filter;

    info = talloc_get_type(pvt, struct sss_dp_get_ssh_host_info);

    if (info->fast_reply) {
        be_type |= BE_REQ_FAST;
    }

    if (info->alias) {
        filter = talloc_asprintf(info, "name=%s:%s", info->name, info->alias);
    } else {
        filter = talloc_asprintf(info, "name=%s", info->name);
    }
    if (!filter) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Out of memory?!\n"));
        return NULL;
    }

    msg = dbus_message_new_method_call(NULL,
                                       DP_PATH,
                                       DP_INTERFACE,
                                       DP_METHOD_HOSTHANDLER);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Out of memory?!\n"));
        talloc_free(filter);
        return NULL;
    }

    /* create the message */
    DEBUG(SSSDBG_TRACE_FUNC,
          ("Creating SSH host request for [%s][%u][%s]\n",
           info->dom->name, be_type, filter));

    dbret = dbus_message_append_args(msg,
                                     DBUS_TYPE_UINT32, &be_type,
                                     DBUS_TYPE_STRING, &filter,
                                     DBUS_TYPE_INVALID);
    talloc_free(filter);
    if (!dbret) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to build message\n"));
        dbus_message_unref(msg);
        return NULL;
    }

    return msg;
}

errno_t
sss_dp_get_ssh_host_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         dbus_uint16_t *dp_err,
                         dbus_uint32_t *dp_ret,
                         char **err_msg)
{
    return sss_dp_req_recv(mem_ctx, req, dp_err, dp_ret, err_msg);
}
