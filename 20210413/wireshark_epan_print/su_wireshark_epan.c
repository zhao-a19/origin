/*
 * 调用wireshark 2.0.2 解析库完成数据解析
 *
 * Copyright (c) 2017 于明明， All rights reserved.
 *
 */

#define WS_MSVC_NORETURN

//#include <gperftools/profiler.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "glib.h"
#include "epan/epan.h"
#include "epan/prefs.h"
#include "epan/epan_dissect.h"
#include "epan/addr_resolv.h"
#include "epan/packet.h"
#include "epan/print.h"
#include "wsutil/plugins.h"
#include "wsutil/privileges.h"
#include "su_wireshark_epan.h"
#include "su_wireshark_print.h"
#include "su_comm.h"

struct protocol_name_search {
    gchar *searched_name;
    dissector_handle_t  matched_handle;
    guint nb_match;
};

typedef struct protocol_name_search *protocol_name_search_t;

void find_protocol_name_func(const gchar *table, gpointer handle, gpointer user_data)
{
    int proto_id;
    const gchar  *protocol_filter_name;
    protocol_name_search_t  search_info;

    g_assert(handle);

    search_info = (protocol_name_search_t)user_data;

    proto_id = dissector_handle_get_protocol_index((dissector_handle_t)handle);
    if (proto_id != -1) {

        protocol_filter_name = proto_get_protocol_filter_name(proto_id);

        g_assert(protocol_filter_name != NULL);

        if (strcmp(protocol_filter_name, search_info->searched_name) == 0) {

            if (search_info->nb_match == 0) {

                search_info->matched_handle = (dissector_handle_t)handle;
            }

            search_info->nb_match++;
        }
    }
}



int try_dissect(epan_dissect_t *edt, const uint8_t *raw_data, uint32_t data_len, uint64_t frame_number,
                const struct su_protocol_define_t *protocol, GSList **kv)
{
    struct wtap_pkthdr phdr;
    frame_data fdata;
    int ret = -1;
    gchar *buf = NULL;


    memset(&phdr, 0, sizeof(struct wtap_pkthdr));
    frame_data_init(&fdata, frame_number, &phdr, 0, 0);

    fdata.pkt_len  = data_len;
    fdata.cap_len  = data_len;

    fdata.lnk_t = WTAP_ENCAP_ETHERNET;

    epan_dissect_run(edt, 0, &phdr, tvb_new_real_data(raw_data, data_len, data_len), &fdata, NULL);

    //write_pdml_proto_tree(edt, stdout);

    ret = write_pdml_proto_tree_level(edt, buf, protocol, kv);

    frame_data_destroy(&fdata);
    wtap_phdr_cleanup(&phdr);

    return ret;
}

static void su_epan_init(struct su_epan_session_t *self)
{
    char *gpf_path, *pf_path;
    int  gpf_open_errno, gpf_read_errno;
    int  pf_open_errno, pf_read_errno;

    //ProfilerStart("w.prof");
    init_process_policies();

    /* Register all the plugin types we have. */
    epan_register_plugin_types(); /* Types known to libwireshark */
    wtap_register_plugin_types(); /* Types known to libwiretap */

    /* Scan for plugins.  This does *not* call their registration routines;
       that's done later. */
    scan_plugins();


    /* Register all libwiretap plugin modules. */
    register_all_wiretap_modules();

    epan_init(register_all_protocols, register_all_protocol_handoffs, NULL, NULL);

    read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
               &pf_open_errno, &pf_read_errno, &pf_path);

    disable_name_resolution();
    self->session = epan_new();
    self->edt = epan_dissect_new(self->session, TRUE, TRUE);


}

void su_epan_destroy(struct su_epan_session_t *self)
{

    epan_dissect_free(self->edt);
    epan_free(self->session);
    //ProfilerStop();
    epan_cleanup();
}

int su_epan_set_port(const char *protocol, uint32_t port)
{
    guint32 selector = port;
    gchar   *table_name = "tcp.port";
    gchar   *dissector_str = (gchar *)protocol;

    dissector_table_t   table_matching;
    dissector_handle_t  dissector_matching;
    struct protocol_name_search   user_protocol_name;

    table_matching = find_dissector_table(table_name);
    if (!table_matching) {
        printf("Error: Set epan dissector failed\n");
        goto err;
    }

    user_protocol_name.nb_match = 0;
    user_protocol_name.searched_name = dissector_str;
    user_protocol_name.matched_handle = NULL;

    dissector_table_foreach_handle(table_name, find_protocol_name_func, &user_protocol_name);

    if (user_protocol_name.nb_match != 0) {
        dissector_matching = user_protocol_name.matched_handle;
    }

    if ( proto_get_id_by_filter_name(dissector_str) == -1 ) {
        printf("Error: Unkown protocol %s\n", dissector_str);
        goto err;
    }

    dissector_change_uint(table_name, selector, dissector_matching);


    return 0;
err:
    return -1;
}


struct su_epan_session_t *su_epan_new(void)
{
    struct su_epan_session_t *self = (struct su_epan_session_t *)malloc(sizeof(struct su_epan_session_t));

    self->init = su_epan_init;
    self->destroy = su_epan_destroy;

    self->init(self);

    su_wireshark_print_init();

    return self;
}

struct su_epan_session_t *pSuEpanSession = NULL;
