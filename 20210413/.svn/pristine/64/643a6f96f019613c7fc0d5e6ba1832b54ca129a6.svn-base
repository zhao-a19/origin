#ifndef DPDK_FIREWALL_SU_EPAN_H
#define DPDK_FIREWALL_SU_EPAN_H

#include <stdint.h>

#include "epan/epan.h"
#include "su_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

struct su_epan_session_t {
    epan_t *session;
    epan_dissect_t *edt;
    uint64_t pkg_num;

    void (*init)(struct su_epan_session_t *self);

    void (*destroy)(struct su_epan_session_t *self);

    int (*decode)(struct su_epan_session_t *self, const uint8_t *data, uint32_t data_len);
};

extern struct su_epan_session_t *pSuEpanSession;

void find_protocol_name_func(const gchar *table, gpointer handle, gpointer user_data);
int su_epan_set_port(const char *protocol, uint32_t port);


struct su_epan_session_t *su_epan_new(void);
int try_dissect(epan_dissect_t *edt, const uint8_t *raw_data, uint32_t data_len, uint64_t frame_number,
                const struct su_protocol_define_t *protocol, GSList **kv);
void su_epan_destroy(struct su_epan_session_t *self);

#ifdef __cplusplus
}
#endif

#endif //DPDK_FIREWALL_SU_EPAN_H
