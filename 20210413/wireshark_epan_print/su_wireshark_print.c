/*****************************************************************************
*                                                                            *
*  Copyright (C) 2017 www.anmit.com All rights reserved.                     *
*                                                                            *
*  @file     wireshark_print                                                 *
*  @brief    自定义的wireshark输出                                             *
*  基于wireshark2.0.2版本修改.                                                 *
*                                                                            *
*  @author   yumm                                                            *
*  @email    yumm@anmit.com                                                  *
*  @version  0.1                                                             *
*  @date     2017/10/24                                                      *
*                                                                            *
*----------------------------------------------------------------------------*
*  Remark         : Description                                              *
*----------------------------------------------------------------------------*
*  Change History :                                                          *
*  <Date>     | <Version> | <Author>       | <Description>                   *
*----------------------------------------------------------------------------*
*  2017/10/24  | 0.1.0     | 于明明          | 添加注释                        *
*----------------------------------------------------------------------------*
*                                                                            *
*****************************************************************************/

#define WS_MSVC_NORETURN

#include <stdio.h>
#include <glib.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include "epan/epan.h"
#include "epan/expert.h"
#include "epan/ftypes/ftypes-int.h"

#include "su_wireshark_print.h"
#include "su_comm.h"
#include "su_protocol.h"

#ifndef ntohll
#define ntohll(x) \
    ((__uint64_t)((((__uint64_t)(x) & 0xff00000000000000ULL) >> 56) | \
                (((__uint64_t)(x) & 0x00ff000000000000ULL) >> 40) | \
                (((__uint64_t)(x) & 0x0000ff0000000000ULL) >> 24) | \
                (((__uint64_t)(x) & 0x000000ff00000000ULL) >>  8) | \
                (((__uint64_t)(x) & 0x00000000ff000000ULL) <<  8) | \
                (((__uint64_t)(x) & 0x0000000000ff0000ULL) << 24) | \
                (((__uint64_t)(x) & 0x000000000000ff00ULL) << 40) | \
                (((__uint64_t)(x) & 0x00000000000000ffULL) << 56)))
#endif


static int su_proto_data = -1;

static int print_escaped_xml_su(char *buf, const char *unescaped_string);

typedef struct {
    int             level;
    char            *buf;
    const struct su_protocol_define_t      *protocol;
    GSList          **kv;
    int             buf_off;
    GSList          *src_list;
    epan_dissect_t  *edt;
} su_write_pdml_data;

static int su_strcpy(const char *src, char *dst) {
    int i;

    for (i = 0; src[i] != '\0'; i++) {
        dst[i] = src[i];
    }

    dst[i] = '\0';

    return i;
}

static int print_escaped_xml_su(char *buf, const char *unescaped_string)
{
    const char *p;
    char        temp_str[8];
    int off = 0;

    for (p = unescaped_string; *p != '\0'; p++) {
        switch (*p) {
            case '&':
                off += su_strcpy("&amp;", buf + off);
                break;
            case '<':
                off += su_strcpy("&lt;", buf + off);
                break;
            case '>':
                off += su_strcpy("&gt;", buf + off);
                break;
            case '"':
                off += su_strcpy("&quot;", buf + off);
                break;
            case '\'':
                off += su_strcpy("&#x27;", buf + off);
                break;
            default:
                if (g_ascii_isprint(*p)) {
                    buf[off++] = *p;
                } else {
                    g_snprintf(temp_str, sizeof(temp_str), "\\x%x", (guint8)*p);
                    off += su_strcpy(temp_str, buf + off);
                }
        }
    }

    buf[off] = '\0';
    return off;
}

static const guint8 *su_get_field_data(GSList *src_list, field_info *fi)
{
    GSList   *src_le;
    tvbuff_t *src_tvb;
    gint      length, tvbuff_length;
    struct data_source *src;

    for (src_le = src_list; src_le != NULL; src_le = src_le->next) {
        src = (struct data_source *)src_le->data;
        src_tvb = get_data_source_tvb(src);
        if (fi->ds_tvb == src_tvb) {
            /*
             * Found it.
             *
             * XXX - a field can have a length that runs past
             * the end of the tvbuff.  Ideally, that should
             * be fixed when adding an item to the protocol
             * tree, but checking the length when doing
             * that could be expensive.  Until we fix that,
             * we'll do the check here.
             */
            tvbuff_length = tvb_captured_length_remaining(src_tvb,
                                                          fi->start);
            if (tvbuff_length < 0) {
                return NULL;
            }
            length = fi->length;
            if (length > tvbuff_length)
                length = tvbuff_length;
            return tvb_get_ptr(src_tvb, fi->start, length);
        }
    }
    g_assert_not_reached();
    return NULL;  /* not found */
}


static int
su_pdml_write_field_hex_value(su_write_pdml_data *pdata, field_info *fi, char *buf)
{
    int           i;
    const guint8 *pd;
    int buf_off = 0;

    if (!fi->ds_tvb)
        return 0;

    if (fi->length > tvb_captured_length_remaining(fi->ds_tvb, fi->start)) {
        buf_off += su_strcpy("field length invalid!", buf + buf_off);
        return buf_off;
    }

    /* Find the data for this field. */
    pd = su_get_field_data(pdata->src_list, fi);

    if (pd) {
        /* Print a simple hex dump */
        switch (fi->length) {
            case 1:
                buf_off += sprintf(buf + buf_off, "%u", *(const uint8_t*)pd);
                break;
            case 2:
                if (pdata->protocol->flag & PROTOCOL_FLAG_BIGENDIAN) {
                    buf_off += sprintf(buf + buf_off, "%u", ntohs(*(const uint16_t *) pd));
                } else {
                    buf_off += sprintf(buf + buf_off, "%u", *(const uint16_t *) pd);
                }
                break;
            case 4:
                if (pdata->protocol->flag & PROTOCOL_FLAG_BIGENDIAN) {
                    buf_off += sprintf(buf + buf_off, "%u", ntohl(*(const uint32_t *) pd));
                } else {
                    buf_off += sprintf(buf + buf_off, "%u", *(const uint32_t *) pd);
                }
                break;
            case 8:
                if (pdata->protocol->flag & PROTOCOL_FLAG_BIGENDIAN) {
                    buf_off += sprintf(buf + buf_off, "%"PRIu64, ntohll(*(const uint64_t *) pd));
                } else {
                    buf_off += sprintf(buf + buf_off, "%"PRIu64, *(const uint64_t *) pd);
                }
                break;
            default:
                for (i = 0 ; i < fi->length && i < 10; i++) {
                    buf_off += sprintf(buf + buf_off, "%02x", pd[i]);
                }

                if (fi->length >= 10) {
                    buf_off += su_strcpy("...", buf + buf_off);
                }
        }
    }

    return buf_off;
}

// add by yumm
/* Write out a tree's data, and any child nodes, as PDML */

static void su_proto_tree_write_node_pdml(proto_node *node, gpointer data)
{
    field_info      *fi    = PNODE_FINFO(node);
    su_write_pdml_data *pdata = (su_write_pdml_data*) data;
    const gchar     *label_ptr;
    //gchar            label_str[ITEM_LABEL_LENGTH];
    gchar            *label_str = g_malloc(4096000);//使用 -v 选项的时候，测试程序会报 段错误
    int              i;
    gboolean         wrap_in_fake_protocol;
    gchar *dfilter_string;
    char *buf = pdata->buf;

    /* dissection with an invisible proto tree? */
    g_assert(fi);

    /* Will wrap up top-level field items inside a fake protocol wrapper to
       preserve the PDML schema */
    wrap_in_fake_protocol =
            (((fi->hfinfo->type != FT_PROTOCOL) ||
              (fi->hfinfo->id == su_proto_data)) &&
             (pdata->level == 0));

    /* Indent to the correct level */
    for (i = -1; i < pdata->level; i++) {
        pdata->buf_off += su_strcpy("  ", buf + pdata->buf_off);
    }

    if (wrap_in_fake_protocol) {
        /* Open fake protocol wrapper */
        pdata->buf_off += su_strcpy("<proto name=\"fake-field-wrapper\">\n", buf + pdata->buf_off);

        /* Indent to increased level before writing out field */
        pdata->level++;
        for (i = -1; i < pdata->level; i++) {
            pdata->buf_off += su_strcpy("  ", buf + pdata->buf_off);
        }
    }

    /* Normal protocols and fields */
    {
        if ((fi->hfinfo->type == FT_PROTOCOL) && (fi->hfinfo->id != proto_expert)) {
            pdata->buf_off += su_strcpy("<proto name=\"", buf + pdata->buf_off);
        } else {
            pdata->buf_off += su_strcpy("<field name=\"", buf + pdata->buf_off);
        }
        pdata->buf_off += print_escaped_xml_su(buf + pdata->buf_off, fi->hfinfo->abbrev);

        if (fi->rep) {
            pdata->buf_off += su_strcpy("\" showname=\"", buf + pdata->buf_off);
            pdata->buf_off += print_escaped_xml_su(buf + pdata->buf_off, fi->rep->representation);
        } else {
            label_ptr = label_str;
            proto_item_fill_label(fi, label_str);
            pdata->buf_off += su_strcpy("\" showname=\"", buf + pdata->buf_off);
            pdata->buf_off += print_escaped_xml_su(buf + pdata->buf_off, label_ptr);
        }

        /* show, value, and unmaskedvalue attributes */
        switch (fi->hfinfo->type)
        {
            case FT_PROTOCOL:
                break;
            case FT_NONE:
                pdata->buf_off += su_strcpy("\" value=\"", buf + pdata->buf_off);
                break;
            default:
                if (pdata->protocol->flag & PROTOCOL_FLAG_FROM_SHOW) {
					dfilter_string = g_malloc(102400);
                    if (fvalue_to_string_repr(&fi->value, FTREPR_DISPLAY, fi->hfinfo->display, dfilter_string) != NULL) {
                        print_escaped_xml_su(label_str, dfilter_string);
                    }
                   	g_free(dfilter_string);
                } else if (fi->length > 0) {
                    pdata->buf_off += su_strcpy("\" value=\"", buf + pdata->buf_off);

                    if (fi->hfinfo->bitmask != 0) {
                        switch (fi->value.ftype->ftype) {
                            case FT_INT8:
                            case FT_INT16:
                            case FT_INT24:
                            case FT_INT32:
                                pdata->buf_off += sprintf(buf + pdata->buf_off, "%X",
                                                          (guint) fvalue_get_sinteger(&fi->value));
                                break;
                            case FT_UINT8:
                            case FT_UINT16:
                            case FT_UINT24:
                            case FT_UINT32:
                            case FT_BOOLEAN:
                                pdata->buf_off += sprintf(buf + pdata->buf_off, "%X", fvalue_get_uinteger(&fi->value));
                                break;
                            case FT_INT40:
                            case FT_INT48:
                            case FT_INT56:
                            case FT_INT64:
                                pdata->buf_off += sprintf(buf + pdata->buf_off, "%"
                                        G_GINT64_MODIFIER
                                        "X", fvalue_get_sinteger64(&fi->value));
                                break;
                            case FT_UINT40:
                            case FT_UINT48:
                            case FT_UINT56:
                            case FT_UINT64:
                                pdata->buf_off += sprintf(buf + pdata->buf_off, "%"
                                        G_GINT64_MODIFIER
                                        "X", fvalue_get_uinteger64(&fi->value));
                                break;
                            default:
                                g_assert_not_reached();
                        }
                        pdata->buf_off += su_strcpy("\" unmaskedvalue=\"", buf + pdata->buf_off);
                        pdata->buf_off += su_pdml_write_field_hex_value(pdata, fi, buf + pdata->buf_off);
                    } else {
                        pdata->buf_off += su_pdml_write_field_hex_value(pdata, fi, buf + pdata->buf_off);
                    }
                }
        }

        if (node->first_child != NULL) {
            pdata->buf_off += su_strcpy("\">\n", buf + pdata->buf_off);
        }
        else if (fi->hfinfo->id == su_proto_data) {
            pdata->buf_off += su_strcpy("\">\n", buf + pdata->buf_off);
        }
        else {
            pdata->buf_off += su_strcpy("\"/>\n", buf + pdata->buf_off);
        }
    }

    /* We always print all levels for PDML. Recurse here. */
    if (node->first_child != NULL) {
        pdata->level++;
        proto_tree_children_foreach(node,
                                    su_proto_tree_write_node_pdml, pdata);
        pdata->level--;
    }

    /* Take back the extra level we added for fake wrapper protocol */
    if (wrap_in_fake_protocol) {
        pdata->level--;
    }

    if (node->first_child != NULL) {
        /* Indent to correct level */
        for (i = -1; i < pdata->level; i++) {
            pdata->buf_off += su_strcpy("  ", buf + pdata->buf_off);
        }
        /* Close pdata->buf_off current element */
        /* Data and expert "protocols" use simple tags */
        if ((fi->hfinfo->id != su_proto_data) && (fi->hfinfo->id != proto_expert)) {
            if (fi->hfinfo->type == FT_PROTOCOL) {
                pdata->buf_off += su_strcpy("</proto>\n", buf + pdata->buf_off);
            }
            else {
                pdata->buf_off += su_strcpy("</field>\n", buf + pdata->buf_off);
            }
        } else {
            pdata->buf_off += su_strcpy("</field>\n", buf + pdata->buf_off);
        }
    }

    /* Close pdata->buf_off fake wrapper protocol */
    if (wrap_in_fake_protocol) {
        pdata->buf_off += su_strcpy("</proto>\n", buf + pdata->buf_off);
    }

	g_free(label_str);
}


static void su_proto_tree_write_node_kv(proto_node *node, gpointer data)
{
    field_info      *fi    = PNODE_FINFO(node);
    su_write_pdml_data *pdata = (su_write_pdml_data*) data;
    gchar            label_str[ITEM_LABEL_LENGTH];
    int              key_index;
    char            *dfilter_string;
    gboolean         wrap_in_fake_protocol;

    /* dissection with an invisible proto tree? */
    g_assert(fi);

    /* Will wrap up top-level field items inside a fake protocol wrapper to
       preserve the PDML schema */
    wrap_in_fake_protocol =
            (((fi->hfinfo->type != FT_PROTOCOL) ||
              (fi->hfinfo->id == su_proto_data)) &&
             (pdata->level == 0));

    print_escaped_xml_su(label_str, fi->hfinfo->abbrev);
    if ((key_index = get_key_index(pdata->protocol, label_str)) >= 0) {
        /* show, value, and unmaskedvalue attributes */
        if (key_index == 1) { //此值为方法，则把方法对应的描述也copy出来
            if (fi->rep) {
                print_escaped_xml_su(label_str, fi->rep->representation);
            }
            else {
                dfilter_string = g_malloc(4096);
                proto_item_fill_label(fi, dfilter_string);
                print_escaped_xml_su(label_str, dfilter_string);
                g_free(dfilter_string);
            }

            dfilter_string = strrchr(label_str, ':');
            if (dfilter_string) {
                dfilter_string += 2;
            } else {
                dfilter_string = label_str;
            }
            pdata->kv[0] = g_slist_append(pdata->kv[0], g_strdup(dfilter_string));
        }

        switch (fi->hfinfo->type) {
            case FT_PROTOCOL:
                break;
            case FT_NONE:
                break;
            default:
                if (pdata->protocol->flag & PROTOCOL_FLAG_FROM_SHOW) {
                    dfilter_string = fvalue_to_string_repr(&fi->value, FTREPR_DISPLAY, fi->hfinfo->display, NULL);
                    if (dfilter_string != NULL) {
                        print_escaped_xml_su(label_str, dfilter_string);
                    }
                    g_free(dfilter_string);
                    pdata->kv[key_index] = g_slist_append(pdata->kv[key_index], g_strdup(label_str));
                } else if (fi->length > 0) {
                    if (fi->hfinfo->bitmask != 0) {
                        switch (fi->value.ftype->ftype) {
                            case FT_INT8:
                            case FT_INT16:
                            case FT_INT24:
                            case FT_INT32:
                                sprintf(label_str, "%X", (guint) fvalue_get_sinteger(&fi->value));
                                break;
                            case FT_UINT8:
                            case FT_UINT16:
                            case FT_UINT24:
                            case FT_UINT32:
                            case FT_BOOLEAN:
                                sprintf(label_str, "%X", fvalue_get_uinteger(&fi->value));
                                break;
                            case FT_INT40:
                            case FT_INT48:
                            case FT_INT56:
                            case FT_INT64:
                                sprintf(label_str, "%"
                                        G_GINT64_MODIFIER
                                        "X", fvalue_get_sinteger64(&fi->value));
                                break;
                            case FT_UINT40:
                            case FT_UINT48:
                            case FT_UINT56:
                            case FT_UINT64:
                                sprintf(label_str, "%"
                                        G_GINT64_MODIFIER
                                        "X", fvalue_get_uinteger64(&fi->value));
                                break;
                            default:
                                g_assert_not_reached();
                        }
                    } else {
                        su_pdml_write_field_hex_value(pdata, fi, label_str);
                    }
                    pdata->kv[key_index] = g_slist_append(pdata->kv[key_index], g_strdup(label_str));
                }

                break;
        }
    }

    /* We always print all levels for PDML. Recurse here. */
    if (node->first_child != NULL) {
        pdata->level++;
        proto_tree_children_foreach(node, su_proto_tree_write_node_kv, pdata);
        pdata->level--;
    }

    /* Take back the extra level we added for fake wrapper protocol */
    if (wrap_in_fake_protocol) {
        pdata->level--;
    }

}

// add by yumm
int write_pdml_proto_tree_level(epan_dissect_t *edt, char *buf, const struct su_protocol_define_t *protocol, GSList **kv)
{
    su_write_pdml_data data;
    proto_node *node;
    proto_node *current;
    int i;

    /* Create the output */
    data.level    = 0;
    data.buf       = buf;
    data.protocol = protocol;
    data.kv = kv;
    data.buf_off    = 0;
    data.src_list = edt->pi.data_src;
    data.edt      = edt;

    node = edt->tree->first_child;
    for (i = 0; i < protocol->level && node != NULL; i++) {
        node = node->next;
    }

    // 解析到第4层的时候，没有内容则为空包
    // 0 为摘要，1位MAC层，2为IP，MAC层，3为TCP，UDP，ICMP层
    if (i < protocol->level-1 && node == NULL) {
        return -2;  // 没有用户层数据
    }

    if (node == NULL) {
        return -1;  // 没有协议数据
    }

    while (node != NULL) {
        current = node;
        node    = current->next;

        su_proto_tree_write_node_kv(current, &data);
    }

    return 0;
}

void su_wireshark_print_init(void) {
    su_proto_data = proto_get_id_by_short_name("Data");
}
