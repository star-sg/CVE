#define _GNU_SOURCE
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/keyctl.h>
#include <linux/unistd.h>
#include <libnftnl/chain.h>
#include <libnftnl/table.h>
#include <libnftnl/rule.h>
#include <libnftnl/set.h>
#include <libnftnl/object.h>
#include <libnftnl/expr.h>
#include <libmnl/libmnl.h>
#include <string.h>

#include "local_netlink.h"
#include "log.h"
#include "setup.h"


/**
 * delete_table(): Delete a netfilter table
 * @nl: socket netlink 
 * @table_name: table name
*/
void delete_table(struct mnl_socket *nl, char *table_name)
{
    struct mnl_nlmsg_batch *batch = NULL;
    struct nlmsghdr *nh = NULL;
    int r = 0;
    int seq = 0;
    char buf[16384] = {0};
    struct nftnl_table *table = NULL;

    assign_to_core(DEF_CORE);

    table = nftnl_table_alloc();
    nftnl_table_set_str(table, NFTNL_TABLE_NAME, table_name);

    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    nh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                     NFT_MSG_DELTABLE, NFPROTO_IPV4,
                                     NLM_F_CREATE, seq++);
    nftnl_table_nlmsg_build_payload(nh, table);
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    r = mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                          mnl_nlmsg_batch_size(batch));
    if (r < 0)
        errout("mnl_socket_sendto");

    return;
}

/**
 * create_table(): Create a netfilter table
 * @nl: netlink socket
 * @table_name: table name
*/
void create_table(struct mnl_socket *nl, char *table_name)
{
    struct mnl_nlmsg_batch *batch = NULL;
    struct nlmsghdr *nh = NULL;
    int r = 0;
    int seq = 0;
    char buf[16384] = {0};
    struct nftnl_table *table = NULL;

    assign_to_core(DEF_CORE);

    table = nftnl_table_alloc();
    nftnl_table_set_str(table, NFTNL_TABLE_NAME, table_name);

    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    nh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                     NFT_MSG_NEWTABLE, NFPROTO_IPV4,
                                     NLM_F_CREATE, seq++);
    nftnl_table_nlmsg_build_payload(nh, table);
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    r = mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                          mnl_nlmsg_batch_size(batch));
    if (r < 0)
        errout("mnl_socket_sendto");

    return;
}

/**
 * create_chain_hook(): create new chain, new rule for enable hooking funtion in netlink filter
 * @nl: netlink socket
 * @table_name: table name
 * @obj_name: object name
*/
void create_chain_hook(struct mnl_socket *nl, char *table_name, char *obj_name)
{
    struct mnl_nlmsg_batch *batch = NULL;
    struct nlmsghdr *nh = NULL;
    int r = 0;
    int seq = 0;
    char buf[16384] = {0};
    struct nftnl_table *table = NULL;

    assign_to_core(DEF_CORE);

    table = nftnl_table_alloc();
    nftnl_table_set_str(table, NFTNL_TABLE_NAME, table_name);

    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    nh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                     NFT_MSG_NEWTABLE, NFPROTO_IPV4,
                                     NLM_F_CREATE, seq++);
    nftnl_table_nlmsg_build_payload(nh, table);
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    r = mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                          mnl_nlmsg_batch_size(batch));
    if (r < 0)
        errout("mnl_socket_sendto");

    return;
}

/**
 * create_obj(): Create a netfilter object
 * @nl: netlink socket
 * @table_name: table name
 * @obj_name: object name
*/
void create_obj(struct mnl_socket *nl, char *table_name, char *obj_name)
{
    struct mnl_nlmsg_batch *batch = NULL;
    struct nlmsghdr *nh = NULL;
    int r = 0;
    int seq = 0;
    char buf[16384] = {0};

    assign_to_core(DEF_CORE);

    /* Create obj1 to table1 */
    struct nftnl_obj *obj = nftnl_obj_alloc();
    nftnl_obj_set_str(obj, NFTNL_OBJ_TABLE, table_name);
    nftnl_obj_set_str(obj, NFTNL_OBJ_NAME, obj_name);
    nftnl_obj_set_u32(obj, NFTNL_OBJ_TYPE, NFT_OBJECT_COUNTER); // NFT_OBJECT_LIMIT NFT_OBJECT_COUNTER

    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    nh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                               NFT_MSG_NEWOBJ, NFPROTO_IPV4, NLM_F_CREATE,
                               seq++);
    nftnl_obj_nlmsg_build_payload(nh, obj);
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    r = mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                          mnl_nlmsg_batch_size(batch));
    if (r < 0)
        errout("mnl_socket_sendto");

    return;
}

/**
 * del_obj(): delete a netfilter object
 * @nl: netlink socket
 * @table_name: table_name
 * @obj_name: object name
*/
void del_obj(struct mnl_socket *nl, char *table_name, char *obj_name)
{
    struct mnl_nlmsg_batch *batch = NULL;
    struct nlmsghdr *nh = NULL;
    int r = 0;
    int seq = 0;
    char buf[16384] = {0};

    assign_to_core(DEF_CORE);

    /* Create obj1 to table1 */
    struct nftnl_obj *obj = nftnl_obj_alloc();
    nftnl_obj_set_str(obj, NFTNL_OBJ_TABLE, table_name);
    nftnl_obj_set_str(obj, NFTNL_OBJ_NAME, obj_name);
    nftnl_obj_set_u32(obj, NFTNL_OBJ_TYPE, NFT_OBJECT_COUNTER); // NFT_OBJECT_LIMIT NFT_OBJECT_COUNTER

    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    nh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                               NFT_MSG_DELOBJ, NFPROTO_IPV4, NLM_F_CREATE,
                               seq++);
    nftnl_obj_nlmsg_build_payload(nh, obj);
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    r = mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                          mnl_nlmsg_batch_size(batch));
    if (r < 0)
        errout("mnl_socket_sendto");

    return;
}

/**
 * get_obj(): get a netfilter object
 * @nl: netlink socket
 * @table_name: table_name
 * @obj_name: object name
*/
void get_obj(char *table_name, char *obj_name)
{
    struct mnl_nlmsg_batch *batch = NULL;
    struct nlmsghdr *nlh = NULL;
    struct mnl_socket *nl = NULL;
    int r = 0, ret=0, portid=0;
    int seq = 0;
    char buf[16384] = {0};
    char recv_buf[2048] = {0};

    assign_to_core(DEF_CORE);

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if(!nl)
		errout("[-] Error at mnl_socket_open()");


    /* Create obj1 to table1 */
    struct nftnl_obj *obj = nftnl_obj_alloc();
    nftnl_obj_set_str(obj, NFTNL_OBJ_TABLE, table_name);
    nftnl_obj_set_str(obj, NFTNL_OBJ_NAME, obj_name);
    nftnl_obj_set_u32(obj, NFTNL_OBJ_TYPE, NFT_OBJECT_COUNTER); // NFT_OBJECT_LIMIT NFT_OBJECT_COUNTER

    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

	nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETOBJ, NFPROTO_IPV4, NLM_F_DUMP | NLM_F_ACK, seq++);
	nftnl_obj_nlmsg_build_payload(nlh, obj);

	if(mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
		errout("[-] Error at mnl_socket_bind()");
		
	portid = mnl_socket_get_portid(nl);

	if(mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		errout("[-] Error at mnl_socket_sendto()");

    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    if (!ret)
        errout("[-] mnl_socket_recvfrom");

    // hexdump(recv_buf, 0x200);
    return;
}


/**
 * create_set(): create a netfilter set
 * @nl: netlink socket
 * @table_name: table_name
 * @set_name: set name
*/
void create_set(struct mnl_socket *nl, char *table_name, char *set_name)
{
    struct mnl_nlmsg_batch *batch = NULL;
    struct nlmsghdr *nh = NULL;
    int r = 0;
    int seq = 0;
    char buf[16384] = {0};
    struct nftnl_table *table = NULL;

    assign_to_core(DEF_CORE);

    /* Create set and add it to table1 */
    struct nftnl_set *set = nftnl_set_alloc();
    nftnl_set_set_str(set, NFTNL_SET_TABLE, table_name);
    nftnl_set_set_str(set, NFTNL_SET_NAME, set_name);
    nftnl_set_set_u32(set, NFTNL_SET_KEY_LEN, 8);
    nftnl_set_set_u32(set, NFTNL_SET_ID, (0xcafe));
    nftnl_set_set_u32(set, NFTNL_SET_FLAGS, NFT_SET_OBJECT); // NFT_SET_TIMEOUT, NFT_SET_ANONYMOUS
    nftnl_set_set_u32(set, NFTNL_SET_OBJ_TYPE, NFT_OBJECT_COUNTER);
    nftnl_set_set_u32(set, NFTNL_SET_KEY_TYPE, 13);
    // nftnl_set_set_u64(set, NFTNL_SET_TIMEOUT, 1500);
    // nftnl_set_set_u32(set, NFTNL_SET_GC_INTERVAL, 2000);
    nftnl_set_set_u32(set, NFTNL_SET_FAMILY, NFPROTO_IPV4);

    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    nh = nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                   NFT_MSG_NEWSET, NFPROTO_IPV4,
                                   NLM_F_CREATE, seq++);
    nftnl_set_nlmsg_build_payload(nh, set);
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    r = mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                          mnl_nlmsg_batch_size(batch));
    if (r < 0)
        errout("mnl_socket_sendto");

    return;
}

/*  */
/**
 * create_table_with_data(): Create a netfilter table with user data
 * @nl: netlink socket
 * @table_name: table_name
 * @data: user data
 * @size: size of data
*/
void create_table_with_data(struct mnl_socket *nl, char *table_name, void *data, size_t size)
{
    struct mnl_nlmsg_batch *batch = NULL;
    struct nlmsghdr *nh = NULL;
    int r = 0;
    int seq = 0;
    char buf[8192] = {0};
    struct nftnl_table *table = NULL;

    assign_to_core(DEF_CORE);

    table = nftnl_table_alloc();
    nftnl_table_set_str(table, NFTNL_TABLE_NAME, table_name);
    nftnl_table_set_data(table, NFTNL_TABLE_USERDATA, data, size);

    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    nh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                     NFT_MSG_NEWTABLE, NFPROTO_IPV4,
                                     NLM_F_CREATE, seq++);
    nftnl_table_nlmsg_build_payload(nh, table);
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    r = mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                          mnl_nlmsg_batch_size(batch));
    if (r < 0)
        errout("mnl_socket_sendto");

    return;
}

/**
 * dump_table(): dummping table information
 * @table_name: table name
*/
char *dump_table(char *table_name)
{
    char buf[8192] = {0};
    uint32_t seq = 0, ret = 0, portid = 0, cfd = 0, sfd = 0;
    uint32_t type = NFTNL_OUTPUT_DEFAULT;
    uint64_t value[0x19];
    struct nftnl_table *table = NULL;
    struct mnl_nlmsg_batch *batch = NULL;
    struct nlmsghdr *nh = NULL;
    char *recv_buf = NULL;
    struct nlmsghdr *nlh = NULL;
    struct mnl_socket *nl = NULL;

    assign_to_core(DEF_CORE);

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if(!nl)
		errout("[-] Error at mnl_socket_open()");

    table = nftnl_table_alloc();
    if (!table){
        errout("[-] nftnl_table_alloc");
    }
    nftnl_table_set_str(table, NFTNL_TABLE_NAME, table_name);

    /*NLM_F_DUMP uses for dumping all tables nf_tables_dump_tables */

	nlh = nftnl_table_nlmsg_build_hdr(buf, NFT_MSG_GETTABLE, NFPROTO_IPV4, NLM_F_ACK, seq++);
	nftnl_table_nlmsg_build_payload(nlh, table);

	if(mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
		errout("[-] Error at mnl_socket_bind()");
		
	portid = mnl_socket_get_portid(nl);

	if(mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		errout("[-] Error at mnl_socket_sendto()");

    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    if (!ret)
        errout("[-] mnl_socket_recvfrom");

    recv_buf = malloc(0x200);
    memset(recv_buf, 0, 0x200);
    memcpy(recv_buf, &buf, 0x200);

    mnl_socket_close(nl);

    return recv_buf;
}