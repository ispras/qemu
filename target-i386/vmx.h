#ifndef __VMX_H
#define __VMX_H

#define VMX_VMCS_INVALID_PTR    0xFFFFFFFFFFFFFFFFULL
#define PHYS_ADDR_WIDTH_MASK    0xFFFFFF0000000000ULL

#define MSR_VMX_BASIC                   0x480
#define MSR_VMX_PINBASED_CTLS           0x481
#define MSR_VMX_PROCBASED_CTLS          0x482
#define MSR_VMX_EXIT_CTLS               0x483
#define MSR_VMX_ENTRY_CTLS              0x484
#define MSR_VMX_MISC                    0x485
#define MSR_VMX_CR0_FIXED0              0x486
#define MSR_VMX_CR0_FIXED1              0x487
#define MSR_VMX_CR4_FIXED0              0x488
#define MSR_VMX_CR4_FIXED1              0x489
#define MSR_VMX_VMCS_ENUM               0x48A

//MSR_VMX_BASIC (0x480) x64
//Bit 30:0  - VMCS revision identifier
//Bit 31    - always 0
#define VMX_MSR_VMX_BASIC_VMCS_REVISION_ID 0x123ULL
//Bit 44:32 - size of VMXON region (0 < x <= 4096)
#define VMX_MSR_VMX_BASIC_VMXON_REGION_SIZE (4096ULL << 32)
//Bit 48    - width of physical address for VMX structures:
//1 - 32bits, 0 - 64 bits (always 0 on x64)
#define VMX_MSR_VMX_BASIC_PHY_ADRESS_SIZE (0ULL << 48)
//Bit 49    - support of dual-monitor treatment and SMM
#define VMX_MSR_VMX_BASIC_SMM_SUPPORT (1ULL << 49)
//Bit 53:50 - memory type for VMX structures:
//0 - Uncacheable (UC)
//6 - Write Back (WB)
#define VMX_MSR_VMX_BASIC_MEMORY_TYPE (6ULL << 50)
//Bits 47:45, 63:54 reserved, read as 0
#define VMX_MSR_VMX_BASIC                   ( \
    VMX_MSR_VMX_BASIC_VMCS_REVISION_ID      | \
    VMX_MSR_VMX_BASIC_VMXON_REGION_SIZE     | \
    VMX_MSR_VMX_BASIC_PHY_ADRESS_SIZE       | \
    VMX_MSR_VMX_BASIC_SMM_SUPPORT           | \
    VMX_MSR_VMX_BASIC_MEMORY_TYPE)
    
//MSR_VMX_PINBASED_CTLS (0x481) x64
//Bit 0 - External-interrupt exiting
#define VMX_MSR_VMX_PINBASED_CTLS_0 (1ULL << (32 + 0))
//Bit 3 - NMI exiting
#define VMX_MSR_VMX_PINBASED_CTLS_3 (1ULL << (32 + 3))
//Bit 1, 2, 4 - always 1
#define VMX_MSR_VMX_PINBASED_CTLS_DEFAULT1 0x0000001600000016ULL
#define VMX_MSR_VMX_PINBASED_CTLS       ( \
    VMX_MSR_VMX_PINBASED_CTLS_0         | \
    VMX_MSR_VMX_PINBASED_CTLS_3         | \
    VMX_MSR_VMX_PINBASED_CTLS_DEFAULT1  )
    
//MSR_VMX_PROCBASED_CTLS (0x482) x64
//Bit 2     - Interrupt-window exiting
#define VMX_MSR_VMX_PROCBASED_CTLS_2     (1ULL << (32 + 2))
//Bit 3     - Use TSC offsetting
#define VMX_MSR_VMX_PROCBASED_CTLS_3     (1ULL << (32 + 3))
//Bit 7     - HLT exiting
#define VMX_MSR_VMX_PROCBASED_CTLS_7     (1ULL << (32 + 7))
//Bit 9     - INVLPG exiting
#define VMX_MSR_VMX_PROCBASED_CTLS_9     (1ULL << (32 + 9))
//Bit 10    - MWAIT exiting
#define VMX_MSR_VMX_PROCBASED_CTLS_10    (1ULL << (32 + 10))
//Bit 11    - RDPMC exiting
#define VMX_MSR_VMX_PROCBASED_CTLS_11    (1ULL << (32 + 11))
//Bit 12    - RDTSC exiting
#define VMX_MSR_VMX_PROCBASED_CTLS_12    (1ULL << (32 + 12))
//Bit 19    - CR8-load exiting
#define VMX_MSR_VMX_PROCBASED_CTLS_19    (1ULL << (32 + 19))
//Bit 20    - CR8-store exiting
#define VMX_MSR_VMX_PROCBASED_CTLS_20    (1ULL << (32 + 20))
//Bit 21    - Use TRP shadow
#define VMX_MSR_VMX_PROCBASED_CTLS_21    (1ULL << (32 + 21))
//Bit 23    - MOV-DR exiting
#define VMX_MSR_VMX_PROCBASED_CTLS_23    (1ULL << (32 + 23))
//Bit 24    - Unconditional I/O exiting
#define VMX_MSR_VMX_PROCBASED_CTLS_24    (1ULL << (32 + 24))
//Bit 25    - Use I/O bitmaps
#define VMX_MSR_VMX_PROCBASED_CTLS_25    (1ULL << (32 + 25))
//Bit 28    - Use MSR bitmaps
#define VMX_MSR_VMX_PROCBASED_CTLS_28    (1ULL << (32 + 28))
//Bit 29    - MONITOR exiting
#define VMX_MSR_VMX_PROCBASED_CTLS_29    (1ULL << (32 + 29))
//Bit 30    - PAUSE exiting
#define VMX_MSR_VMX_PROCBASED_CTLS_30    (1ULL << (32 + 30))
//Bit 1, 4-6, 8, 13-16, 26 - always 1
#define VMX_MSR_VMX_PROCBASED_CTLS_DEFAULT1 0x0401E1720401E172ULL
#define VMX_MSR_VMX_PROCBASED_CTLS       ( \
    VMX_MSR_VMX_PROCBASED_CTLS_2         | \
    VMX_MSR_VMX_PROCBASED_CTLS_3         | \
    VMX_MSR_VMX_PROCBASED_CTLS_7         | \
    VMX_MSR_VMX_PROCBASED_CTLS_9         | \
    VMX_MSR_VMX_PROCBASED_CTLS_10        | \
    VMX_MSR_VMX_PROCBASED_CTLS_11        | \
    VMX_MSR_VMX_PROCBASED_CTLS_12        | \
    VMX_MSR_VMX_PROCBASED_CTLS_19        | \
    VMX_MSR_VMX_PROCBASED_CTLS_20        | \
    VMX_MSR_VMX_PROCBASED_CTLS_21        | \
    VMX_MSR_VMX_PROCBASED_CTLS_23        | \
    VMX_MSR_VMX_PROCBASED_CTLS_24        | \
    VMX_MSR_VMX_PROCBASED_CTLS_25        | \
    VMX_MSR_VMX_PROCBASED_CTLS_28        | \
    VMX_MSR_VMX_PROCBASED_CTLS_29        | \
    VMX_MSR_VMX_PROCBASED_CTLS_30        | \
    VMX_MSR_VMX_PROCBASED_CTLS_DEFAULT1  )

//MSR_VMX_EXIT_CTLS (0x483) x64
//Bit 9     - Host address-space size
#define VMX_MSR_VMX_EXIT_CTLS_9     (1ULL << (32 + 9))
//Bit 15    - Acknowledge interrupt on exit
#define VMX_MSR_VMX_EXIT_CTLS_15    (1ULL << (32 + 15))
//Bit 0-8, 10, 11, 13, 14, 16, 17 - always 1
#define VMX_MSR_VMX_EXIT_CTLS_DEFAULT1 0x00036DFF00036DFFULL
#define VMX_MSR_VMX_EXIT_CTLS       ( \
    VMX_MSR_VMX_EXIT_CTLS_9         | \
    VMX_MSR_VMX_EXIT_CTLS_15        | \
    VMX_MSR_VMX_EXIT_CTLS_DEFAULT1  )

//MSR_VMX_ENTRY_CTLS (0x484) x64
//Bit 9     - IA-32e mode guest
#define VMX_MSR_VMX_ENTRY_CTLS_9     (1ULL << (32 + 9))
//Bit 10    - Entry to SMM
#define VMX_MSR_VMX_ENTRY_CTLS_10    (1ULL << (32 + 10))
//Bit 11    - Deactivate dual-monitor treatment
#define VMX_MSR_VMX_ENTRY_CTLS_11    (1ULL << (32 + 11))
//Bit 0-8, 12 - always 1
#define VMX_MSR_VMX_ENTRY_CTLS_DEFAULT1 0x000011FF000011FFULL
#define VMX_MSR_VMX_ENTRY_CTLS       ( \
    VMX_MSR_VMX_ENTRY_CTLS_9         | \
    VMX_MSR_VMX_ENTRY_CTLS_10        | \
    VMX_MSR_VMX_ENTRY_CTLS_11        | \
    VMX_MSR_VMX_ENTRY_CTLS_DEFAULT1  )
    
//MSR_VMX_MISC (0x485) x64
//Bit 8:6   - bitmap of supported activity states
//bit 6 - HLT
//bit 7 - shutdown
//bit 8 - wait-for-SIPI
#define VMX_MSR_VMX_MISC_ACTIVITY_STATES (0b111ULL << 6)
//Bit 24:16 - number of CR3-target values supported (0 <= x <= 512)
#define VMX_MSR_VMX_MISC_CR3_VALUES (4ULL << 16)
//Bit 27:25 - maximum number of saving MSRs (512 * (N + 1))
#define VMX_MSR_VMX_MISC_MAX_MSRS (0ULL << 25)
//Bit 63:32 - MSEG revision identifier
#define VMX_MSR_VMX_MISC_MSEG (0x456ULL << 32)
//Bits 5:0, 15:9, 31:28 reserved, read as 0
#define VMX_MSR_VMX_MISC                ( \
    VMX_MSR_VMX_MISC_ACTIVITY_STATES    | \
    VMX_MSR_VMX_MISC_CR3_VALUES         | \
    VMX_MSR_VMX_MISC_MAX_MSRS           | \
    VMX_MSR_VMX_MISC_MSEG               )

//MSR_VMX_CR0_FIXED0 (0x486) x32/x64 depends on processor mode
#define VMX_MSR_VMX_CR0_FIXED0 0x0000000080000021ULL
//MSR_VMX_CR0_FIXED1 (0x487) x32/x64 depends on processor mode
#define VMX_MSR_VMX_CR0_FIXED1 0xFFFFFFFFFFFFFFFFULL
//MSR_VMX_CR4_FIXED0 (0x488) x32/x64 depends on processor mode
#define VMX_MSR_VMX_CR4_FIXED0 0x0000000000002000ULL
//MSR_VMX_CR4_FIXED1 (0x489) x32/x64 depends on processor mode
#define VMX_MSR_VMX_CR4_FIXED1 0xFFFFFFFFFFFFFFFFULL

//MSR_VMX_VMCS_ENUM (0x48A) x64
//Bit 9:1   - highest index value for VMCS encoding
//Bits 0, 63:10 reserved, read as 0
#define VMX_MSR_VMX_VMCS_ENUM (0x15ULL << 1)

/** Fields encoding **/
// 16-bit fields
// *Guest-State fields (0000_10xx_xxxx_xxx0)
#define GUEST_ES_SELECTOR                       0x00000800
#define GUEST_CS_SELECTOR                       0x00000802
#define GUEST_SS_SELECTOR                       0x00000804
#define GUEST_DS_SELECTOR                       0x00000806
#define GUEST_FS_SELECTOR                       0x00000808
#define GUEST_GS_SELECTOR                       0x0000080A
#define GUEST_LDTR_SELECTOR                     0x0000080C
#define GUEST_TR_SELECTOR                       0x0000080E

// *Host-State fields (0000_11xx_xxxx_xxx0)
#define HOST_ES_SELECTOR                       0x00000C00
#define HOST_CS_SELECTOR                       0x00000C02
#define HOST_SS_SELECTOR                       0x00000C04
#define HOST_DS_SELECTOR                       0x00000C06
#define HOST_FS_SELECTOR                       0x00000C08
#define HOST_GS_SELECTOR                       0x00000C0A
#define HOST_TR_SELECTOR                       0x00000C0C

// 64-bit fields
// *Control fields (0010_00xx_xxxx_xxxA)
#define ADDRESS_OF_IO_BITMAP_A_FULL                         0x00002000
#define ADDRESS_OF_IO_BITMAP_A_HIGH                         0x00002001
#define ADDRESS_OF_IO_BITMAP_B_FULL                         0x00002002
#define ADDRESS_OF_IO_BITMAP_B_HIGH                         0x00002003
#define ADDRESS_OF_MSR_BITMAPS_FULL                         0x00002004 //*1
#define ADDRESS_OF_MSR_BITMAPS_HIGH                         0x00002005 //*1
#define VM_EXIT_MSR_STORE_ADDRESS_FULL                      0x00002006
#define VM_EXIT_MSR_STORE_ADDRESS_HIGH                      0x00002007
#define VM_EXIT_MSR_LOAD_ADDRESS_FULL                       0x00002008
#define VM_EXIT_MSR_LOAD_ADDRESS_HIGH                       0x00002009
#define VM_ENTRY_MSR_LOAD_ADDRESS_FULL                      0x0000200A
#define VM_ENTRY_MSR_LOAD_ADDRESS_HIGH                      0x0000200B
#define EXECUTIVE_VMCS_POINTER_FULL                         0x0000200C
#define EXECUTIVE_VMCS_POINTER_HIGH                         0x0000200D
#define TSC_OFFSET_FULL                                     0x00002010
#define TSC_OFFSET_HIGH                                     0x00002011
#define VIRTUAL_APIC_ADDRESS_FULL                           0x00002012 //*2
#define VIRTUAL_APIC_ADDRESS_HIGH                           0x00002013 //*2

// *Guest-State fields (0010_10xx_xxxx_xxxA)
#define VMCS_LINK_POINTER_FULL                  0x00002800
#define VMCS_LINK_POINTER_HIGH                  0x00002801
#define GUEST_IA32_DEBUGCTL_FULL                0x00002802
#define GUEST_IA32_DEBUGCTL_HIGH                0x00002803

// 32-bit fields
// *Control fields (0100_00xx_xxxx_xxx0)
#define PIN_BASED_VM_EXECUTION_CONTROLS                 0x00004000
#define PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS   0x00004002
#define EXCEPTION_BITMAP                                0x00004004
#define PAGE_FAULT_ERROR_CODE_MASK                      0x00004006
#define PAGE_FAULT_ERROR_CODE_MATCH                     0x00004008
#define CR3_TARGET_COUNT                                0x0000400A
#define VM_EXIT_CONTROLS                                0x0000400C
#define VM_EXIT_MSR_STORE_COUNT                         0x0000400E
#define VM_EXIT_MSR_LOAD_COUNT                          0x00004010
#define VM_ENTRY_CONTROLS                               0x00004012
#define VM_ENTRY_MSR_LOAD_COUNT                         0x00004014
#define VM_ENTRY_INTERRUPTION_INFORMATION               0x00004016
#define VM_ENTRY_EXCEPTION_ERROR_CODE                   0x00004018
#define VM_ENTRY_INSTRUCTION_LENGTH                     0x0000401A
#define TPR_THRESHOLD                                   0x0000401C //*1

// *Read-Only data fields (0100_01xx_xxxx_xxx0)
#define VM_INSTRUCTION_ERROR                0x00004400
#define EXIT_REASON                         0x00004402
#define VM_EXIT_INTERRUPTION_INFORMATION    0x00004404
#define VM_EXIT_INTERRUPTION_ERROR_CODE     0x00004406
#define IDT_VECTORING_INFORMFTION_FIELD     0x00004408
#define IDT_VECTORING_ERROR_CODE            0x0000440A
#define VM_EXIT_INSTRUCTION_LENGTH          0x0000440C
#define VM_EXIT_INSTRUCTION_INFORMATION     0x0000440E

// *Guest-State fields (0100_10xx_xxxx_xxx0)
#define GUEST_ES_LIMIT                      0x00004800
#define GUEST_CS_LIMIT                      0x00004802
#define GUEST_SS_LIMIT                      0x00004804
#define GUEST_DS_LIMIT                      0x00004806
#define GUEST_FS_LIMIT                      0x00004808
#define GUEST_GS_LIMIT                      0x0000480A
#define GUEST_LDTR_LIMIT                    0x0000480C
#define GUEST_TR_LIMIT                      0x0000480E
#define GUEST_GDTR_LIMIT                    0x00004810
#define GUEST_IDTR_LIMIT                    0x00004812
#define GUEST_ES_ACCESS_RIGHTS              0x00004814
#define GUEST_CS_ACCESS_RIGHTS              0x00004816
#define GUEST_SS_ACCESS_RIGHTS              0x00004818
#define GUEST_DS_ACCESS_RIGHTS              0x0000481A
#define GUEST_FS_ACCESS_RIGHTS              0x0000481C
#define GUEST_GS_ACCESS_RIGHTS              0x0000481E
#define GUEST_LDTR_ACCESS_RIGHTS            0x00004820
#define GUEST_TR_ACCESS_RIGHTS              0x00004822
#define GUEST_INTERRUPTIBILITY_STATE        0x00004824
#define GUEST_ACTIVITY_STATE                0x00004826
#define GUEST_IA32_SYSENTER_CS              0x0000482A

// *Host-State fields (0100_11xx_xxxx_xxx0)
#define HOST_IA32_SYSENTER_CS               0x00004C00

// natural-width fields
// *Control fields (0110_00xx_xxxx_xxx0)
#define CR0_GUEST_HOST_MASK     0x00006000
#define CR4_GUEST_HOST_MASK     0x00006002
#define CR0_READ_SHADOW         0x00006004
#define CR4_READ_SHADOW         0x00006006
#define CR3_TARGET_VALUE_0      0x00006008
#define CR3_TARGET_VALUE_1      0x0000600A
#define CR3_TARGET_VALUE_2      0x0000600C
#define CR3_TARGET_VALUE_3      0x0000600E

// *Read-Only data fields (0110_01xx_xxxx_xxx0)
#define EXIT_QUALIFICATION      0x00006400
#define IO_RCX                  0x00006402
#define IO_RSI                  0x00006404
#define IO_RDI                  0x00006406
#define IO_RIP                  0x00006408
#define GUEST_LINEAR_ADDRESS    0x0000640A

// *Guest-State fields (0110_10xx_xxxx_xxx0)
#define GUEST_CR0                           0x00006800
#define GUEST_CR3                           0x00006802
#define GUEST_CR4                           0x00006804
#define GUEST_ES_BASE                       0x00006806
#define GUEST_CS_BASE                       0x00006808
#define GUEST_SS_BASE                       0x0000680A
#define GUEST_DS_BASE                       0x0000680C
#define GUEST_FS_BASE                       0x0000680E
#define GUEST_GS_BASE                       0x00006810
#define GUEST_LDTR_BASE                     0x00006812
#define GUEST_TR_BASE                       0x00006814
#define GUEST_GDTR_BASE                     0x00006816
#define GUEST_IDTR_BASE                     0x00006818
#define GUEST_DR7                           0x0000681A
#define GUEST_RSP                           0x0000681C
#define GUEST_RIP                           0x0000681E
#define GUEST_RFLAGS                        0x00006820
#define GUEST_PENDING_DEBUG_EXCEPTIONS      0x00006822
#define GUEST_IA32_SYSENTER_ESP             0x00006824
#define GUEST_IA32_SYSENTER_EIP             0x00006826

// *Host-State fields (0110_11xx_xxxx_xxx0)
#define HOST_CR0                    0x00006C00
#define HOST_CR3                    0x00006C02
#define HOST_CR4                    0x00006C04
#define HOST_FS_BASE                0x00006C06
#define HOST_GS_BASE                0x00006C08
#define HOST_TR_BASE                0x00006C0A
#define HOST_GDTR_BASE              0x00006C0C
#define HOST_IDTR_BASE              0x00006C0E
#define HOST_IA32_SYSENTER_ESP      0x00006C10
#define HOST_IA32_SYSENTER_EIP      0x00006C12
#define HOST_RSP                    0x00006C14
#define HOST_RIP                    0x00006C16

/** Basic exit reasons **/
#define VMX_EXIT_EXCEPTION_NMI          0
#define VMX_EXIT_EXCEPTION  VMX_EXIT_EXCEPTION_NMI | 0x100
#define VMX_EXIT_NMI        VMX_EXIT_EXCEPTION_NMI | 0x200
#define VMX_EXIT_EXTERNAL_INTERRUPT     1
#define VMX_EXIT_TRIPLE_FAULT           2
#define VMX_EXIT_INIT                   3
#define VMX_EXIT_SIPI                   4
#define VMX_EXIT_IO_SMI                 5
#define VMX_EXIT_OTHER_SMI              6
#define VMX_EXIT_INTERRUPT_WINDOW       7
#define VMX_EXIT_TASK_SWITCH            9
#define VMX_EXIT_CPUID                  10
#define VMX_EXIT_HLT                    12
#define VMX_EXIT_INVD                   13
#define VMX_EXIT_INVLPG                 14
#define VMX_EXIT_RDPMC                  15
#define VMX_EXIT_RDTSC                  16
#define VMX_EXIT_RSM                    17
#define VMX_EXIT_VMCALL                 18
#define VMX_EXIT_VMCLEAR                19
#define VMX_EXIT_VMLAUNCH               20
#define VMX_EXIT_VMPTRLD                21
#define VMX_EXIT_VMPTRST                22
#define VMX_EXIT_VMREAD                 23
#define VMX_EXIT_VMRESUME               24
#define VMX_EXIT_VMWRITE                25
#define VMX_EXIT_VMXOFF                 26
#define VMX_EXIT_VMXON                  27
#define VMX_EXIT_CR_ACCESS              28
#define VMX_EXIT_CLTS           VMX_EXIT_CR_ACCESS | 0x100
#define VMX_EXIT_LMSW           VMX_EXIT_CR_ACCESS | 0x200
#define VMX_EXIT_MOV_FROM_CR3   VMX_EXIT_CR_ACCESS | 0x400
#define VMX_EXIT_MOV_FROM_CR8   VMX_EXIT_CR_ACCESS | 0x800
#define VMX_EXIT_MOV_TO_CR0     VMX_EXIT_CR_ACCESS | 0x1000
#define VMX_EXIT_MOV_TO_CR3     VMX_EXIT_CR_ACCESS | 0x2000
#define VMX_EXIT_MOV_TO_CR4     VMX_EXIT_CR_ACCESS | 0x4000
#define VMX_EXIT_MOV_TO_CR8     VMX_EXIT_CR_ACCESS | 0x8000
#define VMX_EXIT_MOV_DR                 29
#define VMX_EXIT_IO_INSTRUCTION         30
#define VMX_EXIT_IN             VMX_EXIT_IO_INSTRUCTION | 0x100
#define VMX_EXIT_OUT            VMX_EXIT_IO_INSTRUCTION | 0x200
#define VMX_EXIT_INS            VMX_EXIT_IO_INSTRUCTION | 0x400
#define VMX_EXIT_OUTS           VMX_EXIT_IO_INSTRUCTION | 0x800
#define VMX_EXIT_RDMSR                  31
#define VMX_EXIT_WRMSR                  32
#define VMX_ENTRY_FAIL_INVALID_GUEST    33
#define VMX_ENTRY_FAIL_MSR_LOADING      34
#define VMX_EXIT_MWAIT                  36
#define VMX_EXIT_MONITOR                39
#define VMX_EXIT_PAUSE                  40
#define VMX_ENTRY_FAIL_MACHINE_CHECK    41
#define VMX_EXIT_TRP_BELOW_THR          43

/** Control masks **/
#define EXTERNAL_INTERRUPT_EXITING      (env->curr_vmcs.exec_control.pin_based_controls & 0x1)
#define NMI_EXITING                     (env->curr_vmcs.exec_control.pin_based_controls & 0x8)
#define VIRTUAL_NMIS                    (env->curr_vmcs.exec_control.pin_based_controls & 0x20)
#define ACTIVATE_VMX_PREEMPTION_TIMER   (env->curr_vmcs.exec_control.pin_based_controls & 0x40)
#define PROCESS_POSTED_INTERRUPTS       (env->curr_vmcs.exec_control.pin_based_controls & 0x80)
#define INTERRUPT_WINDOW_EXITING        (env->curr_vmcs.exec_control.processor_based_controls & 0x4)
#define USE_TSC_OFFSETING               (env->curr_vmcs.exec_control.processor_based_controls & 0x8)
#define HLT_EXITING                     (env->curr_vmcs.exec_control.processor_based_controls & 0x80)
#define INVLPG_EXITING                  (env->curr_vmcs.exec_control.processor_based_controls & 0x200)
#define MWAIT_EXITING                   (env->curr_vmcs.exec_control.processor_based_controls & 0x400)
#define RDPMC_EXITING                   (env->curr_vmcs.exec_control.processor_based_controls & 0x800)
#define RDTSC_EXITING                   (env->curr_vmcs.exec_control.processor_based_controls & 0x1000)
#define CR3_LOAD_EXITING                (env->curr_vmcs.exec_control.processor_based_controls & 0x8000)
#define CR3_STORE_EXITING               (env->curr_vmcs.exec_control.processor_based_controls & 0x10000)
#define CR8_LOAD_EXITING                (env->curr_vmcs.exec_control.processor_based_controls & 0x80000)
#define CR8_STORE_EXITING               (env->curr_vmcs.exec_control.processor_based_controls & 0x100000)
#define USE_TRP_SHADOW                  (env->curr_vmcs.exec_control.processor_based_controls & 0x200000)
#define NMI_WINDOW_EXITING              (env->curr_vmcs.exec_control.processor_based_controls & 0x400000)
#define MOV_DR_EXITING                  (env->curr_vmcs.exec_control.processor_based_controls & 0x800000)
#define UNCONDITIONAL_IO_EXITING        (env->curr_vmcs.exec_control.processor_based_controls & 0x1000000)
#define USE_IO_BITMAPS                  (env->curr_vmcs.exec_control.processor_based_controls & 0x2000000)
#define MONITOR_TRAP_FLAG               (env->curr_vmcs.exec_control.processor_based_controls & 0x8000000)
#define USE_MSR_BITMAPS                 (env->curr_vmcs.exec_control.processor_based_controls & 0x10000000)
#define MONITOR_EXITING                 (env->curr_vmcs.exec_control.processor_based_controls & 0x20000000)
#define PAUSE_EXITING                   (env->curr_vmcs.exec_control.processor_based_controls & 0x40000000)
#define ACTIVATE_SECONDARY_CONTROLS     (env->curr_vmcs.exec_control.processor_based_controls & 0x80000000)
#define SAVE_DEBUG_CONTROLS             (env->curr_vmcs.exit_control.controls & 0x4)
#define HOST_ADDRESS_SPACE_SIZE         (env->curr_vmcs.exit_control.controls & 0x200)
#define EXIT_LOAD_PERF_GLOBAL_CTRL      (env->curr_vmcs.exit_control.controls & 0x1000)
#define ACKNOWLEDGE_INT_ON_EXIT         (env->curr_vmcs.exit_control.controls & 0x8000)
#define SAVE_PAT                        (env->curr_vmcs.exit_control.controls & 0x40000)
#define EXIT_LOAD_PAT                   (env->curr_vmcs.exit_control.controls & 0x80000)
#define SAVE_EFER                       (env->curr_vmcs.exit_control.controls & 0x100000)
#define EXIT_LOAD_EFER                  (env->curr_vmcs.exit_control.controls & 0x200000)
#define SAVE_VMX_PT_VALUE               (env->curr_vmcs.exit_control.controls & 0x400000)
#define LOAD_DEBUG_CONTROLS             (env->curr_vmcs.entry_control.controls & 0x4)
#define IA32E_MODE_GUEST                (env->curr_vmcs.entry_control.controls & 0x200)
#define ENTRY_TO_SMM                    (env->curr_vmcs.entry_control.controls & 0x400)
#define DEACTIVATE_DM_TREATMENT         (env->curr_vmcs.entry_control.controls & 0x800)
#define ENTRY_LOAD_PERF_GLOBAL_CTRL     (env->curr_vmcs.entry_control.controls & 0x2000)
#define ENTRY_LOAD_PAT                  (env->curr_vmcs.entry_control.controls & 0x4000)
#define ENTRY_LOAD_EFER                 (env->curr_vmcs.entry_control.controls & 0x8000)

#define ACTIVITY_STATE_ACTIVE       0
#define ACTIVITY_STATE_HLT          1
#define ACTIVITY_STATE_SHUTDOWN     2
#define ACTIVITY_STATE_WAITFORSIPI  3

#define VMCS_CLEAR      0
#define VMCS_LAUNCHED   1

#define INT_TYPE_EXT_INT        0
#define INT_TYPE_NMI            2
#define INT_TYPE_HARD_EXCP      3
#define INT_TYPE_SOFT_INT       4
#define INT_TYPE_PRIV_SOFT_EXCP 5
#define INT_TYPE_SOFT_EXCP      6

struct guest_state_area
{
    // guest register state  
    target_ulong cr0;
    target_ulong cr3;
    target_ulong cr4;
    target_ulong dr7;
    target_ulong rsp;
    target_ulong rip;
    target_ulong rflags;   
    SegmentCache cs;
    SegmentCache ss;
    SegmentCache ds;
    SegmentCache es;
    SegmentCache fs;
    SegmentCache gs;
    SegmentCache ldtr;
    SegmentCache tr; 
    SegmentCache gdtr; /* only base and limit are used */
    SegmentCache idtr; /* only base and limit are used */    
    uint64_t msr_debugctl;
    uint32_t msr_sysenter_cs;
    target_ulong msr_sysenter_esp;
    target_ulong msr_sysenter_eip;
    uint32_t smbase;    
    // guest non-register state
    uint32_t activity_state;
    uint32_t interuptibility_state;
    target_ulong pending_debug_exceptions;
    uint64_t vmcs_link_pointer;
};

struct host_state_area
{
    target_ulong cr0;
    target_ulong cr3;
    target_ulong cr4;
    target_ulong rsp;
    target_ulong rip; 
    uint16_t cs_selector;
    uint16_t ss_selector;
    uint16_t ds_selector;
    uint16_t es_selector;
    uint16_t fs_selector;
    uint16_t gs_selector;
    uint16_t tr_selector;
    target_ulong fs_base;
    target_ulong gs_base;
    target_ulong tr_base;
    target_ulong idtr_base;
    target_ulong gdtr_base;
    uint32_t msr_sysenter_cs;
    target_ulong msr_sysenter_esp;
    target_ulong msr_sysenter_eip;
};

struct vm_execution_control_fields
{
    uint32_t pin_based_controls;
    uint32_t processor_based_controls;
    uint32_t exception_bitmap;
    uint32_t page_fault_error_code_mask;
    uint32_t page_fault_error_code_match;
    uint64_t io_bitmap_a;
    uint64_t io_bitmap_b;
    uint64_t tsc_offset;
    target_ulong cr0_guest_host_mask;
    target_ulong cr4_guest_host_mask;
    target_ulong cr0_read_shadow;
    target_ulong cr4_read_shadow;
    target_ulong cr3_target_value[4];
    uint32_t cr3_target_count;
    uint64_t virtual_apic_page_address;
    uint32_t tpr_threshold;
    uint64_t msr_bitmap_address;
    uint64_t executive_vmcs_pointer;
};

struct vm_exit_control_fields
{
    uint32_t controls;
    uint32_t msr_store_count;
    uint64_t msr_store_address;
    uint32_t msr_load_count;
    uint64_t msr_load_address;
};

struct vm_entry_control_fields
{
    uint32_t controls;
    uint32_t msr_load_count;
    uint64_t msr_load_address;
    uint32_t interruption_information;
    uint32_t exception_error_code;
    uint32_t instruction_length;
};

struct vm_exit_information_fields
{
    uint32_t exit_reason;
    target_ulong exit_qualification;
    uint32_t interruption_information;
    uint32_t interruption_error_code;
    uint32_t idt_vectoring_information;
    uint32_t idt_vectoring_error_code;
    uint32_t instruction_length;
    target_ulong guest_linear_address;
    uint32_t instruction_information;
    target_ulong io_rcx;
    target_ulong io_rsi;
    target_ulong io_rdi;
    target_ulong io_rip;
    uint32_t vm_instruction_error;
};

typedef struct VMCS
{
    uint32_t launch_state;
    struct guest_state_area guest_state;
    struct host_state_area host_state;
    struct vm_execution_control_fields exec_control;
    struct vm_exit_control_fields exit_control;
    struct vm_entry_control_fields entry_control;
    struct vm_exit_information_fields exit_info;
} VMCS;
#endif
