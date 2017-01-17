#include "qemu/osdep.h"
#include "sysemu/char.h"
#include "sysemu/sysemu.h"
#include "sysemu/cpus.h"
#include "exec/windbgstub.h"
#include "exec/windbgstub-utils.h"

// windbg.exe -b -k com:pipe,baud=115200,port=\\.\pipe\windbg,resets=0
// qemu.exe -windbg pipe:windbg

#define WINDBG "windbg"

typedef enum ParsingState {
    STATE_LEADER,
    STATE_PACKET_TYPE,
    STATE_PACKET_BYTE_COUNT,
    STATE_PACKET_ID,
    STATE_PACKET_CHECKSUM,
    STATE_PACKET_DATA,
    STATE_TRAILING_BYTE,
} ParsingState;

typedef struct ParsingContext {
    // index in the current buffer,
    // which depends on the current state
    int index;
    ParsingState state;
    KD_PACKET packet;
    uint8_t data[PACKET_MAX_SIZE];
} ParsingContext;

static uint32_t cntrl_packet_id = RESET_PACKET_ID;
static uint32_t data_packet_id = INITIAL_PACKET_ID;
static uint8_t lock = 0;

static ParsingContext chr_ctx = { .state = STATE_LEADER };

static CharDriverState *windbg_chr = NULL;

static FILE *dump_file;

static CPU_CTRL_ADDRS *cc_addrs;

void windbg_dump(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    if (dump_file) {
        vfprintf(dump_file, fmt, ap);
        fflush(dump_file);
    }
    va_end(ap);
}

static void windbg_send_data_packet(uint8_t *data, uint16_t byte_count,
                                    uint16_t type)
{
    uint8_t trailing_byte = PACKET_TRAILING_BYTE;

    KD_PACKET packet = {
        .PacketLeader = PACKET_LEADER,
        .PacketType = type,
        .ByteCount = byte_count,
        .PacketId = data_packet_id,
        .Checksum = compute_checksum(data, byte_count)
    };

    qemu_chr_fe_write(windbg_chr, PTR(packet), sizeof(packet));
    qemu_chr_fe_write(windbg_chr, data, byte_count);
    qemu_chr_fe_write(windbg_chr, &trailing_byte, sizeof(trailing_byte));

    data_packet_id ^= 1;
}

static void windbg_send_control_packet(uint16_t type)
{
    KD_PACKET packet = {
        .PacketLeader = CONTROL_PACKET_LEADER,
        .PacketType = type,
        .ByteCount = 0,
        .PacketId = cntrl_packet_id,
        .Checksum = 0
    };

    qemu_chr_fe_write(windbg_chr, PTR(packet), sizeof(packet));

    cntrl_packet_id ^= 1;
}

static void windbg_process_manipulate_packet(ParsingContext *ctx)
{
    const size_t m64_size = sizeof(DBGKD_MANIPULATE_STATE64);

    PacketData pd;
    pd.m64 = (DBGKD_MANIPULATE_STATE64 *) ctx->data;
    pd.extra_size = ctx->packet.ByteCount - m64_size;
    pd.extra = ctx->data + m64_size;
    pd.m64->ReturnStatus = STATUS_SUCCESS;

    int err = 0;
    CPUState *cpu = qemu_get_cpu(pd.m64->Processor < get_cpu_amount() ?
                                 pd.m64->Processor : 0);

    switch(pd.m64->ApiNumber) {

    case DbgKdReadVirtualMemoryApi:
    {
        DBGKD_READ_MEMORY64 *mem = &pd.m64->u.ReadMemory;

        mem->ActualBytesRead = MIN(mem->TransferCount, PACKET_MAX_SIZE - m64_size);
        err = cpu_memory_rw_debug(cpu, mem->TargetBaseAddress,
                                  pd.extra, mem->ActualBytesRead, 0);
        pd.extra_size = mem->ActualBytesRead;

        if (err) {
            pd.m64->ReturnStatus = STATUS_UNSUCCESSFUL;

            // tmp checking
            WINDBG_DEBUG("ReadVirtualMemoryApi: No physical page mapped: " FMT_ADDR,
                         (target_ulong) mem->TargetBaseAddress);
        }

        break;
    }
    case DbgKdWriteVirtualMemoryApi:
    {
        DBGKD_WRITE_MEMORY64 *mem = &pd.m64->u.WriteMemory;

        mem->ActualBytesWritten = MIN(pd.extra_size, mem->TransferCount);
        err = cpu_memory_rw_debug(cpu, mem->TargetBaseAddress,
                                  pd.extra, mem->ActualBytesWritten, 1);

        if (err) {
            pd.m64->ReturnStatus = STATUS_UNSUCCESSFUL;
        }
        pd.extra_size = 0;

        break;
    }
    case DbgKdGetContextApi:
    {
        pd.extra_size = sizeof(CPU_CONTEXT);
        memcpy(pd.extra, kd_get_context(cpu), pd.extra_size);

        break;
    }
    case DbgKdSetContextApi:
    {
        kd_set_context(cpu, pd.extra, MIN(pd.extra_size, sizeof(CPU_CONTEXT)));
        pd.extra_size = 0;

        break;
    }
    case DbgKdWriteBreakPointApi:
    {
        windbg_write_breakpoint(cpu, &pd);
        break;
    }
    case DbgKdRestoreBreakPointApi:
    {
        windbg_restore_breakpoint(cpu, &pd);
        break;
    }
    case DbgKdReadControlSpaceApi:
    {
        DBGKD_READ_MEMORY64 *mem = &pd.m64->u.ReadMemory;

        // tmp checking
        if (mem->TargetBaseAddress != 0x2f4 && mem->TargetBaseAddress != 0x2cc) {
            WINDBG_DEBUG("ReadControlSpaceApi: Catched unknown " FMT_ADDR,
                         (target_ulong) mem->TargetBaseAddress);
        }

        mem->ActualBytesRead = MIN(mem->TransferCount, PACKET_MAX_SIZE - m64_size);
        uint32_t offset = mem->TargetBaseAddress - sizeof(CPU_CONTEXT);
        memcpy(pd.extra, ((uint8_t *) kd_get_kspecial_registers(cpu)) + offset,
               mem->ActualBytesRead);
        pd.extra_size = mem->ActualBytesRead;

        break;
    }
    case DbgKdWriteControlSpaceApi:
    {
        DBGKD_WRITE_MEMORY64 *mem = &pd.m64->u.WriteMemory;

        // tmp checking
        if (mem->TargetBaseAddress != 0x2f4 && mem->TargetBaseAddress != 0x2cc) {
            WINDBG_DEBUG("WriteControlSpaceApi: Catched unknown " FMT_ADDR,
                         (target_ulong) mem->TargetBaseAddress);
        }

        mem->ActualBytesWritten = MIN(pd.extra_size, mem->TransferCount);
        uint32_t offset = mem->TargetBaseAddress - sizeof(CPU_CONTEXT);
        kd_set_kspecial_registers(cpu, pd.extra, mem->ActualBytesWritten, offset);
        pd.extra_size = 0;

        break;
    }
    case DbgKdReadIoSpaceApi:
    {
        windbg_read_io_space(cpu, &pd);
        break;
    }
    case DbgKdWriteIoSpaceApi:
    {
        windbg_write_io_space(cpu, &pd);
        break;
    }
    case DbgKdContinueApi2:
    {
        cpu_single_step(cpu, pd.m64->u.Continue2.ControlSet.TraceFlag ?
                        SSTEP_ENABLE | SSTEP_NOIRQ | SSTEP_NOTIMER : 0);

        if (!runstate_needs_reset()) {
            vm_start();
        }

        return;
    }
    case DbgKdReadPhysicalMemoryApi:
    {
        DBGKD_READ_MEMORY64 *mem = &pd.m64->u.ReadMemory;

        mem->ActualBytesRead = MIN(mem->TransferCount, PACKET_MAX_SIZE - m64_size);
        cpu_physical_memory_rw(mem->TargetBaseAddress, pd.extra,
                               mem->ActualBytesRead, 0);
        pd.extra_size = mem->ActualBytesRead;

        break;
    }
    case DbgKdWritePhysicalMemoryApi:
    {
        DBGKD_WRITE_MEMORY64 *mem = &pd.m64->u.WriteMemory;

        mem->ActualBytesWritten = MIN(pd.extra_size, mem->TransferCount);
        cpu_physical_memory_rw(mem->TargetBaseAddress, pd.extra,
                               mem->ActualBytesWritten, 1);
        pd.extra_size = 0;

        break;
    }
    case DbgKdGetVersionApi:
    {
        err = cpu_memory_rw_debug(cpu, cc_addrs->Version, (uint8_t *) pd.m64 + 0x10,
                                  m64_size - 0x10, 0);
        if (err) {
            WINDBG_ERROR("GetVersionApi: " FMT_ERR, err);
            pd.m64->ReturnStatus = STATUS_UNSUCCESSFUL;
        }

        break;
    }
    case DbgKdReadMachineSpecificRegister:
    {
        windbg_read_msr(cpu, &pd);
        break;
    }
    case DbgKdWriteMachineSpecificRegister:
    {
        windbg_write_msr(cpu, &pd);
        break;
    }
    case DbgKdSearchMemoryApi:
    {
        windbg_search_memory(cpu, &pd);
        break;
    }
    case DbgKdClearAllInternalBreakpointsApi:
    {
        // Unsupported yet!!! But need for connect
        break;
    }
    case DbgKdQueryMemoryApi:
    {
        DBGKD_QUERY_MEMORY *mem = &pd.m64->u.QueryMemory;

        if (mem->AddressSpace == DBGKD_QUERY_MEMORY_VIRTUAL) {
            mem->AddressSpace = DBGKD_QUERY_MEMORY_PROCESS;
            mem->Flags = DBGKD_QUERY_MEMORY_READ |
                         DBGKD_QUERY_MEMORY_WRITE |
                         DBGKD_QUERY_MEMORY_EXECUTE;
        }
        break;
    }
    default:
        WINDBG_ERROR("Catched unimplemented api: %s",
                     kd_api_name(pd.m64->ApiNumber));
        pd.m64->ReturnStatus = STATUS_UNSUCCESSFUL;

        return;
    }

    windbg_send_data_packet(pd.m64, pd.extra_size + m64_size, ctx->packet.PacketType);
}

static void windbg_process_data_packet(ParsingContext *ctx)
{
    switch (ctx->packet.PacketType) {
    case PACKET_TYPE_KD_STATE_MANIPULATE:
        windbg_send_control_packet(PACKET_TYPE_KD_ACKNOWLEDGE);
        windbg_process_manipulate_packet(ctx);

        break;
    default:
        WINDBG_ERROR("Catched unsupported data packet 0x%x",
                     ctx->packet.PacketType);

        cntrl_packet_id = 0;
        windbg_send_control_packet(PACKET_TYPE_KD_RESEND);

        break;
    }
}

static void windbg_process_control_packet(ParsingContext *ctx)
{
    switch (ctx->packet.PacketType) {
    case PACKET_TYPE_KD_ACKNOWLEDGE:

        break;
    case PACKET_TYPE_KD_RESET:
    {
        //TODO: For all processors
        SizedBuf *lssc = kd_get_load_symbols_sc(qemu_get_cpu(0));

        windbg_send_data_packet(lssc->data, lssc->size,
                                PACKET_TYPE_KD_STATE_CHANGE64);
        windbg_send_control_packet(ctx->packet.PacketType);
        cntrl_packet_id = INITIAL_PACKET_ID;

        break;
    }
    default:
        WINDBG_ERROR("Catched unsupported control packet 0x%x",
                     ctx->packet.PacketType);

        cntrl_packet_id = 0;
        windbg_send_control_packet(PACKET_TYPE_KD_RESEND);

        break;
    }
}

static int windbg_chr_can_receive(void *opaque)
{
    // We can handle an arbitrarily large amount of data.
    // Pick the maximum packet size, which is as good as anything.
    return PACKET_MAX_SIZE;
}

static void windbg_bp_handler(CPUState *cpu)
{
    windbg_send_data_packet((uint8_t *) kd_get_exception_sc(cpu),
                            sizeof(EXCEPTION_STATE_CHANGE),
                            PACKET_TYPE_KD_STATE_CHANGE64);
}

static void windbg_vm_stop(void)
{
    vm_stop(RUN_STATE_PAUSED);
    windbg_bp_handler(qemu_get_cpu(0));
}

static void windbg_read_byte(ParsingContext *ctx, uint8_t byte)
{
    switch (ctx->state) {
    case STATE_LEADER:
        if (byte == PACKET_LEADER_BYTE || byte == CONTROL_PACKET_LEADER_BYTE) {
            if (ctx->index > 0 && byte != UINT8(ctx->packet.PacketLeader, 0)) {
                ctx->index = 0;
            }
            UINT8(ctx->packet.PacketLeader, ctx->index) = byte;
            ++ctx->index;
            if (ctx->index == sizeof(ctx->packet.PacketLeader)) {
                ctx->state = STATE_PACKET_TYPE;
                ctx->index = 0;
            }
        }
        else if (byte == BREAKIN_PACKET_BYTE) {
            windbg_vm_stop();
            ctx->index = 0;
        }
        else {
            ctx->index = 0;
        }
        break;
    case STATE_PACKET_TYPE:
        UINT8(ctx->packet.PacketType, ctx->index) = byte;
        ++ctx->index;
        if (ctx->index == sizeof(ctx->packet.PacketType)) {
            if (ctx->packet.PacketType >= PACKET_TYPE_MAX) {
                ctx->state = STATE_LEADER;
            }
            else {
                ctx->state = STATE_PACKET_BYTE_COUNT;
            }
            ctx->index = 0;
        }
        break;
    case STATE_PACKET_BYTE_COUNT:
        UINT8(ctx->packet.ByteCount, ctx->index) = byte;
        ++ctx->index;
        if (ctx->index == sizeof(ctx->packet.ByteCount)) {
            ctx->state = STATE_PACKET_ID;
            ctx->index = 0;
        }
        break;
    case STATE_PACKET_ID:
        UINT8(ctx->packet.PacketId, ctx->index) = byte;
        ++ctx->index;
        if (ctx->index == sizeof(ctx->packet.PacketId)) {
            ctx->state = STATE_PACKET_CHECKSUM;
            ctx->index = 0;
        }
        break;
    case STATE_PACKET_CHECKSUM:
        UINT8(ctx->packet.Checksum, ctx->index) = byte;
        ++ctx->index;
        if (ctx->index == sizeof(ctx->packet.Checksum)) {
            if (ctx->packet.PacketLeader == CONTROL_PACKET_LEADER) {
                windbg_process_control_packet(ctx);
                ctx->state = STATE_LEADER;
            }
            else {
                if (ctx->packet.ByteCount > PACKET_MAX_SIZE) {
                    ctx->state = STATE_LEADER;
                    cntrl_packet_id = 0;
                    windbg_send_control_packet(PACKET_TYPE_KD_RESEND);
                }
                else {
                    ctx->state = STATE_PACKET_DATA;
                }
            }
            ctx->index = 0;
        }
        break;
    case STATE_PACKET_DATA:
        ctx->data[ctx->index] = byte;
        ++ctx->index;
        if (ctx->index == ctx->packet.ByteCount) {
            ctx->state = STATE_TRAILING_BYTE;
            ctx->index = 0;
        }
        break;
    case STATE_TRAILING_BYTE:
        if (byte == PACKET_TRAILING_BYTE) {
            windbg_process_data_packet(ctx);
        }
        else {
            cntrl_packet_id = 0;
            windbg_send_control_packet(PACKET_TYPE_KD_RESEND);
        }
        ctx->state = STATE_LEADER;
        break;
    }
}

static void windbg_chr_receive(void *opaque, const uint8_t *buf, int size)
{
    if (lock) {
        int i;
        for (i = 0; i < size; i++) {
            windbg_read_byte(&chr_ctx, buf[i]);
        }
    }
}

void windbg_start_sync(void)
{
    windbg_on_init();
    cc_addrs = kd_get_cpu_ctrl_addrs(qemu_get_cpu(0));

    lock = 1;
}

static void windbg_exit(void)
{
    windbg_on_exit();

    if (dump_file) {
        fclose(dump_file);
    }
    dump_file = NULL;
}

int windbgserver_start(const char *device)
{
    if (windbg_chr) {
        WINDBG_ERROR("Multiple instances are not supported yet");
        exit(1);
    }

    if (!register_excp_debug_handler(windbg_bp_handler)) {
        WINDBG_ERROR("Another debugger stub has already been registered");
        exit(1);
    }

    // open external pipe for listening to windbg
    windbg_chr = qemu_chr_new(WINDBG, device, NULL);
    if (!windbg_chr) {
        return -1;
    }

    qemu_chr_fe_claim_no_fail(windbg_chr);
    qemu_chr_add_handlers(windbg_chr, windbg_chr_can_receive,
                          windbg_chr_receive, NULL, NULL);

    // open dump file
    dump_file = fopen(WINDBG ".dump", "wb");

    atexit(windbg_exit);

    return 0;
}