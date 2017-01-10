#include "qemu/osdep.h"
#include "cpu.h"
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

typedef struct Context {
    // index in the current buffer,
    // which depends on the current state
    int index;
    ParsingState state;
    KD_PACKET packet;
    uint8_t data[PACKET_MAX_SIZE];
} Context;

static uint32_t cntrl_packet_id = RESET_PACKET_ID;
static uint32_t data_packet_id = INITIAL_PACKET_ID;
static uint8_t lock = 0;

static Context chr_ctx = { .state = STATE_LEADER };

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

static void windbg_process_manipulate_packet(Context *ctx)
{
    uint8_t packet[PACKET_MAX_SIZE];
    size_t packet_size = 0,
           extra_data_size = 0,
           m64_size = sizeof(DBGKD_MANIPULATE_STATE64);

    bool send_only_m64;
    int err = 0;

    DBGKD_MANIPULATE_STATE64 m64;
    memset(packet, 0, PACKET_MAX_SIZE);
    memcpy(&m64, ctx->data, m64_size);

    CPUState *cpu = qemu_get_cpu(m64.Processor < get_cpu_amount() ?
                                 m64.Processor : 0);

    extra_data_size = ctx->packet.ByteCount - m64_size;

    m64.ReturnStatus = STATUS_SUCCESS;

    switch(m64.ApiNumber) {

    case DbgKdReadVirtualMemoryApi:
    {
        DBGKD_READ_MEMORY64 *mem = &m64.u.ReadMemory;

        mem->ActualBytesRead = MIN(mem->TransferCount, PACKET_MAX_SIZE - m64_size);
        err = cpu_memory_rw_debug(cpu, mem->TargetBaseAddress,
                                  M64_OFFSET(packet), mem->ActualBytesRead, 0);
        packet_size = m64_size + mem->ActualBytesRead;

        if (err) {
            m64.ReturnStatus = STATUS_UNSUCCESSFUL;

            // tmp checking
            WINDBG_DEBUG("ReadVirtualMemoryApi: No physical page mapped: " FMT_ADDR,
                         (target_ulong) mem->TargetBaseAddress);
        }

        send_only_m64 = false;
        break;
    }
    case DbgKdWriteVirtualMemoryApi:
    {
        DBGKD_WRITE_MEMORY64 *mem = &m64.u.WriteMemory;

        mem->ActualBytesWritten = MIN(extra_data_size, mem->TransferCount);
        err = cpu_memory_rw_debug(cpu, mem->TargetBaseAddress,
                                  M64_OFFSET(ctx->data), mem->ActualBytesWritten, 1);

        if (err) {
            m64.ReturnStatus = STATUS_UNSUCCESSFUL;
        }

        send_only_m64 = true;
        break;
    }
    case DbgKdGetContextApi:
    {
        packet_size = sizeof(CPU_CONTEXT);
        memcpy(M64_OFFSET(packet), kd_get_context(m64.Processor), packet_size);
        packet_size += m64_size;

        send_only_m64 = false;
        break;
    }
    case DbgKdSetContextApi:
    {
        kd_set_context(M64_OFFSET(ctx->data), MIN(extra_data_size,
                       sizeof(CPU_CONTEXT)), m64.Processor);

        send_only_m64 = true;
        break;
    }
    case DbgKdWriteBreakPointApi:
    {
        DBGKD_WRITE_BREAKPOINT64 *bp = &m64.u.WriteBreakPoint;

        bp->BreakPointHandle = windbg_breakpoint_insert(cpu, bp->BreakPointAddress) + 1;

        if (bp->BreakPointHandle <= 0) {
            m64.ReturnStatus = STATUS_UNSUCCESSFUL;
        }

        send_only_m64 = true;
        break;
    }
    case DbgKdRestoreBreakPointApi:
    {
        DBGKD_RESTORE_BREAKPOINT *bp = &m64.u.RestoreBreakPoint;

        int err = windbg_breakpoint_remove(cpu, bp->BreakPointHandle - 1);

        if (err) {
            m64.ReturnStatus = STATUS_UNSUCCESSFUL;
        }

        send_only_m64 = true;
        break;
    }
    case DbgKdReadControlSpaceApi:
    {
        DBGKD_READ_MEMORY64 *mem = &m64.u.ReadMemory;

        // tmp checking
        if (mem->TargetBaseAddress != 0x2f4 && mem->TargetBaseAddress != 0x2cc) {
            WINDBG_DEBUG("ReadControlSpaceApi: Catched unknown " FMT_ADDR,
                         (target_ulong) mem->TargetBaseAddress);
        }

        mem->ActualBytesRead = MIN(mem->TransferCount, PACKET_MAX_SIZE - m64_size);
        uint32_t offset = mem->TargetBaseAddress - sizeof(CPU_CONTEXT);
        memcpy(M64_OFFSET(packet),
               ((uint8_t *) kd_get_kspecial_registers(m64.Processor)) + offset,
               mem->ActualBytesRead);
        packet_size = m64_size + mem->ActualBytesRead;

        send_only_m64 = false;
        break;
    }
    case DbgKdWriteControlSpaceApi:
    {
        DBGKD_WRITE_MEMORY64 *mem = &m64.u.WriteMemory;

        // tmp checking
        if (mem->TargetBaseAddress != 0x2f4 && mem->TargetBaseAddress != 0x2cc) {
            WINDBG_DEBUG("WriteControlSpaceApi: Catched unknown " FMT_ADDR,
                         (target_ulong) mem->TargetBaseAddress);
        }

        mem->ActualBytesWritten = MIN(extra_data_size, mem->TransferCount);
        uint32_t offset = mem->TargetBaseAddress - sizeof(CPU_CONTEXT);
        kd_set_kspecial_registers(M64_OFFSET(ctx->data), mem->ActualBytesWritten,
                               offset, m64.Processor);

        send_only_m64 = true;
        break;
    }
    case DbgKdReadIoSpaceApi:
    {
        DBGKD_READ_WRITE_IO64 *io = &m64.u.ReadWriteIo;

        cpu_physical_memory_rw(io->IoAddress + 0x80000000,
                               PTR(io->DataValue), io->DataSize, 0);

        send_only_m64 = true;
        break;
    }
    case DbgKdWriteIoSpaceApi:
    {
        DBGKD_READ_WRITE_IO64 *io = &m64.u.ReadWriteIo;

        cpu_physical_memory_rw(io->IoAddress + 0x80000000,
                               PTR(io->DataValue), io->DataSize, 1);

        send_only_m64 = true;
        break;
    }
    case DbgKdContinueApi2:
    {
        cpu_single_step(cpu, m64.u.Continue2.ControlSet.TraceFlag ?
                        SSTEP_ENABLE | SSTEP_NOIRQ | SSTEP_NOTIMER : 0);

        if (!runstate_needs_reset()) {
            vm_start();
        }

        return;
    }
    case DbgKdReadPhysicalMemoryApi:
    {
        DBGKD_READ_MEMORY64 *mem = &m64.u.ReadMemory;

        mem->ActualBytesRead = MIN(mem->TransferCount, PACKET_MAX_SIZE - m64_size);
        cpu_physical_memory_rw(mem->TargetBaseAddress, M64_OFFSET(packet),
                               mem->ActualBytesRead, 0);
        packet_size = m64_size + mem->ActualBytesRead;

        send_only_m64 = false;
        break;
    }
    case DbgKdWritePhysicalMemoryApi:
    {
        DBGKD_WRITE_MEMORY64 *mem = &m64.u.WriteMemory;

        mem->ActualBytesWritten = MIN(extra_data_size, mem->TransferCount);
        cpu_physical_memory_rw(mem->TargetBaseAddress, M64_OFFSET(ctx->data),
                               mem->ActualBytesWritten, 1);

        send_only_m64 = true;
        break;
    }
    case DbgKdGetVersionApi:
    {
        err = cpu_memory_rw_debug(cpu, cc_addrs->Version, PTR(m64) + 0x10,
                                  m64_size - 0x10, m64.Processor);

        if (err) {
            WINDBG_ERROR("GetVersionApi: " FMT_ERR, err);
        }

        send_only_m64 = true;
        break;
    }
    case DbgKdClearAllInternalBreakpointsApi:
    {
        // Unsupported yet!!! But need for connect

        send_only_m64 = true;
        break;
    }
    case DbgKdQueryMemoryApi:
    {
        DBGKD_QUERY_MEMORY *mem = &m64.u.QueryMemory;

        if (mem->AddressSpace == DBGKD_QUERY_MEMORY_VIRTUAL) {
            mem->AddressSpace = DBGKD_QUERY_MEMORY_PROCESS;
            mem->Flags = DBGKD_QUERY_MEMORY_READ |
                         DBGKD_QUERY_MEMORY_WRITE |
                         DBGKD_QUERY_MEMORY_EXECUTE;
        }

        send_only_m64 = true;
        break;
    }
    default:
        WINDBG_ERROR("Catch unsupported api 0x%x", m64.ApiNumber);
        exit(1);
        return;
    }

    if (send_only_m64) {
        windbg_send_data_packet(PTR(m64), m64_size, ctx->packet.PacketType);
    }
    else {
        memcpy(packet, &m64, m64_size);
        windbg_send_data_packet(packet, packet_size, ctx->packet.PacketType);
    }
}

static void windbg_process_data_packet(Context *ctx)
{
    switch (ctx->packet.PacketType) {
    case PACKET_TYPE_KD_STATE_MANIPULATE:
        windbg_send_control_packet(PACKET_TYPE_KD_ACKNOWLEDGE);
        windbg_process_manipulate_packet(ctx);

        break;
    default:
        WINDBG_ERROR("Catch unsupported data packet 0x%x",
                     ctx->packet.PacketType);

        cntrl_packet_id = 0;
        windbg_send_control_packet(PACKET_TYPE_KD_RESEND);

        break;
    }
}

static void windbg_process_control_packet(Context *ctx)
{
    switch (ctx->packet.PacketType) {
    case PACKET_TYPE_KD_ACKNOWLEDGE:

        break;
    case PACKET_TYPE_KD_RESET:
    {
        //TODO: For all processors
        SizedBuf *lssc = kd_get_load_symbols_sc(0);

        windbg_send_data_packet(lssc->data, lssc->size,
                                PACKET_TYPE_KD_STATE_CHANGE64);
        windbg_send_control_packet(ctx->packet.PacketType);
        cntrl_packet_id = INITIAL_PACKET_ID;

        break;
    }
    default:
        WINDBG_ERROR("Catch unsupported control packet 0x%x",
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
    windbg_send_data_packet((uint8_t *) kd_get_exception_sc(0),
                            sizeof(EXCEPTION_STATE_CHANGE),
                            PACKET_TYPE_KD_STATE_CHANGE64);
}

static void windbg_vm_stop(void)
{
    vm_stop(RUN_STATE_PAUSED);
    windbg_bp_handler(qemu_get_cpu(0));
}

static void windbg_read_byte(Context *ctx, uint8_t byte)
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
    cc_addrs = kd_get_cpu_ctrl_addrs(0);

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