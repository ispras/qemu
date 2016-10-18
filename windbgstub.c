#include "qemu/osdep.h"
#include "cpu.h"
//#include "qemu-common.h"
#include "sysemu/char.h"
//#include "sysemu/sysemu.h"
#include "exec/windbgstub.h"
#include "exec/windbgstub-utils.h"

//windbg.exe -b -k com:pipe,baud=115200,port=\\.\pipe\windbg,resets=0
//qemu.exe -windbg pipe:windbg

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

static Context input_context = { .state = STATE_LEADER };

static CharDriverState *windbg_chr = NULL;

static FILE *dump_file;

//TODO: Remove it
static uint32_t cntrl_packet_id = RESET_PACKET_ID;
static uint8_t lock = 0;
//////////////////////////////////////////////////

static PCPU_CTRL_ADDRS pc_addrs;

static void windbg_dump(const char *fmt, ...)
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
    static uint32_t data_packet_id = INITIAL_PACKET_ID;
    static uint8_t trailing_byte = PACKET_TRAILING_BYTE;

    KD_PACKET packet = {
        .PacketLeader = PACKET_LEADER,
        .PacketType = type,
        .ByteCount = byte_count,
        .PacketId = data_packet_id,
        .Checksum = data_checksum_compute(data, byte_count)
    };

    qemu_chr_fe_write(windbg_chr, (uint8_t *)&packet,
                      sizeof(packet));
    qemu_chr_fe_write(windbg_chr, data, byte_count);
    qemu_chr_fe_write(windbg_chr, &trailing_byte,
                      sizeof(trailing_byte));

    data_packet_id ^= 1;

    DUMP_STRUCT(packet);
    DUMP_ARRAY(data, byte_count);
    DUMP_VAR(trailing_byte);
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

    qemu_chr_fe_write(windbg_chr, (uint8_t *)&packet, sizeof(packet));

    cntrl_packet_id ^= 1;

    DUMP_STRUCT(packet);
}

static void windbg_process_manipulate_packet(Context *ctx)
{
    uint8_t packet[PACKET_MAX_SIZE];
    size_t packet_size = 0,
           extra_data_size = 0,
           m64_size = sizeof(DBGKD_MANIPULATE_STATE64);
    uint32_t count, addr;
    bool send_only_m64 = false;
    DBGKD_MANIPULATE_STATE64 m64;

    CPUState *cpu = find_cpu(0);

    memset(packet, 0, PACKET_MAX_SIZE);
    memcpy(&m64, ctx->data, m64_size);

    extra_data_size = ctx->packet.ByteCount - m64_size;

    m64.ReturnStatus = 0x0;

    switch(m64.ApiNumber) {

    case DbgKdReadVirtualMemoryApi:
        count = m64.u.ReadMemory.TransferCount;
        addr = m64.u.ReadMemory.TargetBaseAddress;

        m64.u.ReadMemory.ActualBytesRead = count;
        cpu_memory_rw_debug(cpu, addr, M64_OFFSET(packet), count, 0);

        packet_size = m64_size + count;

        break;
    case DbgKdWriteVirtualMemoryApi:
        count = ROUND(extra_data_size, m64.u.WriteMemory.TransferCount);
        addr = m64.u.WriteMemory.TargetBaseAddress;

        m64.u.WriteMemory.ActualBytesWritten = count;
        cpu_memory_rw_debug(cpu, addr, M64_OFFSET(ctx->data), count, 1);

        send_only_m64 = true;
        break;
    case DbgKdGetContextApi:
        packet_size = sizeof(CPU_CONTEXT);
        //TODO: For all processors
        memcpy(M64_OFFSET(packet), get_Context(0), packet_size);
        packet_size += m64_size;

        break;
    case DbgKdSetContextApi:
        set_Context(M64_OFFSET(ctx->data), ROUND(extra_data_size,
                    sizeof(CPU_CONTEXT)), 0);

        send_only_m64 = true;
        break;
    case DbgKdWriteBreakPointApi:

        break;
    case DbgKdRestoreBreakPointApi:
        m64.ReturnStatus = 0xc0000001;

        send_only_m64 = true;
        break;
    case DbgKdContinueApi:

        send_only_m64 = true;
        break;
    case DbgKdReadControlSpaceApi:
        count = m64.u.ReadMemory.TransferCount;
        addr = m64.u.ReadMemory.TargetBaseAddress - sizeof(CPU_CONTEXT);

        m64.u.ReadMemory.ActualBytesRead = count;
        //TODO: For all processors
        memcpy(M64_OFFSET(packet), get_KSpecialRegisters(0) + addr, count);
        packet_size = m64_size + count;

        break;
    case DbgKdWriteControlSpaceApi:
        count = ROUND(extra_data_size, m64.u.WriteMemory.TransferCount);
        addr = m64.u.WriteMemory.TargetBaseAddress - sizeof(CPU_CONTEXT);

        m64.u.WriteMemory.ActualBytesWritten = count;
        set_KSpecialRegisters(M64_OFFSET(ctx->data), count, addr, 0);

        send_only_m64 = true;
        break;
    case DbgKdReadIoSpaceApi:

        break;
    case DbgKdWriteIoSpaceApi:

        break;
    case DbgKdRebootApi:

        break;
    case DbgKdContinueApi2:

        send_only_m64 = true;
        break;
    case DbgKdReadPhysicalMemoryApi:

        break;
    case DbgKdWritePhysicalMemoryApi:

        break;
    case DbgKdQuerySpecialCallsApi:

        break;
    case DbgKdSetSpecialCallApi:

        break;
    case DbgKdClearSpecialCallsApi:

        break;
    case DbgKdSetInternalBreakPointApi:

        break;
    case DbgKdGetInternalBreakPointApi:

        break;
    case DbgKdReadIoSpaceExtendedApi:

        break;
    case DbgKdWriteIoSpaceExtendedApi:

        break;
    case DbgKdGetVersionApi:
        cpu_memory_rw_debug(cpu, pc_addrs->Version, PTR(m64) + 0x10,
                            m64_size - 0x10, 0);

        send_only_m64 = true;
        break;
    case DbgKdWriteBreakPointExApi:

        break;
    case DbgKdRestoreBreakPointExApi:

        break;
    case DbgKdCauseBugCheckApi:

        break;
    case DbgKdSwitchProcessor:

        break;
    case DbgKdPageInApi:

        break;
    case DbgKdReadMachineSpecificRegister:

        break;
    case DbgKdWriteMachineSpecificRegister:

        break;
    case OldVlm1:

        break;
    case OldVlm2:

        break;
    case DbgKdSearchMemoryApi:

        break;
    case DbgKdGetBusDataApi:

        break;
    case DbgKdSetBusDataApi:

        break;
    case DbgKdCheckLowMemoryApi:

        break;
    case DbgKdClearAllInternalBreakpointsApi:

        return;
    case DbgKdFillMemoryApi:

        break;
    case DbgKdQueryMemoryApi:

        break;
    case DbgKdSwitchPartition:

        break;
    default:

        break;
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
        cntrl_packet_id = 0;
        windbg_send_control_packet(PACKET_TYPE_KD_RESEND);

        break;
    }
}

static void windbg_process_control_packet(Context *ctx)
{
    switch (ctx->packet.PacketType) {
    case PACKET_TYPE_UNUSED:

        break;
    case PACKET_TYPE_KD_STATE_CHANGE32:

        break;
    case PACKET_TYPE_KD_STATE_MANIPULATE:

        break;
    case PACKET_TYPE_KD_DEBUG_IO:

        break;
    case PACKET_TYPE_KD_ACKNOWLEDGE:

        break;
    case PACKET_TYPE_KD_RESEND:

        break;
    case PACKET_TYPE_KD_RESET:
        windbg_send_control_packet(ctx->packet.PacketType);
        //TODO: For all processors
        windbg_send_data_packet((uint8_t *)get_ExceptionStateChange(0),
                                sizeof(EXCEPTION_STATE_CHANGE),
                                PACKET_TYPE_KD_STATE_CHANGE64);
        cntrl_packet_id = INITIAL_PACKET_ID;

        break;
    case PACKET_TYPE_KD_STATE_CHANGE64:

        break;
    case PACKET_TYPE_KD_POLL_BREAKIN:

        break;
    case PACKET_TYPE_KD_TRACE_IO:

        break;
    case PACKET_TYPE_KD_CONTROL_REQUEST:

        break;
    case PACKET_TYPE_KD_FILE_IO:

        break;
    case PACKET_TYPE_MAX:

        break;
    default:
        cntrl_packet_id = 0;
        windbg_send_control_packet(PACKET_TYPE_KD_RESEND);

        break;
    }
}

static int windbg_chr_can_receive(void *opaque)
{
  /* We can handle an arbitrarily large amount of data.
   Pick the maximum packet size, which is as good as anything.  */
  return PACKET_MAX_SIZE;
}

static void windbg_read_byte(Context *ctx, uint8_t byte)
{
    switch (ctx->state) {
    case STATE_LEADER:
        if (byte == PACKET_LEADER_BYTE || byte == CONTROL_PACKET_LEADER_BYTE) {
            if (ctx->index > 0 && byte != BYTE(ctx->packet.PacketLeader, 0)) {
                ctx->index = 0;
            }
            BYTE(ctx->packet.PacketLeader, ctx->index) = byte;
            ++ctx->index;
            if (ctx->index == sizeof(ctx->packet.PacketLeader)) {
                ctx->state = STATE_PACKET_TYPE;
                ctx->index = 0;
            }
        } else if (byte == BREAKIN_PACKET_BYTE) {
            //TODO: For all processors
            //TODO: breakpoint
            cpu_single_step(find_cpu(0), SSTEP_ENABLE);
            //TODO: data_packet_id = INITIAL_PACKET_ID;
            ctx->index = 0;
        } else {
            // skip the byte, restart waiting for the leader
            ctx->index = 0;
        }
        break;
    case STATE_PACKET_TYPE:
        BYTE(ctx->packet.PacketType, ctx->index) = byte;
        ++ctx->index;
        if (ctx->index == sizeof(ctx->packet.PacketType)) {
            if (ctx->packet.PacketType >= PACKET_TYPE_MAX) {
                ctx->state = STATE_LEADER;
            } else {
                if (ctx->packet.PacketLeader == CONTROL_PACKET_LEADER
                    && ctx->packet.PacketType == PACKET_TYPE_KD_RESEND) {
                    ctx->state = STATE_LEADER;
                } else {
                    ctx->state = STATE_PACKET_BYTE_COUNT;
                }
            }
            ctx->index = 0;
        }
        break;
    case STATE_PACKET_BYTE_COUNT:
        BYTE(ctx->packet.ByteCount, ctx->index) = byte;
        ++ctx->index;
        if (ctx->index == sizeof(ctx->packet.ByteCount)) {
            ctx->state = STATE_PACKET_ID;
            ctx->index = 0;
        }
        break;
    case STATE_PACKET_ID:
        BYTE(ctx->packet.PacketId, ctx->index) = byte;
        ++ctx->index;
        if (ctx->index == sizeof(ctx->packet.PacketId)) {
            ctx->state = STATE_PACKET_CHECKSUM;
            ctx->index = 0;
        }
        break;
    case STATE_PACKET_CHECKSUM:
        BYTE(ctx->packet.Checksum, ctx->index) = byte;
        ++ctx->index;
        if (ctx->index == sizeof(ctx->packet.Checksum)) {
            if (ctx->packet.PacketLeader == CONTROL_PACKET_LEADER) {
                windbg_process_control_packet(ctx);
                ctx->state = STATE_LEADER;
            } else {
                if (ctx->packet.ByteCount > PACKET_MAX_SIZE) {
                    ctx->state = STATE_LEADER;
                    cntrl_packet_id = 0;
                    windbg_send_control_packet(PACKET_TYPE_KD_RESEND);
                } else {
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
        } else {
            cntrl_packet_id = 0;
            windbg_send_control_packet(PACKET_TYPE_KD_RESEND);
        }
        ctx->state = STATE_LEADER;
        break;
    }
}

static void windbg_in_chr_receive(void *opaque, const uint8_t *buf, int size)
{
    if (lock) {
        int i;
        for (i = 0; i < size; i++) {
            uint8_t tmp = buf[i];
            windbg_read_byte(&input_context, tmp);
            DUMP_VAR(tmp);
        }
    }
}

static void windbg_close(void)
{
    if (dump_file) {
        fclose(dump_file);
    }
    dump_file = NULL;
}

void windbg_start_sync(void)
{
    pc_addrs = get_KPCRAddress(0);
    
    lock = 1;
}

int windbgserver_start(const char *device)
{
    if (windbg_chr) {
        fprintf(stderr, "Multiple WinDbg instances are not supported yet\n");
        exit(1);
    }

    // open external pipe for listening to windbg
    windbg_chr = qemu_chr_new("windbg", device, NULL);
    if (!windbg_chr) {
        return -1;
    }

    qemu_chr_fe_claim_no_fail(windbg_chr);
    qemu_chr_add_handlers(windbg_chr, windbg_chr_can_receive,
                          windbg_in_chr_receive, NULL, NULL);

    // open dump file
    dump_file = fopen("windbg.dump", "wb");

    atexit(windbg_close);

    return 0;
}