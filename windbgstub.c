/*
 * windbgstub.c
 *
 * Copyright (c) 2010-2019 Institute for System Programming
 *                         of the Russian Academy of Sciences.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "chardev/char.h"
#include "chardev/char-fe.h"
#include "qemu/cutils.h"
#include "sysemu/reset.h"
#include "sysemu/sysemu.h"
#include "sysemu/kvm.h"
#include "exec/windbgstub.h"
#include "exec/windbgstub-utils.h"

typedef enum ParsingState {
    STATE_LEADER,
    STATE_PACKET_TYPE,
    STATE_PACKET_BYTE_COUNT,
    STATE_PACKET_ID,
    STATE_PACKET_CHECKSUM,
    STATE_PACKET_DATA,
    STATE_TRAILING_BYTE,
} ParsingState;

typedef enum ParsingResult {
    RESULT_NONE,
    RESULT_BREAKIN_BYTE,
    RESULT_UNKNOWN_PACKET,
    RESULT_CONTROL_PACKET,
    RESULT_DATA_PACKET,
    RESULT_ERROR,
} ParsingResult;

typedef struct ParsingContext {
    /* index in the current buffer, which depends on the current state */
    int index;
    ParsingState state;
    ParsingResult result;
    KD_PACKET packet;
    PacketData data;
    const char *name;
} ParsingContext;

typedef struct WindbgState {
    bool is_loaded;
    bool catched_breakin_byte;
    uint32_t wait_packet_type;
    uint32_t curr_packet_id;
    ParsingContext ctx;
    CharBackend chr;
} WindbgState;

static WindbgState *windbg_state;
static bool skip_debug_excp;

static void windbg_state_clean(WindbgState *state)
{
    state->is_loaded = false;
    state->catched_breakin_byte = false;
    state->wait_packet_type = 0;
    state->curr_packet_id = INITIAL_PACKET_ID | SYNC_PACKET_ID;
    state->ctx.state = STATE_LEADER;
    state->ctx.result = RESULT_NONE;
}

static uint32_t compute_checksum(uint8_t *data, uint16_t len)
{
    uint32_t checksum = 0;
    while (len) {
        --len;
        checksum += *data++;
    }
    return checksum;
}

static void windbg_store_packet(KD_PACKET *packet)
{
    stw_p(&packet->PacketLeader, packet->PacketLeader);
    stw_p(&packet->PacketType, packet->PacketType);
    stw_p(&packet->ByteCount, packet->ByteCount);
    stl_p(&packet->PacketId, packet->PacketId);
    stl_p(&packet->Checksum, packet->Checksum);
}

static void windbg_send_data_packet(WindbgState *state, uint8_t *data,
                                    uint16_t byte_count, uint16_t type)
{
    const uint8_t trailing_byte = PACKET_TRAILING_BYTE;

    KD_PACKET packet = {
        .PacketLeader = PACKET_LEADER,
        .PacketType = type,
        .ByteCount = byte_count,
        .PacketId = state->curr_packet_id,
        .Checksum = compute_checksum(data, byte_count),
    };

    windbg_store_packet(&packet);

    qemu_chr_fe_write(&state->chr, PTR(packet), sizeof(packet));
    qemu_chr_fe_write(&state->chr, data, byte_count);
    qemu_chr_fe_write(&state->chr, &trailing_byte, sizeof(trailing_byte));

    state->wait_packet_type = PACKET_TYPE_KD_ACKNOWLEDGE;
}

static void windbg_send_control_packet(WindbgState *state, uint16_t type,
                                       uint32_t id)
{
    KD_PACKET packet = {
        .PacketLeader = CONTROL_PACKET_LEADER,
        .PacketType = type,
        .ByteCount = 0,
        .PacketId = id,
        .Checksum = 0,
    };

    windbg_store_packet(&packet);

    qemu_chr_fe_write(&state->chr, PTR(packet), sizeof(packet));
}

static bool windbg_state_change(CPUState *cs, KdStateChangeType type)
{
    static PacketData out_data = {};

    if (kd_init_state_change(cs, &out_data, type)) {
        windbg_send_data_packet(windbg_state, out_data.buf, out_data.size,
                                PACKET_TYPE_KD_STATE_CHANGE64);
        return true;
    } else {
        return false;
    }
}

static void windbg_excp_debug_handler(CPUState *cs)
{
    if (skip_debug_excp) {
        skip_debug_excp = false;
        return;
    }

    if (windbg_state && windbg_state->is_loaded) {
        windbg_state_change(cs, STATE_CHANGE_BREAKPOINT);
    }
}

static void windbg_vm_stop(void)
{
    windbg_state_change(qemu_get_cpu(0), STATE_CHANGE_BREAKPOINT);
    vm_stop(RUN_STATE_DEBUG);
}

static void windbg_process_manipulate_packet(WindbgState *state)
{
    CPUState *cs;
    ParsingContext *ctx = &state->ctx;
    PacketData *data = &ctx->data;

    data->m64.ReturnStatus = NT_STATUS_SUCCESS;

    cs = qemu_get_cpu(data->m64.Processor);
    if (cs == NULL) {
        cs = qemu_get_cpu(0);
    }

    switch (data->m64.ApiNumber) {
    case DbgKdReadVirtualMemoryApi:
        kd_api_read_virtual_memory(cs, data);
        break;

    case DbgKdWriteVirtualMemoryApi:
        kd_api_write_virtual_memory(cs, data);
        break;

    case DbgKdGetContextApi:
        kd_api_get_context(cs, data);
        break;

    case DbgKdSetContextApi:
        kd_api_set_context(cs, data);
        break;

    case DbgKdWriteBreakPointApi:
        kd_api_write_breakpoint(cs, data);
        break;

    case DbgKdRestoreBreakPointApi:
        kd_api_restore_breakpoint(cs, data);
        break;

    case DbgKdContinueApi:
    case DbgKdContinueApi2:
        kd_api_continue(cs, data);
        return;

    case DbgKdReadControlSpaceApi:
        kd_api_read_control_space(cs, data);
        break;

    case DbgKdWriteControlSpaceApi:
        kd_api_write_control_space(cs, data);
        break;

    case DbgKdReadIoSpaceApi:
        kd_api_read_io_space(cs, data);
        break;

    case DbgKdWriteIoSpaceApi:
        kd_api_write_io_space(cs, data);
        break;

    case DbgKdReadPhysicalMemoryApi:
        kd_api_read_physical_memory(cs, data);
        break;

    case DbgKdWritePhysicalMemoryApi:
        kd_api_write_physical_memory(cs, data);
        break;

    case DbgKdGetVersionApi:
        kd_api_get_version(cs, data);
        break;

    case DbgKdReadMachineSpecificRegister:
        kd_api_read_msr(cs, data);
        break;

    case DbgKdWriteMachineSpecificRegister:
        kd_api_write_msr(cs, data);
        break;

    case DbgKdSearchMemoryApi:
        kd_api_search_memory(cs, data);
        break;

    case DbgKdClearAllInternalBreakpointsApi:
        kd_api_clear_all_internal_breakpoints(cs, data);
        return;

    case DbgKdFillMemoryApi:
        kd_api_fill_memory(cs, data);
        break;

    case DbgKdQueryMemoryApi:
        kd_api_query_memory(cs, data);
        break;

    case DbgKdGetContextExApi:
        kd_api_get_context_ex(cs, data);
        break;

    case DbgKdSetContextExApi:
        kd_api_set_context_ex(cs, data);
        break;

    default:
        kd_api_unsupported(cs, data);
        break;
    }

    if (data->m64.ReturnStatus == NT_STATUS_UNSUCCESSFUL) {
        WINDBG_ERROR("Caught error at %s", kd_api_name(data->m64.ApiNumber));
    }

    stl_p(&data->m64.ReturnStatus, data->m64.ReturnStatus);

    windbg_send_data_packet(state, data->buf, data->size,
                            ctx->packet.PacketType);
}

static void windbg_process_data_packet(WindbgState *state)
{
    ParsingContext *ctx = &state->ctx;

    if (state->wait_packet_type == PACKET_TYPE_KD_ACKNOWLEDGE) {
        /* We received something different */
        windbg_send_control_packet(state, PACKET_TYPE_KD_RESEND, 0);
        return;
    }

    switch (ctx->packet.PacketType) {
    case PACKET_TYPE_KD_STATE_MANIPULATE:
        windbg_send_control_packet(state, PACKET_TYPE_KD_ACKNOWLEDGE,
                                   ctx->packet.PacketId);
        windbg_process_manipulate_packet(state);
        state->curr_packet_id &= ~SYNC_PACKET_ID;
        break;

    default:
        WINDBG_ERROR("Caught unsupported data packet 0x%x",
                     ctx->packet.PacketType);

        windbg_send_control_packet(state, PACKET_TYPE_KD_RESEND, 0);
        break;
    }
}

static void windbg_process_control_packet(WindbgState *state)
{
    ParsingContext *ctx = &state->ctx;

    switch (ctx->packet.PacketType) {
    case PACKET_TYPE_KD_ACKNOWLEDGE:
        if (state->wait_packet_type == PACKET_TYPE_KD_ACKNOWLEDGE &&
            (ctx->packet.PacketId == (state->curr_packet_id &
                                      ~SYNC_PACKET_ID))) {
            state->curr_packet_id ^= 1;
            state->wait_packet_type = 0;
        }
        break;

    case PACKET_TYPE_KD_RESET: {
        state->curr_packet_id = INITIAL_PACKET_ID;
        windbg_send_control_packet(state, PACKET_TYPE_KD_RESET, 0);
        windbg_state_change(qemu_get_cpu(0), STATE_CHANGE_LOAD_SYMBOLS);
        vm_stop(RUN_STATE_DEBUG);
        break;
    }

    case PACKET_TYPE_KD_RESEND:
        break;

    default:
        WINDBG_ERROR("Caught unsupported control packet 0x%x",
                     ctx->packet.PacketType);

        windbg_send_control_packet(state, PACKET_TYPE_KD_RESEND, 0);
        break;
    }
}

static void windbg_ctx_handler(WindbgState *state)
{
    if (!state->is_loaded) {
        if (state->ctx.result == RESULT_BREAKIN_BYTE) {
            state->catched_breakin_byte = true;
        }
        return;
    }

    switch (state->ctx.result) {
    case RESULT_NONE:
        break;

    case RESULT_BREAKIN_BYTE:
        windbg_vm_stop();
        break;

    case RESULT_CONTROL_PACKET:
        windbg_process_control_packet(state);
        break;

    case RESULT_DATA_PACKET:
        windbg_process_data_packet(state);
        break;

    case RESULT_UNKNOWN_PACKET:
    case RESULT_ERROR:
        windbg_send_control_packet(state, PACKET_TYPE_KD_RESEND, 0);
        break;

    default:
        break;
    }
}

static void windbg_read_byte(ParsingContext *ctx, uint8_t byte)
{
    switch (ctx->state) {
    case STATE_LEADER:
        ctx->result = RESULT_NONE;
        if (byte == PACKET_LEADER_BYTE || byte == CONTROL_PACKET_LEADER_BYTE) {
            if (ctx->index > 0 && byte != PTR(ctx->packet.PacketLeader)[0]) {
                ctx->index = 0;
            }
            PTR(ctx->packet.PacketLeader)[ctx->index] = byte;
            ++ctx->index;
            if (ctx->index == sizeof(ctx->packet.PacketLeader)) {
                ctx->state = STATE_PACKET_TYPE;
                ctx->index = 0;
            }
        } else if (byte == BREAKIN_PACKET_BYTE) {
            ctx->result = RESULT_BREAKIN_BYTE;
            ctx->index = 0;
        } else {
            ctx->index = 0;
        }
        break;

    case STATE_PACKET_TYPE:
        PTR(ctx->packet.PacketType)[ctx->index] = byte;
        ++ctx->index;
        if (ctx->index == sizeof(ctx->packet.PacketType)) {
            ctx->packet.PacketType = lduw_p(&ctx->packet.PacketType);
            if (ctx->packet.PacketType >= PACKET_TYPE_MAX) {
                ctx->state = STATE_LEADER;
                ctx->result = RESULT_UNKNOWN_PACKET;
            } else {
                ctx->state = STATE_PACKET_BYTE_COUNT;
            }
            ctx->index = 0;
        }
        break;

    case STATE_PACKET_BYTE_COUNT:
        PTR(ctx->packet.ByteCount)[ctx->index] = byte;
        ++ctx->index;
        if (ctx->index == sizeof(ctx->packet.ByteCount)) {
            ctx->packet.ByteCount = lduw_p(&ctx->packet.ByteCount);
            ctx->data.size = ctx->packet.ByteCount;
            ctx->state = STATE_PACKET_ID;
            ctx->index = 0;
        }
        break;

    case STATE_PACKET_ID:
        PTR(ctx->packet.PacketId)[ctx->index] = byte;
        ++ctx->index;
        if (ctx->index == sizeof(ctx->packet.PacketId)) {
            ctx->packet.PacketId = ldl_p(&ctx->packet.PacketId);
            ctx->state = STATE_PACKET_CHECKSUM;
            ctx->index = 0;
        }
        break;

    case STATE_PACKET_CHECKSUM:
        PTR(ctx->packet.Checksum)[ctx->index] = byte;
        ++ctx->index;
        if (ctx->index == sizeof(ctx->packet.Checksum)) {
            ctx->packet.Checksum = ldl_p(&ctx->packet.Checksum);
            if (ctx->packet.PacketLeader == CONTROL_PACKET_LEADER) {
                ctx->state = STATE_LEADER;
                ctx->result = RESULT_CONTROL_PACKET;
            } else if (ctx->packet.ByteCount > PACKET_MAX_SIZE) {
                ctx->state = STATE_LEADER;
                ctx->result = RESULT_ERROR;
            } else {
                ctx->state = STATE_PACKET_DATA;
            }
            ctx->index = 0;
        }
        break;

    case STATE_PACKET_DATA:
        ctx->data.buf[ctx->index] = byte;
        ++ctx->index;
        if (ctx->index == ctx->packet.ByteCount) {
            ctx->state = STATE_TRAILING_BYTE;
            ctx->index = 0;
        }
        break;

    case STATE_TRAILING_BYTE:
        if (byte == PACKET_TRAILING_BYTE) {
            ctx->result = RESULT_DATA_PACKET;
        } else {
            ctx->result = RESULT_ERROR;
        }
        ctx->state = STATE_LEADER;
        break;
    }
}

static int windbg_chr_can_receive(void *opaque)
{
    return PACKET_MAX_SIZE;
}

static void windbg_chr_receive(void *opaque, const uint8_t *buf, int size)
{
    int i;
    for (i = 0; i < size; i++) {
        windbg_read_byte(&windbg_state->ctx, buf[i]);
        windbg_ctx_handler(windbg_state);
    }
}

static void windbg_exit(void)
{
    g_free(windbg_state);
}

static void windbg_handle_reset(void *opaque)
{
    windbg_state_clean(windbg_state);
    windbg_on_reset();
}

#ifdef WINDBG_CATCH_INTERRUPTS
void windbg_interrupt_handler(CPUState *cs, uint64_t instr_pointer)
{
    static target_ulong last_instr_pointer;

    if (windbg_state && windbg_state->is_loaded
        && last_instr_pointer != instr_pointer) {

        bool need_excp = windbg_state_change(cs, STATE_CHANGE_INTERRUPT);
        if (need_excp) {
            cs->exception_index = EXCP_DEBUG;
            skip_debug_excp = true;
            last_instr_pointer = instr_pointer;
        }
    } else {
        last_instr_pointer = 0;
    }
}
#endif /* WINDBG_CATCH_INTERRUPTS */

void windbg_try_load(void)
{
    if (windbg_state && !windbg_state->is_loaded) {
        if (windbg_on_load()) {
            windbg_state->is_loaded = true;

            /* Handle last packet. Or we can require resend last packet. */
            windbg_ctx_handler(windbg_state);

            if (windbg_state->catched_breakin_byte == true) {
                windbg_vm_stop();
                windbg_state->catched_breakin_byte = false;
            }
        }
    }
}

int windbg_server_start(const char *device)
{
    Chardev *chr = NULL;

    if (windbg_state) {
        WINDBG_ERROR("Multiple instances of windbg are not supported.");
        exit(1);
    }

    if (kvm_enabled()) {
        WINDBG_ERROR("KVM is not supported.");
        exit(1);
    }

    if (!strstart(device, "pipe:", NULL)) {
        WINDBG_ERROR("Unsupported device. Supported only pipe.");
        exit(1);
    }

    windbg_state = g_new0(WindbgState, 1);
    windbg_state->ctx.name = "windbg";
    windbg_state_clean(windbg_state);

    chr = qemu_chr_new_noreplay("windbg", device, true, NULL);
    if (!chr) {
        return -1;
    }

    qemu_chr_fe_init(&windbg_state->chr, chr, &error_abort);
    qemu_chr_fe_set_handlers(&windbg_state->chr, windbg_chr_can_receive,
                             windbg_chr_receive, NULL, NULL, NULL, NULL, true);

    qemu_register_reset(windbg_handle_reset, NULL);

    if (!register_excp_debug_handler(windbg_excp_debug_handler)) {
        exit(1);
    }

    atexit(windbg_exit);
    return 0;
}

#ifdef WINDBG_PARSER
static int packet_counter;

static void windbg_debug_ctx_handler(ParsingContext *ctx)
{
  #ifdef WINDBG_PARSER_FULL_HANDLER
    static FILE *out;
    if (out == NULL) {
        out = fopen("parsed_packets.txt", "w");
    }

    if (ctx->result == RESULT_NONE) {
        return;
    }

    KD_PACKET *pkt = &ctx->packet;

    FPRINT(out, "======\n");
    FPRINT(out, "FROM: %s : %d\n", ctx->name, packet_counter);
    switch (ctx->result) {
    case RESULT_BREAKIN_BYTE:
        FPRINT(out, "CATCH BREAKING BYTE\n");
        break;

    case RESULT_UNKNOWN_PACKET:
        FPRINT(out, "UNKNOWN PACKET TYPE: 0x%x\n", pkt->PacketType);
        break;

    case RESULT_CONTROL_PACKET:
        FPRINT(out, "CONTROL PACKET: %s\n", kd_pkt_type_name(pkt->PacketType));
        FPRINT(out, "id: 0x%x\n", pkt->PacketId);
        break;

    case RESULT_DATA_PACKET:
        FPRINT(out, "DATA PACKET: %s\n", kd_pkt_type_name(pkt->PacketType));
        FPRINT(out, "id: 0x%x\n", pkt->PacketId);

        if (pkt->PacketType == PACKET_TYPE_KD_STATE_MANIPULATE) {
            FPRINT(out, "Api: %s\n", kd_api_name(ctx->data.m64.ApiNumber));
        }

        FPRINT(out, "Raw buffer: [size: %d]\n", pkt->ByteCount);
        FPRINT_MEMORY(out, ctx->data.buf, pkt->ByteCount, 0, false, true);

        if (pkt->PacketType == PACKET_TYPE_KD_STATE_MANIPULATE) {
            switch (ctx->data.m64.ApiNumber) {
            case DbgKdGetVersionApi:
                FPRINT(out, "\n");
                REFLECTION(DBGKD_GET_VERSION64, &ctx->data.m64.u, out,
                    MajorVersion,
                    MinorVersion,
                    ProtocolVersion,
                    KdSecondaryVersion,
                    Flags,
                    MachineType,
                    MaxPacketType,
                    MaxStateChange,
                    MaxManipulate,
                    Simulation,
                    Unused[1],
                    KernBase,
                    PsLoadedModuleList,
                    DebuggerDataList);
                break;
            case DbgKdReadVirtualMemoryApi:
            case DbgKdReadPhysicalMemoryApi:
            case DbgKdReadControlSpaceApi:
                FPRINT(out, "\n");
                REFLECTION(DBGKD_READ_MEMORY64, &ctx->data.m64.u, out,
                    TargetBaseAddress,
                    TransferCount,
                    ActualBytesRead);
                break;
            case DbgKdWriteVirtualMemoryApi:
            case DbgKdWritePhysicalMemoryApi:
            case DbgKdWriteControlSpaceApi:
                FPRINT(out, "\n");
                REFLECTION(DBGKD_WRITE_MEMORY64, &ctx->data.m64.u, out,
                    TargetBaseAddress,
                    TransferCount,
                    ActualBytesWritten);
                break;
            case DbgKdWriteBreakPointApi:
                FPRINT(out, "\n");
                REFLECTION(DBGKD_WRITE_BREAKPOINT64, &ctx->data.m64.u, out,
                    BreakPointAddress,
                    BreakPointHandle);
                break;
            case DbgKdRestoreBreakPointApi:
                FPRINT(out, "\n");
                REFLECTION(DBGKD_RESTORE_BREAKPOINT, &ctx->data.m64.u, out,
                    BreakPointHandle);
                break;
            case DbgKdReadIoSpaceApi:
            case DbgKdWriteIoSpaceApi:
                FPRINT(out, "\n");
                REFLECTION(DBGKD_READ_WRITE_IO64, &ctx->data.m64.u, out,
                    IoAddress,
                    DataSize,
                    DataValue);
                break;
            case DbgKdReadMachineSpecificRegister:
            case DbgKdWriteMachineSpecificRegister:
                FPRINT(out, "\n");
                REFLECTION(DBGKD_READ_WRITE_MSR, &ctx->data.m64.u, out,
                    Msr,
                    DataValueLow,
                    DataValueHigh);
                break;
            case DbgKdSearchMemoryApi:
                FPRINT(out, "\n");
                REFLECTION(DBGKD_SEARCH_MEMORY, &ctx->data.m64.u, out,
                    SearchAddress,
                    SearchLength,
                    PatternLength);
                break;
            case DbgKdFillMemoryApi:
                FPRINT(out, "\n");
                REFLECTION(DBGKD_FILL_MEMORY, &ctx->data.m64.u, out,
                    Address,
                    Length,
                    Flags,
                    PatternLength);
                break;
            case DbgKdQueryMemoryApi:
                FPRINT(out, "\n");
                REFLECTION(DBGKD_QUERY_MEMORY, &ctx->data.m64.u, out,
                    Address,
                    Reserved,
                    AddressSpace,
                    Flags);
                break;
            case DbgKdGetContextExApi:
            case DbgKdSetContextExApi:
                FPRINT(out, "\n");
                REFLECTION(DBGKD_CONTEXT_EX, &ctx->data.m64.u, out,
                    Offset,
                    ByteCount,
                    BytesCopied);
                break;
            default:
                break;
            }
        } else if (pkt->PacketType == PACKET_TYPE_KD_STATE_CHANGE64) {
            FPRINT(out, "\n");
            REFLECTION(DBGKD_ANY_WAIT_STATE_CHANGE, &ctx->data.buf, out,
                NewState,
                ProcessorLevel,
                Processor,
                NumberProcessors,
                Thread,
                ProgramCounter);

            switch (((DBGKD_ANY_WAIT_STATE_CHANGE *) &ctx->data.buf)->NewState) {
            case DbgKdExceptionStateChange:
                REFLECTION(DBGKD_ANY_WAIT_STATE_CHANGE, &ctx->data.buf, out,
                    u.Exception.ExceptionRecord.ExceptionCode,
                    u.Exception.ExceptionRecord.ExceptionFlags,
                    u.Exception.ExceptionRecord.ExceptionRecord,
                    u.Exception.ExceptionRecord.ExceptionAddress,
                    u.Exception.ExceptionRecord.NumberParameters,
                    u.Exception.ExceptionRecord.ExceptionInformation[15],
                    u.Exception.FirstChance);
                break;
            case DbgKdLoadSymbolsStateChange:
                REFLECTION(DBGKD_ANY_WAIT_STATE_CHANGE, &ctx->data.buf, out,
                    u.LoadSymbols.PathNameLength,
                    u.LoadSymbols.BaseOfDll,
                    u.LoadSymbols.ProcessId,
                    u.LoadSymbols.CheckSum,
                    u.LoadSymbols.SizeOfImage,
                    u.LoadSymbols.UnloadSymbols);
                break;
            default:
                break;
            }
            REFLECTION(DBGKD_ANY_WAIT_STATE_CHANGE, &ctx->data.buf, out,
                ControlReport.Dr6,
                ControlReport.Dr7,
                ControlReport.InstructionCount,
                ControlReport.ReportFlags,
                ControlReport.InstructionStream,
                ControlReport.SegCs,
                ControlReport.SegDs,
                ControlReport.SegEs,
                ControlReport.SegFs,
                ControlReport.EFlags);
            FPRINT(out, "\n");
        }
        break;

    case RESULT_ERROR:
        FPRINT(out, "ERROR: CATCH ERROR\n");
        break;

    default:
        break;
    }

    FPRINT(out, "\n");
    fflush(out);
  #endif /* WINDBG_PARSER_FULL_HANDLER */
}

static void windbg_debug_ctx_handler_api(ParsingContext *ctx)
{
  #ifdef WINDBG_PARSER_API_HANDLER
    static FILE *out;
    if (out == NULL) {
        out = fopen("parsed_packets_api.txt", "w");
    }

    switch (ctx->result) {
    case RESULT_BREAKIN_BYTE:
        fprintf(out, "BREAKING BYTE\n");
        break;

    case RESULT_DATA_PACKET:
        if (ctx->packet.PacketType == PACKET_TYPE_KD_STATE_MANIPULATE) {
            fprintf(out, "%s: %d : %s\n", ctx->name, packet_counter,
                    kd_api_name(ctx->data.m64.ApiNumber));
        }
        break;

    default:
        return;
    }

    fflush(out);
  #endif /* WINDBG_PARSER_API_HANDLER */
}

static void windbg_debug_parser(ParsingContext *ctx, const uint8_t *buf,
                                int len)
{
    int i;
    for (i = 0; i < len; ++i) {
        windbg_read_byte(ctx, buf[i]);
        if (ctx->result != RESULT_NONE) {
            ++packet_counter;
            windbg_debug_ctx_handler(ctx);
            windbg_debug_ctx_handler_api(ctx);
        }
    }
}

void windbg_debug_parser_hook(bool is_server, const uint8_t *buf, int len)
{
    if (is_server) {
  #ifdef WINDBG_PARSER_SERVER
        static ParsingContext ctx = { .state = STATE_LEADER,
                                      .result = RESULT_NONE,
                                      .name = "server" };
        windbg_debug_parser(&ctx, buf, len);
  #endif /* WINDBG_PARSER_SERVER */
    } else {
  #ifdef WINDBG_PARSER_CLIENT
        static ParsingContext ctx = { .state = STATE_LEADER,
                                      .result = RESULT_NONE,
                                      .name = "client" };
        windbg_debug_parser(&ctx, buf, len);
  #endif /* WINDBG_PARSER_CLIENT */
    }
}

#endif /* WINDBG_PARSER */
