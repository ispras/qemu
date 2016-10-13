#include "qemu-common.h"
#include "sysemu/char.h"
#include "sysemu/sysemu.h"
#include "exec/windbgstub.h"
#include "exec/windbgstub-utils.h"

//windbg.exe -b -k com:pipe,baud=115200,port=\\.\pipe\windbg,resets=0
//qemu.exe -windbg pipe:async,windbg

static CharDriverState *windbg_chr = NULL;

static FILE *dump_file;

//TODO: Remove it
static uint32_t cntrl_packet_id = RESET_PACKET_ID;
static UCHAR lock = 0;
//////////////////////////////////////////////////

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
}

static int windbg_chr_can_receive(void *opaque)
{
  /* We can handle an arbitrarily large amount of data.
   Pick the maximum packet size, which is as good as anything.  */
  return PACKET_MAX_SIZE;
}

static void windbg_read_byte(Context *ctx, uint8_t byte)
{

}

static void windbg_in_chr_receive(void *opaque, const uint8_t *buf, int size)
{
    if (lock) {
        int i;

        for (i = 0; i < size; i++) {
            uint8_t tmp = buf[i];
            windbg_read_byte(&input_context, tmp);
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
    lock = 1;f
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
                          windbg_in_chr_receive, NULL,
                          NULL);

    // open dump file
    dump_file = fopen("windbg.dump", "wb");

    atexit(windbg_close);

    return 0;
}