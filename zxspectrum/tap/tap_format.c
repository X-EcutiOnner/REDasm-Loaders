#include "tap_format.h"
#include <string.h>

static char tap_filename_buf[TAP_FILENAME_LENGTH + 1] = {0};

bool tap_read_block_header(RDReader* r, TapBlockHeader* v) {
    rd_reader_read_byte(r, &v->type);
    rd_reader_read(r, v->filename, sizeof(v->filename));
    rd_reader_read_le16(r, &v->data_length);
    rd_reader_read_le16(r, &v->param1);
    rd_reader_read_le16(r, &v->param2);
    rd_reader_read_byte(r, &v->checksum);

    return !rd_reader_has_error(r);
}

const char* tap_trim_filename(const char* filename, char* out, usize outlen) {
    usize end = TAP_FILENAME_LENGTH;

    while(end > 0 && filename[end - 1] == ' ')
        end--;

    usize n = (end < outlen - 1) ? end : outlen - 1;
    memcpy(out, filename, n);
    out[n] = '\0';
    return out;
}
