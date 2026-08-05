// Batch dump driver for irext binaries. JSON goes to the output file
// (argv), library debug printf noise stays on stdout/stderr.
// Usage:
//   irext_dump ac  <file.bin> <sub_cate> <out.json>
//   irext_dump cmd <file.bin> <sub_cate> <max_key> <out.json>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ir_defs.h"
#include "ir_decode.h"

static UINT16 user_data[USER_DATA_SIZE];

static const char *MODE_NAMES[] = {"cool", "heat", "auto", "fan", "dry"};

static void print_durations(FILE *out, UINT16 len) {
    fprintf(out, "[");
    for (UINT16 i = 0; i < len; i++) {
        fprintf(out, i ? ",%u" : "%u", user_data[i]);
    }
    fprintf(out, "]");
}

static int dump_ac(const char *path, UINT8 sub_cate, FILE *out) {
    if (ir_file_open(REMOTE_CATEGORY_AC, sub_cate, path) == IR_DECODE_FAILED) {
        fprintf(stderr, "open failed\n");
        return 1;
    }
    t_remote_ac_status st;
    memset(&st, 0, sizeof(st));

    UINT8 supported_mode = 0;
    if (get_supported_mode(&supported_mode) == IR_DECODE_FAILED || supported_mode == 0) {
        supported_mode = 0xFF;  // try everything; empty frames are skipped
    }

    fprintf(out, "{");
    int first = 1;

    // OFF frame
    st.ac_power = AC_POWER_OFF;
    st.ac_mode = AC_MODE_COOL;
    st.ac_temp = AC_TEMP_25;
    st.ac_wind_dir = AC_SWING_ON;
    st.ac_wind_speed = AC_WS_AUTO;
    UINT16 len = ir_decode(KEY_AC_POWER, user_data, &st);
    if (len > 4 && len < USER_DATA_SIZE) {
        fprintf(out, "\"off\":");
        print_durations(out, len);
        first = 0;
    }

    // Every supported mode x temperature, fan auto, swing on
    for (int m = 0; m < AC_MODE_MAX; m++) {
        if (!(supported_mode & (1 << m))) continue;
        // Range comes back as AC_TEMP enum indexes (0..14); -1/-1 = all temps.
        INT8 tmin = -1, tmax = -1;
        if (get_temperature_range((UINT8)m, &tmin, &tmax) == IR_DECODE_FAILED ||
            tmin < 0 || tmax < 0 || tmax < tmin) {
            tmin = 0; tmax = 14;
        }
        tmin += 16; tmax += 16;
        if (tmax > 30) tmax = 30;
        for (INT8 t = tmin; t <= tmax; t++) {
            st.ac_power = AC_POWER_ON;
            st.ac_mode = (t_ac_mode)m;
            st.ac_temp = (t_ac_temperature)(t - 16);
            st.ac_wind_dir = AC_SWING_ON;
            st.ac_wind_speed = AC_WS_AUTO;
            st.change_wind_direction = 0;
            len = ir_decode(KEY_AC_TEMP_PLUS, user_data, &st);
            if (len > 4 && len < USER_DATA_SIZE) {
                if (!first) fprintf(out, ",");
                fprintf(out, "\"%s.%d\":", MODE_NAMES[m], t);
                print_durations(out, len);
                first = 0;
            }
        }
    }
    fprintf(out, "}");
    ir_close();
    return 0;
}

static int dump_cmd(const char *path, UINT8 sub_cate, int max_key, FILE *out) {
    if (ir_file_open(REMOTE_CATEGORY_TV, sub_cate, path) == IR_DECODE_FAILED) {
        fprintf(stderr, "open failed\n");
        return 1;
    }
    fprintf(out, "{");
    int first = 1;
    for (int k = 0; k <= max_key; k++) {
        UINT16 len = ir_decode((UINT8)k, user_data, NULL);
        if (len > 4 && len < USER_DATA_SIZE) {
            if (!first) fprintf(out, ",");
            fprintf(out, "\"%d\":", k);
            print_durations(out, len);
            first = 0;
        }
    }
    fprintf(out, "}");
    ir_close();
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s ac <file> <sub_cate> <out.json>\n"
                        "       %s cmd <file> <sub_cate> <max_key> <out.json>\n",
                argv[0], argv[0]);
        return 1;
    }
    UINT8 sub = (UINT8)atoi(argv[3]);
    if (sub < 1 || sub > 2) sub = 1;

    int rc;
    FILE *out;
    if (strcmp(argv[1], "ac") == 0) {
        out = fopen(argv[4], "w");
        if (!out) { fprintf(stderr, "cannot write %s\n", argv[4]); return 1; }
        rc = dump_ac(argv[2], sub, out);
    } else {
        if (argc < 6) { fprintf(stderr, "cmd needs max_key + out\n"); return 1; }
        int max_key = atoi(argv[4]);
        out = fopen(argv[5], "w");
        if (!out) { fprintf(stderr, "cannot write %s\n", argv[5]); return 1; }
        rc = dump_cmd(argv[2], sub, max_key, out);
    }
    fclose(out);
    return rc;
}
