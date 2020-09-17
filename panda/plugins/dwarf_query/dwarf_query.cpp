/* PANDABEGINCOMMENT
 *
 *  Authors:
 *  Tiemoko Ballo           N/A
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <iostream>
#include <fstream>
#include <string>
#include <jsoncpp/json/json.h>

#include "panda/plugin.h"
#include "panda/common.h"

#include "dwarf_query_int_fns.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
}

// Globals -------------------------------------------------------------------------------------------------------------

// TODO

// Python CFFI API -----------------------------------------------------------------------------------------------------

// TODO

// Core ----------------------------------------------------------------------------------------------------------------

void load_struct(const Json::Value& struct_entry) {
    // TODO: stuff here
}

void load_func(const Json::Value& func_entry) {
    // TODO: stuff here
}

void load_json(const Json::Value& root) {

    unsigned struct_cnt = 0;
    unsigned func_cnt = 0;
    std::string struct_str("struct");
    std::string base_str("base");

    for (auto sym : root["user_types"]) {

        if (!sym.isNull()) {

            std::string type;

            if (!sym["kind"].isNull()) {
                type.assign(sym["kind"].asString());
            } else if (!sym["type"]["kind"].isNull()) {
                type.assign(sym["type"]["kind"].asString());
            }

            if (type.compare(struct_str) == 0) {
                struct_cnt++;
                load_struct(sym);

                // TODO: temp debug
                printf("Loaded struct \'%s\'\n", type.c_str());
            } else if (type.compare(base_str) == 0) {
                func_cnt++;
                load_func(sym);

                // TODO: temp debug
                printf("Loaded struct \'%s\'\n", type.c_str());
            }
        }
    }

    printf("Loaded %u funcs, %u structs.\n", func_cnt, struct_cnt);
}

// Setup/Teardown ------------------------------------------------------------------------------------------------------

bool init_plugin(void *_self) {

    panda_arg_list *args = panda_get_args("dwarf_query");
    const char* json_filename = panda_parse_string_req(args, "json", "dwarf2json_output.json");
    std::ifstream ifs(json_filename);

    Json::Reader reader;
    Json::Value obj;

    if (!reader.parse(ifs, obj)) {
        fprintf(stderr, "[ERROR] dwarf_query: invalid JSON!\n");
        return false;
    } else {
        load_json(obj);
    }

    switch (panda_os_familyno) {

        case OS_LINUX: {
           return true;
        } break;

        default: {
            fprintf(stderr, "[WARNING] dwarf_query: This has never been tested for a non-Linux OS!\n");
            return true;
        }
    }
}

void uninit_plugin(void *_self) {
    // N/A
}