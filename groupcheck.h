/*
 * groupcheck is a minimal polkit replacement for group-based authentication.
 * Copyright (c) 2016, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU Lesser General Public License,
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for
 * more details.
 */

#pragma once

#include <stdbool.h>
#include <systemd/sd-bus.h>

#define LINE_BUF_SIZE 512
#define MAX_NAME_SIZE 256
#define MAX_GROUPS 10

/* file parser results */

struct line_data {
    char *id;
    int n_groups;
    char *groups[MAX_GROUPS];
};

struct conf_data {
    struct line_data *lines;
    int n_lines;
};

/* D-Bus message analysis */

enum subject_kind {
    SUBJECT_KIND_UNKNOWN = 0,
    SUBJECT_KIND_UNIX_PROCESS,
    SUBJECT_KIND_UNIX_SESSION,
    SUBJECT_KIND_SYSTEM_BUS_NAME,
};

struct subject_unix_session {
    char session_id[MAX_NAME_SIZE];
};

struct subject_unix_process {
    uint64_t start_time;
    uint32_t pid;
};

struct subject_system_bus {
    char system_bus_name[MAX_NAME_SIZE];
};

struct subject {
    enum subject_kind kind;
    union {
        struct subject_unix_session s;
        struct subject_unix_process p;
        struct subject_system_bus b;
    } data;
};

/* Initialize D-Bus server. "bus" and "slot" parameters are output
 * parameters, "data" is an input parameter. */
int initialize_bus(sd_bus **bus, sd_bus_slot **slot, struct conf_data *data);

/* Load a policy file. The resulting struct must be freed by the caller. */
int load_file(struct conf_data *conf_data, const char *filename);
int load_directory(struct conf_data *conf_data, const char *filename);

/* Exported for test programs. */
void print_decision(struct subject *subject, const char *action_id, bool allowed);
bool check_allowed(sd_bus *bus, struct conf_data *conf_data, struct subject *subject, const char *action_id);
