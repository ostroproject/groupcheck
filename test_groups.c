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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>

#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>

#include "groupcheck.h"

int main(int argc, char *argv[])
{
    struct line_data *data = NULL;
    int r = -1;
    sd_bus *bus = NULL;
    const char *policy_file;
    const char *action_id;
    struct subject subject = { 0 };
    bool allowed;

    if (argc != 3) {
        fprintf(stderr, "Usage:\n\ttest_groups <policyfile> <action_id>\n");
        return EXIT_FAILURE;
    }

    policy_file = argv[1];
    action_id = argv[2];

    data = load_file(policy_file);
    if (!data) {
        fprintf(stderr, "Error loading policy data.\n");
        goto end;
    }

    r = sd_bus_open_system(&bus);
    if (r < 0) {
        fprintf(stderr, "Error connecting to bus: %s\n", strerror(-r));
        goto end;
    }

    subject.kind = SUBJECT_KIND_UNIX_PROCESS;
    subject.data.p.pid = getpid();

    allowed = check_allowed(bus, data, &subject, action_id);
    print_decision(&subject, action_id, allowed);

end:
    sd_bus_unref(bus);
    free(data);

    if (r < 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
