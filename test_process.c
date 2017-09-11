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
    int r = -1, i, j;
    const char *policy_file;
    const char *action_id;
    struct conf_data conf_data = { 0 };
    struct subject subject;
    bool allowed;

    /* TODO: set supplementary groups to a set we want to test. */

    if (argc != 3) {
        fprintf(stderr, "Usage:\n\ttest_groups <policyfile> <action_id>\n");
        return EXIT_FAILURE;
    }

    policy_file = argv[1];
    action_id = argv[2];

    r = load_file(&conf_data, policy_file);
    if (r < 0) {
        fprintf(stderr, "Error loading policy data.\n");
        goto end;
    }
    print_config(&conf_data);

    subject.kind = SUBJECT_KIND_UNIX_PROCESS;
    subject.data.p.pid = getpid();
    r = get_start_time(subject.data.p.pid, &subject.data.p.start_time);
    if (r < 0) {
        fprintf(stderr, "Error obtaining process start time.\n");
        goto end;
    }

    allowed = check_allowed(NULL, &conf_data, &subject, action_id);
    print_decision(&subject, action_id, allowed);

end:
    for (i = 0; i < conf_data.n_lines; i++) {
        for (j = 0; j < conf_data.lines[i].n_groups; j++) {
            free(conf_data.lines[i].groups[j]);
        }
        free(conf_data.lines[i].id);
    }
    free(conf_data.lines);

    if (r < 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
