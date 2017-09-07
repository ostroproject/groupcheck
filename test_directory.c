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

#include "groupcheck.h"

int main(int argc, char *argv[])
{
    int r = -1, i, j;
    const char *policy_directory;
    struct conf_data conf_data = { 0 };

    if (argc != 2) {
        fprintf(stderr, "Usage:\n\ttest_directory <policydir>\n");
        return EXIT_FAILURE;
    }

    policy_directory = argv[1];

    r = load_directory(&conf_data, policy_directory);
    if (r < 0) {
        fprintf(stderr, "Error loading policy data.\n");
        goto end;
    }

    if (conf_data.n_lines != 2) {
        fprintf(stderr, "Expected two config lines (had %i).\n", conf_data.n_lines);
        goto end;
    }

    printf("First line : id: %s\n", conf_data.lines[0].id);
    printf("           : groups: ");
    for (i = 0; i < conf_data.lines[0].n_groups; i++) {
        printf("%s ", conf_data.lines[0].groups[i]);
    }
    printf("\n");

    printf("Second line: id: %s\n", conf_data.lines[1].id);
    printf("           : groups: ");
    for (i = 0; i < conf_data.lines[1].n_groups; i++) {
        printf("%s ", conf_data.lines[1].groups[i]);
    }
    printf("\n");
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
