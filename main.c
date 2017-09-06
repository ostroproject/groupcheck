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
#include <unistd.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>

#include "groupcheck.h"

void usage(char *argv[])
{
    fprintf(stderr, "Usage: %s [-d config_directory] [-f config_file]\n",
            argv[0]);
}

int main(int argc, char *argv[])
{
    sd_event *e = NULL;
    sd_bus *bus = NULL;
    sd_bus_slot *slot = NULL;
    struct conf_data conf_data = { 0 };
    int r = -1;
    const char *policy_files[32];
    const char *policy_directories[32];
    int n_files = 0, n_directories = 0;
    int i, j;
    int opt = getopt(argc, argv, "d:f:");

    if (opt == -1) {
        usage(argv);
        goto end;
    }

    while (opt != -1) {
        switch (opt) {
            case 'd':
                if (n_directories < 32)
                    policy_directories[n_directories++] = optarg;
                else {
                    fprintf(stderr, "Error: too many policy directories\n");
                    goto end;
                }
                break;
            case 'f':
                if (n_files < 32)
                    policy_files[n_files++] = optarg;
                else {
                    fprintf(stderr, "Error: too many policy files\n");
                    goto end;
                }
                break;
            default:
                usage(argv);
                goto end;
        }

        opt = getopt(argc, argv, "d:f:");
    }

    if (optind < argc) {
        usage(argv);
        goto end;
    }

    for (i = 0; i < n_directories; i++) {
        r = load_directory(&conf_data, policy_directories[i]);
        if (r < 0) {
            fprintf(stderr, "Error loading configuration directory %s: %s\n",
                policy_directories[i], strerror(-r));
            goto end;
        }
    }
    for (i = 0; i < n_files; i++) {
        r = load_file(&conf_data, policy_files[i]);
        if (r < 0) {
            fprintf(stderr, "Error loading configuration file %s: %s\n",
                policy_files[i], strerror(-r));
            goto end;
        }
    }

    r = sd_event_default(&e);
    if (r < 0) {
        fprintf(stderr, "Error initializing default event: %s\n", strerror(-r));
        goto end;
    }

    r = initialize_bus(&bus, &slot, &conf_data);
    if (r < 0) {
        fprintf(stderr, "Error initializing D-Bus connection: %s\n", strerror(-r));
        goto end;
    }

    r = sd_bus_attach_event(bus, e, 0);
    if (r < 0) {
        fprintf(stderr, "Error attaching bus to event loop: %s\n", strerror(-r));
        goto end;
    }

    r = sd_event_loop(e);
    if (r < 0) {
        fprintf(stderr, "Exited from event loop with error: %s\n", strerror(-r));
    }

end:
    if (slot)
        sd_bus_slot_unref(slot);
    if (bus)
        sd_bus_unref(bus);
    if (e)
        sd_event_unref(e);

    for (i = 0; i < conf_data.n_lines; i++) {
        for (j = 0; j < conf_data.lines[i].n_groups; j++) {
            free(conf_data.lines[i].groups[j]);
        }
        free(conf_data.lines[i].id);
    }
    free(conf_data.lines);

    fprintf(stdout, "Exiting daemon.\n");

    if (r < 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
