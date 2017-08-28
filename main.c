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
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>

#include "groupcheck.h"

int main(int argc, char *argv[])
{
    sd_event *e = NULL;
    sd_bus *bus = NULL;
    sd_bus_slot *slot = NULL;
    struct line_data *data = NULL;
    int r = -1;
    const char *policy_file;

    policy_file = find_policy_file();
    if (!policy_file) {
        fprintf(stderr, "Error finding policy data file.\n");
        goto end;
    }

    data = load_file(policy_file);
    if (!data) {
        fprintf(stderr, "Error loading policy data.\n");
        goto end;
    }

    r = sd_event_default(&e);
    if (r < 0) {
        fprintf(stderr, "Error initializing default event: %s\n", strerror(-r));
        goto end;
    }

    r = initialize_bus(&bus, &slot, data);
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

    free(data);

    fprintf(stdout, "Exiting daemon.\n");

    if (r < 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
