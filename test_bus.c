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
#include <grp.h>
#include <errno.h>

#include <systemd/sd-bus.h>

#include "groupcheck.h"

int main(int argc, char *argv[])
{
    sd_bus *bus = NULL;
    sd_bus_message *msg = NULL, *reply = NULL;
    int r = -1, i;
    const char *action_id;
    const char *name = NULL;
    bool *allowed;
    gid_t supplementary_groups[argc];

    if (argc < 2) {
        fprintf(stderr, "Usage:\n\ttest_bus <action_id> [group1 group2 ...]\n");
        return EXIT_FAILURE;
    }

    action_id = argv[1];

    if (argc > 2) {
        for (i = 0; i < argc-2; i++) {
            struct group *grp;
            grp = getgrnam(argv[i+2]);
            if (grp == NULL) {
                fprintf(stderr, "Error: group '%s' was not found.\n", argv[i+2]);
                goto end;
            }
            supplementary_groups[i] = grp->gr_gid;
        }
        r = setgroups(argc-2, supplementary_groups);
        if (r < 0) {
            fprintf(stderr, "Error setting the supplementary groups: %s\n", strerror(errno));
            goto end;
        }
    }

    r = sd_bus_open_system(&bus);
    if (r < 0) {
        fprintf(stderr, "Error connecting to the system bus: %s\n", strerror(-r));
        goto end;
    }

    r = sd_bus_get_unique_name(bus, &name);
    if (r < 0) {
        fprintf(stderr, "Error getting unique name: %s\n", strerror(-r));
        goto end;
    }

    r = sd_bus_message_new_method_call(bus,
            &msg,
            "org.freedesktop.PolicyKit1",
            "/org/freedesktop/PolicyKit1/Authority",
            "org.freedesktop.PolicyKit1.Authority",
            "CheckAuthorization");
    if (r < 0) {
        fprintf(stderr, "Error creating method call: %s\n", strerror(-r));
        goto end;
    }

    r = sd_bus_message_open_container(msg, SD_BUS_TYPE_STRUCT, "sa{sv}");
    if (r < 0)
        goto end;

    r = sd_bus_message_append(msg, "s", "system-bus-name");
    if (r < 0)
        goto end;

    r = sd_bus_message_open_container(msg, SD_BUS_TYPE_ARRAY, "{sv}");
    if (r < 0)
        goto end;
    
    r = sd_bus_message_open_container(msg, SD_BUS_TYPE_DICT_ENTRY, "sv");
    if (r < 0)
        goto end;

    r = sd_bus_message_append(msg, "s", "name");
    if (r < 0)
        goto end;
    
    r = sd_bus_message_append(msg, "v", "s", name);
    if (r < 0)
        goto end;
    
    /* dict entry */
    r = sd_bus_message_close_container(msg);
    if (r < 0)
        goto end;
    
    /* array */
    r = sd_bus_message_close_container(msg);
    if (r < 0)
        goto end;

    /* struct */
    r = sd_bus_message_close_container(msg);
    if (r < 0)
        goto end;

    r = sd_bus_message_append(msg, "s", action_id);
    if (r < 0)
        goto end;

    r = sd_bus_message_append(msg, "a{ss}", 0, NULL);
    if (r < 0)
        goto end;

    r = sd_bus_message_append(msg, "u", 1);
    if (r < 0)
        goto end;

    r = sd_bus_message_append(msg, "s", "");
    if (r < 0)
        goto end;
    
    r = sd_bus_call(bus, msg, 0, NULL, &reply);
    if (r < 0) {
        fprintf(stderr, "D-Bus method call failed: %s\n", strerror(-r));
        goto end;
    }

    r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_STRUCT, "bba{ss}");
    if (r < 0)
        return r;

    r = sd_bus_message_read(reply, "b", &allowed);
    if (r < 0)
        return r;

    printf("Permission was %sgranted\n", allowed ? "" : "NOT ");

end:

    if (r < 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
