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
#include <errno.h>
#include <stdbool.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>

#define LINE_BUF_SIZE 512
#define MAX_NAME_SIZE 256
#define MAX_GROUPS 10

/* file parser results */

struct line_data {
    char buf[LINE_BUF_SIZE];
    char *id;
    int n_groups;
    char *groups[MAX_GROUPS];
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
    uint32_t pid;
    uint64_t start_time;
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

static bool check_allowed(sd_bus *bus, struct line_data *data,
        struct subject *subject, const char *action_id)
{
    struct line_data *line;
    char **groups = NULL;
    int n_groups = 0;
    int r, i, j;
    sd_bus_creds *creds = NULL;
    uint64_t mask = SD_BUS_CREDS_SUPPLEMENTARY_GIDS | SD_BUS_CREDS_AUGMENT
            | SD_BUS_CREDS_PID | SD_BUS_CREDS_GID;
    gid_t primary_gid;
    const gid_t *gids = NULL;
    int n_gids = 0;

    /* find first the corresponding group data from the policy */

    line = data;

    while (line->id) {
        if (strcmp(line->id, action_id) == 0) {
            groups = line->groups;
            n_groups = line->n_groups;
            break;
        }

        line++;
    }

    if (!groups)
        return false;

    /* check which groups the subject belongs to */

    switch (subject->kind) {
    case SUBJECT_KIND_UNIX_PROCESS:
        mask = _SD_BUS_CREDS_ALL;
        r = sd_bus_creds_new_from_pid(&creds, subject->data.p.pid, mask);
        if (r < 0) {
            goto end;
        }

        n_gids = sd_bus_creds_get_supplementary_gids(creds, &gids);
        if (n_gids < 0)
            goto end;

        r = sd_bus_creds_get_gid(creds, &primary_gid);
        if (r < 0)
            goto end;

        break;

    case SUBJECT_KIND_SYSTEM_BUS_NAME:
        r = sd_bus_get_name_creds(bus, subject->data.b.system_bus_name, mask, &creds);
        if (r < 0)
            goto end;

        n_gids = sd_bus_creds_get_supplementary_gids(creds, &gids);
        if (n_gids < 0)
            goto end;

        r = sd_bus_creds_get_gid(creds, &primary_gid);
        if (r < 0)
            goto end;

        break;

    default:
        /* not supported yet */
        break;
    }

    for (i = 0; i < n_gids; i++) {
        fprintf(stdout, "supplementary gid: %d\n", gids[i]);
    }

    if (gids) {
        struct group *grp;

        /* match the groups */

        for (i = 0; i < n_groups; i++) {
            grp = getgrnam(groups[i]);
            fprintf(stdout, "group: %s (%d)\n", grp->gr_name, grp->gr_gid);
            if (grp == NULL)
                continue;

            for (j = 0; j < n_gids; j++) {

                if (gids[j] == primary_gid) {
                    /* We only include supplementary gids in the check, not the
                       primary gid. This is to make it more difficult for
                       processes to exec a setgid process to gain elevated
                       group access. */
                       continue;
                }

                printf("comparing %d and %d\n", gids[j], grp->gr_gid);
                if (gids[j] == grp->gr_gid) {
                    sd_bus_creds_unref(creds);
                    /* the subject belongs to one of the groups defined in policy */
                    return true;
                }
            }
        }
    }

end:
    sd_bus_creds_unref(creds);
    return false;
}

static void print_decision(struct subject *subject, const char *action_id, bool allowed)
{
    if (subject == NULL || action_id == NULL)
        return;

    switch (subject->kind) {
    case SUBJECT_KIND_UNIX_PROCESS:
        fprintf(stdout, "Unix process (pid: %d, start time: %lu) %sallowed to do action-id %s\n",
                subject->data.p.pid, subject->data.p.start_time, allowed ? "" : "NOT ", action_id);
        break;
    case SUBJECT_KIND_UNIX_SESSION:
        fprintf(stdout, "Unix session (session id: %s) %sallowed to do action-id %s\n",
                subject->data.s.session_id, allowed ? "" : "NOT ", action_id);
        break;
    case SUBJECT_KIND_SYSTEM_BUS_NAME:
        fprintf(stdout, "System bus name %s %sallowed to do action-id %s\n",
                subject->data.b.system_bus_name, allowed ? "" : "NOT ", action_id);
        break;
    default:
        break;
    }
}

static int parse_line(struct line_data *data)
{
    char *p;
    bool has_equals = false;
    bool group_begins = true;

    memset(data->groups, 0, MAX_GROUPS*sizeof(char *));
    data->n_groups = 0;

    /* data->buf has already been initialized with the raw data */

    p = data->id = data->buf;

    while (*p && p != data->buf + sizeof(data->buf)) {
        if (*p == '=') {
            has_equals = true;
            *p = '\0';
            p++;
            break;
        }
        p++;
    }

    if (!has_equals) {
        fprintf(stderr, "Error parsing configuration file.\n");
        return -EINVAL;
    }

    if (*p != '"') {
        fprintf(stderr, "Error parsing configuration file.\n");
        return -EINVAL;
    }

    if (p != data->buf + sizeof(data->buf))
        p++;

    while (*p && p != data->buf + sizeof(data->buf)) {
        if (group_begins) {
            if (data->n_groups >= MAX_GROUPS) {
                fprintf(stderr, "Error: too many groups defined.\n");
                return -EINVAL;
            }
            data->groups[data->n_groups++] = p;
            group_begins = false;
            continue;
        }

        if (*p == ',') {
            group_begins = true;
            *p = '\0';
        }
        else if (*p == '"') {
            /* done parsing the line */
            *p = '\0';
            return 0;
        }
        p++;
    }

    fprintf(stderr, "Error parsing configuration file.\n");
    return -EINVAL;
}

static struct line_data * load_file(const char *filename)
{
    FILE *f;
    char buf[LINE_BUF_SIZE];
    int n_lines = 0;
    int r, i;
    struct line_data *data = NULL;

    f = fopen(filename, "r");

    if (f == NULL)
        return NULL;

    /* The configuration file must be of following format. No whitespaces
     * are allowed except for newlines. First part of the line is the action-id.
     * It is followed by an equation mark and then the comma-separated list of
     * groups inside double quotation marks. Comments are lines starting with
     * '#' character.

       org.freedesktop.login1.reboot="adm,wheel"
       # reboot allowed only for adm group
       org.freedesktop.login1.reboot="adm"

     */

    /* allocate memory for storing the data */
    while (fgets(buf, sizeof(buf), f)) {
        if (strlen(buf) == 0) {
            /* '\0' in line */
            continue;
        }
        else if (buf[0] == '#') {
            /* a comment */
            continue;
        }
        else if (buf[0] == '\n') {
            /* a newline */
            continue;
        }

        data = realloc(data, sizeof(struct line_data)*(n_lines+1));
        memcpy(data[n_lines].buf, buf, LINE_BUF_SIZE);
        n_lines++;
    }

    /* allocate one more line item to be a sentinel and zero it */
    data = realloc(data, sizeof(struct line_data)*(n_lines+1));
    memset(&data[n_lines], 0, sizeof(struct line_data));

    /* parse the lines */
    for (i = 0; i < n_lines; i++) {
        r = parse_line(&data[i]);
        if (r < 0) {
            fclose(f);
            free(data);
            return NULL;
        }
    }

    fclose(f);

    return data;
}

static const char *find_policy_file()
{
    struct stat s;
    const char *dynamic_conf = "/etc/groupcheck.policy";
    const char *default_conf = "/usr/share/defaults/etc/groupcheck.policy";

    if (stat(dynamic_conf, &s) == 0)
        return dynamic_conf;
    else if (stat(default_conf, &s) == 0)
        return default_conf;

    return NULL;
}

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
