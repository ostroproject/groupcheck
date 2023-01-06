DISCONTINUATION OF PROJECT

This project will no longer be maintained by Intel.

Intel has ceased development and contributions including, but not limited to, maintenance, bug fixes, new releases, or updates, to this project.  

Intel no longer accepts patches to this project.

If you have an ongoing need to use this project, are interested in independently developing it, or would like to maintain patches for the open source software community, please create your own fork of this project.  
GROUPCHECK
==========

Groupcheck is a drop-in
[polkit](https://www.freedesktop.org/wiki/Software/polkit/) replacement
for embedded systems. It only supports authentication by group
membership. Groupcheck is licensed with LGPLv2.1.

Why groupcheck?
---------------

Groupcheck is a minimal service, written in C for speed. The binary size
is expected to be around 19 kB. Groupcheck's only external dependency is
libsystemd. Because libsystemd is already in use in all systemd-based
distributions, groupcheck's practical memory footprint is very small.

Polkit is not very suitable for embedded systems, because the policy
rules are written in JavaScript. Polkit uses Mozilla's large JavaScript
engine to run the policy scripts. Many polkit features are
desktop-focused, such as providing authorization backends so that the
user may be queried for permission to perform an action. In a typical
embedded system, the "user" concept is different from desktop use.
Groupcheck does not implement those parts of polkit D-Bus API that deal
with registration of authorization backends.

```
                .------------.
                | groupcheck |
                '------------'
                      ^ | allowed/disallowed
   CheckAuthorization | |
   (action,process)   | v
              .----------------.
              | system service |----> if allowed, perform
              '----------------'      the requested action
                       ^
                       |
        request action |
           .----------------------.
           | process requesting a |
           | a system service to  |
           | do something         |
           '----------------------'
```

Using groupcheck
----------------

Groupcheck doesn't take any command line parameters. The mapping between
action ids (which action is requested by a service in the system) and
the policy (who is allowed to do the action) is done in configuration
files.

Configuration files can either be loaded as simple files (using
`-f configuration_file` command line parameter) or as a directory
containing configuration files (using `-d configuration_directory`
command line parameter. At least one file or directory must be
specified on the command line.

Policy files look like this:

    # let both adm and wheel groups trigger service file reload
    org.freedesktop.systemd1.reload-daemon="adm,wheel"
    org.freedesktop.login1.reboot="adm"

Lines starting with `#` are comments. For all other lines, the first
item in the line is the action id. It's followed by an equals sign,
after which comes a comma-separated list of groups which will be allowed
to do to the action. The group list is within `"` characters.
Whitespaces within lines are not allowed.

The example policy file means that uids in groups `adm` or `wheel` are
allowed to do action `org.freedesktop.systemd1.reload-daemon` and uids
in group `adm` is allowed to do action `org.freedesktop.login1.reboot`.
Other uids are not allowed to do either action. Actions not listed in
the policy file are not allowed.

Caller responsibilities
-----------------------

Groupcheck works in asynchronous fashion. When a request comes in, groupcheck
does its policy evaluation based on the best information available at the time.
The caller (typically a system service) needs to ensure that nothing that
affects the evaluation has changed between the time the request to groupcheck is
made and the answer comes back. For example, if a process requests the system
service to perform an action and then dies, the answer from groupcheck based on
the PID is no longer valid, because the PID can now belong to completely
different process. The same concept applies also to things like D-Bus connection
IDs.
