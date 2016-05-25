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

Using groupcheck
----------------

Groupcheck doesn't take any command line parameters. The mapping between
action ids (which action is requested by a service in the system) and
the policy (who is allowed to do the action) is done in a
configuration file. The first path searched for configuration is
`/etc/groupcheck.policy` and the fallback configuration path is at
`/usr/share/defaults/etc/groupcheck.policy`. Policies are read from only
one file.

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

Improvement ideas
-----------------

* Make policy files to be read from a `.d` directory, allowing services
  to drop in their own policy files.
