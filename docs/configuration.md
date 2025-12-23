# Configuration

The operation of the syzkaller `syz-manager` process is governed by a
configuration file, passed at invocation time with the `-config` option.
This configuration can be based on the [example](/pkg/mgrconfig/testdata/qemu-example.cfg);
the file is in JSON format and contains the the [following parameters](/pkg/mgrconfig/config.go).

## Kernel objects

`kernel_obj` still points at the directory that contains the unstripped
kernel binary and modules. When several instrumented binaries are produced
from the same directory, set the optional `vmlinux` field to the absolute
path of the exact kernel object file that syzkaller should use for
symbolization, coverage processing, and KFuzzTest activation. When the field
is omitted syzkaller falls back to `<kernel_obj>/<target kernel_object>`.

## Crash filtering

Set `ignore_warning_crashes` to `true` to completely skip kernel reports whose
first line contains the word `WARNING`. This prevents benign warning splats
from being treated as crashes and keeps fuzzing progress uninterrupted. For
fine grained filtering, continue to use the existing `suppressions` and
`ignores` arrays.

## QEMU VM options

The following options can be specified in the `vm` section when using the QEMU VM type:

### `ssh_port`

Set `ssh_port` to specify a base SSH port for VM instances. When specified, VM instances
will use sequential ports starting from this value (`ssh_port + index`). For example,
if `ssh_port` is set to 10022 with 4 VMs, the VMs will use ports 10022, 10023, 10024,
and 10025 respectively.

If not specified (0), random available ports will be automatically selected for each VM.

This option is useful when you need:
- Predictable SSH ports for external scripts or debugging
- To avoid port conflicts with other services
- To configure firewall rules in advance

Example configuration:
```json
{
    "vm": {
        "count": 4,
        "ssh_port": 10022,
        "kernel": "/path/to/bzImage",
        "cpu": 2,
        "mem": 2048
    }
}
```
