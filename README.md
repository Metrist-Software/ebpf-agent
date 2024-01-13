# OrchestratorEbpfPlugin

This is an optional plugin for Orchestrator that will attempt to discover
API/Service usage by using [eBPF](https://ebpf.io/).

The plugin is distributed as an x86_64 executable that is separately
packaged. It can be run on the same node as an orchestrator, or on
a different node.

## Limitations

This plugin is a work in progress. For now, only TLS/SSL protected
connections from software using the OpenSSL library are detected.

Wider support will be added in the future.

## Building/development

We use Vagrant to generate supported Virtual Machines for development and
building of executable code. The reason to use VMs (over Docker containers
or straight on the host) is that eBPF can be pretty kernel-version specific
and this gives us the best control.

A [Makefile](Makefile) orchestrates things, see the targets there.

Note that `make dist` assumes that GnuPG is installed with one of the
published [trusted keys](https://github.com/Metrist-Software/orchestrator/blob/main/dist/SIGNING.md)
available to sign the final executable.

## License

Most code in this repository is licensed under the terms of the
Apache License, Version 2.0. See the file [LICENSE.txt](LICENSE.txt)
for details.

Due to Linux kernel requirements, the code in the `probes/` directory
is licensed under the GNU Public License, v3. See the file
[probes/LICENSE.txt](probes/LICENSE.txt) for details.
