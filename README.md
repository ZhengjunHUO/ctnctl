# Migrated from [my ciliumlearn project](https://github.com/ZhengjunHUO/ciliumlearn/tree/main/ebpf/ctnctl
# Apply firewall rules to docker container by attaching eBPF program to its cgroups

### Developed and tested under:
- Fedora 32 kernel 5.11.22-100.fc32.x86_64
- Go version 1.17.3
- Cgroup v2
- Docker version 20.10.7 (Cgroup driver: systemd)
- container's cgroup path: /sys/fs/cgroup/system.slice/docker-xxx.scope/

// TODO: add compatibility to elder kernel ; cgroups v1 ; different os/arch

## Build
```bash
make
cp ctnctl /usr/local/bin/ctnctl
```

## Run
```bash
ctnctl -h
Apply firewall rules to container based on eBPF Cgroups

Usage:
  ctnctl [command]

Available Commands:
  block       Add an ip to container's blacklist
  clear       Clear container's firewall rules
  completion  Generate the autocompletion script for the specified shell
  follow      Print out the container's traffic flow
  help        Help about any command
  show        Show container's firewall rules
  unblock     Remove an ip from container's blacklist

Flags:
  -h, --help   help for ctnctl

Use "ctnctl [command] --help" for more information about a command.
```

## Cleanup
```bash
make clean
```
