# geopacket

An XDP eBPF program and user monitor for geo-filtering ingress packets. It's not a tactic for the long-term, but it sure can come in handy for less sophisticated DDoS attacks that are coming from a specific place and/or aren't making use of IP source spoofing.

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run -g <GEOLOCATIONS_FILE> -d <DISALLOWED> -i <IFACE>
```

The arguments are:
 - `GEOLOCATIONS_FILE`: a file with a CIDR-notated subnet and ISO 3166-1 alpha-2-notated two letter country code separated by a space, each line corresponding to a known mapping between that subnet and its geolocation.
 - `DISALLOWED`: a comma-separated list of ISO 3166-1 alpha-2-notated two letter country codes, specifying for which locations incoming packets should be dropped.
 - `IFACE`: the network interface to which the XDP program should be attached.

## Testing

Because with functionality like this it's quite easy to lock yourself out of a machine that you're accessing via SSH (for instance, if you're in the USA and accidentally specify `us` as a disallowed region), there's also a simple Dockerfile so that any such potentially destructive choices are limited to that test container's network namespace. This container must be run with the `privileged` flag to be allowed to load and attach eBPF programs.

For testing purposes, an easy way to spoof the source IP of ICMP packets sent to the container's IP is:
```bash
sudo iptables -t nat -A POSTROUTING -p icmp -d <CONTAINER_IP> -j SNAT --to-source <SOURCE_IP>
```

Here, `CONTAINER_IP` is the container's IP at its veth connected to the bridge network, likely `172.17.0.2` (so that only packets heading to the container get spoofed), and `SOURCE_IP` is the source address that ICMP packets sent from the host to the container will have. Consult your geolocations file for a subnet from the desired country to test, set `SOURCE_IP` to be a member of that subnet, and then blast away with `ping`. To undo:

```bash
sudo iptables -t nat -D POSTROUTING -p icmp -d <CONTAINER_IP> -j SNAT --to-source <SOURCE_IP>
```

## Todo

 - Observability: eBPF programs are hard to observe, so this is likely best handled by publishing desired metrics, especially regarding any errors, in another BPF map.
 - Perf analysis: again, not trivial, but a well-designed experiment with synthetic loads should be informative. Luckily, results from doing that locally on veths should be just as meaningful as anything else. Amusingly, since fentry/fexit probes can now be attached to BPF programs, collecting perf metrics here is likely a great application for eBPF!
