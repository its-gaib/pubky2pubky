#!/usr/bin/env bash
set -euo pipefail

# Runs the real CLI peers behind two independent Linux network namespaces and
# stateful, endpoint-independent translating gateways. A live rendezvous/STUN
# deployment must be reachable at HPK_RENDEZVOUS_CONNECT_IP.

if [[ ${EUID} -ne 0 ]]; then
  printf 'nat-lab.sh must run as root\n' >&2
  exit 1
fi

for command in flock ip iptables mktemp sysctl tc timeout; do
  if ! command -v "$command" >/dev/null; then
    printf 'required command is missing: %s\n' "$command" >&2
    exit 1
  fi
done

hpk_bin=${HPK_BIN:-target/release/hole-punchky}
connect_ip=${HPK_RENDEZVOUS_CONNECT_IP:-}
connect_port=${HPK_RENDEZVOUS_CONNECT_PORT:-8080}

if [[ ! -x $hpk_bin ]]; then
  printf 'Hole Punchky CLI is not executable: %s\n' "$hpk_bin" >&2
  exit 1
fi
if [[ ! $connect_ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  printf 'HPK_RENDEZVOUS_CONNECT_IP must be an IPv4 address\n' >&2
  exit 1
fi
if [[ ! $connect_port =~ ^[0-9]+$ ]] || ((connect_port < 1 || connect_port > 65535)); then
  printf 'HPK_RENDEZVOUS_CONNECT_PORT must be a TCP port\n' >&2
  exit 1
fi
if [[ $(sysctl -n net.ipv4.ip_forward) != 1 ]]; then
  printf 'net.ipv4.ip_forward must be enabled in the parent namespace\n' >&2
  exit 1
fi

exec 9>/run/lock/hole-punchky-nat-lab.lock
if ! flock -n 9; then
  printf 'another Hole Punchky NAT lab is already running\n' >&2
  exit 1
fi

suffix=$(printf '%05d' $((BASHPID % 100000)))
gateway_a="hpk-gwa-$suffix"
gateway_b="hpk-gwb-$suffix"
device_a="hpk-deva-$suffix"
device_b="hpk-devb-$suffix"
root_wan_a="hwa$suffix"
root_wan_b="hwb$suffix"
peer_wan_a="hpa$suffix"
peer_wan_b="hpb$suffix"
gateway_lan_a="hla$suffix"
gateway_lan_b="hlb$suffix"
peer_lan_a="hda$suffix"
peer_lan_b="hdb$suffix"
work_dir=$(mktemp -d /tmp/hole-punchky-nat-lab.XXXXXX)
bob_pid=''
forward_a_added=false
forward_b_added=false

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ -n $bob_pid ]]; then
    kill "$bob_pid" 2>/dev/null || true
    wait "$bob_pid" 2>/dev/null || true
  fi
  if [[ $forward_a_added == true ]]; then
    iptables -w -D FORWARD -i "$root_wan_a" -o "$root_wan_b" -j ACCEPT 2>/dev/null || true
  fi
  if [[ $forward_b_added == true ]]; then
    iptables -w -D FORWARD -i "$root_wan_b" -o "$root_wan_a" -j ACCEPT 2>/dev/null || true
  fi
  for namespace in "$device_a" "$device_b" "$gateway_a" "$gateway_b"; do
    ip netns del "$namespace" 2>/dev/null || true
    if [[ -d /etc/netns/$namespace ]]; then
      find "/etc/netns/$namespace" -depth -delete
    fi
  done
  ip link del "$root_wan_a" 2>/dev/null || true
  ip link del "$root_wan_b" 2>/dev/null || true
  find "$work_dir" -depth -delete
  exit "$status"
}
trap cleanup EXIT INT TERM

for namespace in "$gateway_a" "$gateway_b" "$device_a" "$device_b"; do
  ip netns add "$namespace"
  ip -n "$namespace" link set lo up
done

ip link add "$root_wan_a" type veth peer name "$peer_wan_a"
ip link set "$peer_wan_a" netns "$gateway_a"
ip addr add 198.18.101.1/29 dev "$root_wan_a"
ip link set "$root_wan_a" up
ip -n "$gateway_a" link set "$peer_wan_a" name wan0
ip -n "$gateway_a" addr add 198.18.101.2/29 dev wan0
ip -n "$gateway_a" link set wan0 up

ip link add "$root_wan_b" type veth peer name "$peer_wan_b"
ip link set "$peer_wan_b" netns "$gateway_b"
ip addr add 198.18.102.1/29 dev "$root_wan_b"
ip link set "$root_wan_b" up
ip -n "$gateway_b" link set "$peer_wan_b" name wan0
ip -n "$gateway_b" addr add 198.18.102.2/29 dev wan0
ip -n "$gateway_b" link set wan0 up

ip link add "$gateway_lan_a" type veth peer name "$peer_lan_a"
ip link set "$gateway_lan_a" netns "$gateway_a"
ip link set "$peer_lan_a" netns "$device_a"
ip -n "$gateway_a" link set "$gateway_lan_a" name lan0
ip -n "$gateway_a" addr add 10.201.0.1/24 dev lan0
ip -n "$gateway_a" link set lan0 up
ip -n "$device_a" link set "$peer_lan_a" name eth0
ip -n "$device_a" addr add 10.201.0.2/24 dev eth0
ip -n "$device_a" link set eth0 up

ip link add "$gateway_lan_b" type veth peer name "$peer_lan_b"
ip link set "$gateway_lan_b" netns "$gateway_b"
ip link set "$peer_lan_b" netns "$device_b"
ip -n "$gateway_b" link set "$gateway_lan_b" name lan0
ip -n "$gateway_b" addr add 10.202.0.1/24 dev lan0
ip -n "$gateway_b" link set lan0 up
ip -n "$device_b" link set "$peer_lan_b" name eth0
ip -n "$device_b" addr add 10.202.0.2/24 dev eth0
ip -n "$device_b" link set eth0 up

ip -n "$gateway_a" route add default via 198.18.101.1
ip -n "$gateway_b" route add default via 198.18.102.1
ip -n "$device_a" route add default via 10.201.0.1
ip -n "$device_b" route add default via 10.202.0.1

# .2 is each gateway's transit address. .3 is the translated public address
# routed through that gateway, without assigning it to either interface.
ip route add 198.18.101.3/32 via 198.18.101.2 dev "$root_wan_a"
ip route add 198.18.102.3/32 via 198.18.102.2 dev "$root_wan_b"
ip -n "$gateway_a" route add 198.18.101.3/32 via 10.201.0.2 dev lan0
ip -n "$gateway_b" route add 198.18.102.3/32 via 10.202.0.2 dev lan0

for gateway in "$gateway_a" "$gateway_b"; do
  ip netns exec "$gateway" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$gateway" iptables -w -P FORWARD DROP
  ip netns exec "$gateway" iptables -w -A FORWARD -i lan0 -o wan0 -j ACCEPT
  ip netns exec "$gateway" iptables -w -A FORWARD -i wan0 -o lan0 \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
done

# Rewrite only the IP address at the LAN edge, on opposite sides of conntrack.
# This models endpoint-independent, port-preserving one-to-one NAT. Conntrack
# sees the public tuple and still requires each device to send first before its
# stateful firewall permits the reverse flow; there is no inbound port forward.
install_nat_edge() {
  local gateway=$1 private_ip=$2 public_ip=$3
  ip netns exec "$gateway" tc qdisc add dev lan0 clsact
  ip netns exec "$gateway" tc filter add dev lan0 ingress protocol ip pref 10 \
    flower src_ip "$private_ip" ip_proto udp \
    action pedit ex munge ip src set "$public_ip" pipe action csum ip and udp
  ip netns exec "$gateway" tc filter add dev lan0 ingress protocol ip pref 20 \
    flower src_ip "$private_ip" ip_proto tcp \
    action pedit ex munge ip src set "$public_ip" pipe action csum ip and tcp
  ip netns exec "$gateway" tc filter add dev lan0 egress protocol ip pref 10 \
    flower dst_ip "$public_ip" ip_proto udp \
    action pedit ex munge ip dst set "$private_ip" pipe action csum ip and udp
  ip netns exec "$gateway" tc filter add dev lan0 egress protocol ip pref 20 \
    flower dst_ip "$public_ip" ip_proto tcp \
    action pedit ex munge ip dst set "$private_ip" pipe action csum ip and tcp
}
install_nat_edge "$gateway_a" 10.201.0.2 198.18.101.3
install_nat_edge "$gateway_b" 10.202.0.2 198.18.102.3

iptables -w -I FORWARD 1 -i "$root_wan_a" -o "$root_wan_b" -j ACCEPT
forward_a_added=true
iptables -w -I FORWARD 1 -i "$root_wan_b" -o "$root_wan_a" -j ACCEPT
forward_b_added=true

# The client deliberately permits ws:// only for a loopback hostname. Each
# namespace gets a private hosts file that routes that development hostname to
# the rendezvous address outside both NATs.
for device in "$device_a" "$device_b"; do
  install -d -m 700 "/etc/netns/$device"
  printf '127.0.0.1 loopback\n::1 loopback\n%s localhost\n' "$connect_ip" \
    >"/etc/netns/$device/hosts"
done

alice_init=$(
  "$hpk_bin" init \
    --device-id alice-nat \
    --root-out "$work_dir/alice.root.json" \
    --device-out "$work_dir/alice.device.json"
)
bob_init=$(
  "$hpk_bin" init \
    --device-id bob-nat \
    --root-out "$work_dir/bob.root.json" \
    --device-out "$work_dir/bob.device.json"
)
alice_identity=$(sed -n 's/^identity=//p' <<<"$alice_init")
bob_identity=$(sed -n 's/^identity=//p' <<<"$bob_init")
if [[ -z $alice_identity || -z $bob_identity ]]; then
  printf 'failed to create NAT lab identities\n' >&2
  exit 1
fi

rendezvous_url="ws://localhost:${connect_port}/v1/ws"
timeout 75 ip netns exec "$device_b" "$hpk_bin" listen \
  --device "$work_dir/bob.device.json" \
  --rendezvous "$rendezvous_url" \
  --accept --echo --once >"$work_dir/bob.log" 2>&1 &
bob_pid=$!

for _ in {1..50}; do
  if grep -q '^listening identity=' "$work_dir/bob.log"; then
    break
  fi
  if ! kill -0 "$bob_pid" 2>/dev/null; then
    printf 'Bob listener exited before registration:\n' >&2
    sed -n '1,80p' "$work_dir/bob.log" >&2
    exit 1
  fi
  sleep 0.1
done
if ! grep -q '^listening identity=' "$work_dir/bob.log"; then
  printf 'Bob listener did not register in time\n' >&2
  exit 1
fi

if ! dial_output=$(timeout 75 ip netns exec "$device_a" "$hpk_bin" dial \
  --device "$work_dir/alice.device.json" \
  --peer "$bob_identity" \
  --rendezvous "$rendezvous_url" \
  --message 'hello across two NATs' 2>&1); then
  printf 'Alice dial failed:\n%s\nBob listener:\n' "$dial_output" >&2
  sed -n '1,80p' "$work_dir/bob.log" >&2
  exit 1
fi

for _ in {1..50}; do
  if ! kill -0 "$bob_pid" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
wait "$bob_pid"
bob_pid=''

if [[ $dial_output != *'connected path=Direct'* ]]; then
  printf 'Alice did not nominate a direct candidate:\n%s\n' "$dial_output" >&2
  exit 1
fi
if [[ $dial_output != *'response=hello across two NATs'* ]]; then
  printf 'Alice did not receive Bob echo:\n%s\n' "$dial_output" >&2
  exit 1
fi
if ! grep -q '^connected path=Direct$' "$work_dir/bob.log"; then
  printf 'Bob did not nominate a direct candidate:\n' >&2
  sed -n '1,80p' "$work_dir/bob.log" >&2
  exit 1
fi

printf 'alice_private=10.201.0.2 alice_nat=198.18.101.3 path=Direct\n'
printf 'bob_private=10.202.0.2 bob_nat=198.18.102.3 path=Direct\n'
printf 'echo=hello across two NATs\n'
