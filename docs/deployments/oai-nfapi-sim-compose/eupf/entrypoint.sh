#!/bin/env sh

apk add iproute2

iptables -A FORWARD -j ACCEPT
#ip route add 10.1.0.0/16 via `nslookup upf.free5gc.org | awk '/^Address: / { print $2 }'` dev eth0

echo "1200 n6if" >> /etc/iproute2/rt_tables
ip rule add from 10.60.0.0/16 table n6if
ip rule add from 12.1.1.0/24 table n6if
#ip route add default via `nslookup nat.free5gc.org | awk '/^Address: / { print $2 }'` dev eth0 table n6if
ip route add default via `nslookup natn6.free5gc.org | awk '/^Address: / { print $2 }'` table n6if

# Run app replacing current shell (to preserve signal handling) and forward cmd arguments
exec /app/bin/eupf "$@"