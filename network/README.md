# VoidFlame Network Protection

This directory contains host/proxy-side defensive controls for a Minecraft server.

## Architecture

Internet -> upstream DDoS protection/provider -> HAProxy TCP proxy -> Minecraft backend

The Minecraft plugin protects player/session behavior. These files protect the host/proxy from connection floods and abusive connection patterns.

These controls are not a substitute for upstream volumetric DDoS scrubbing. If the uplink is saturated, the traffic must be filtered upstream.

## Deployment

1. Put HAProxy on the public edge host and keep the Minecraft backend bound to a private interface/firewall-restricted port.
2. Replace BACKEND_IP and PUBLIC_MINECRAFT_PORT in `haproxy.cfg`.
3. Load `nftables.conf` only after reviewing your SSH/admin source networks.
4. Install the Fail2Ban jail/filter and adjust the log path to the proxy log.
5. Keep the Minecraft backend inaccessible directly from the public Internet.
6. Test with normal clients before enabling aggressive limits.

Default limits are deliberately conservative to avoid blocking normal reconnects or shared-NAT players.
