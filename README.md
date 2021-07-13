# gre-l4-demo

## System Setup

This PoC is run on a MBP running Big Sur 11.4.

The PoC allows for a stateless proxy that handles and rewrites request and response packets at the IP level.

Remote request ==> Proxy ==> Server

and

Remote request <== Proxy <== Server

This PoC allows proof that a programatic proxy library can handle the packet rewrites.

### Update Proxy and remote IPs

In `/localproxy/localproxy.go` there are a variety of IPs and ports that need to be configured to match the PoC setup.
These IP addresses are used for firewall and packet filtering, and although they are not "important" per se, they are required.
Note that the serverIP and serverPort should match the request that we are using on the remote system (aka if you want to use TLS, port 443 should be used).

### Update pf firewall rules

Because the PoC uses pcap instead of `net.ListenIP`, the interfaces return nack packets etc, and cause havoc with our logic.
To prevent this, we use the mac built-in firewall to prevent the packets from reaching the system, and therefore don't have to deal with duplicate responses.
We need to append 2 firewall rules to `/etc/pf.conf`

This is an example with the proxy IP of `192.168.1.114` and proxy port of `9000`

```
block drop in proto tcp to 192.168.1.114 port 9000
block drop out proto tcp from 192.168.1.114 port 9000
```

Once a change to `/etc/pf.conf` is made, the following commands need to be run:

```
sudo pfctl -d # Disable the firewall.
sudo pfctl -f /etc/pf.conf # Reload the firewall configuration.
sudo pfctl -E # Re-enable the firewall.
sudo pfctl -sr # List the firewall rules to confirm the changes are applied.
```

### Start the local proxy

This is a simple: `sudo go run ./localproxy/localproxy.go`.

### Configure the hostfile entry in the remote system

The record for the proxy has to be added into the remote system (`/etc/hosts`) to allow requests to be sent to the proxy.

`192.168.1.114  traefik.io`

### Query the proxy from the remote system

The query can be made from the remote system: `curl -v http://traefik.io:9000 --local-port 32000 --retry 0`.


