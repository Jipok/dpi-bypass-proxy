# DPI Bypass Proxy

A Go-based proxy tool that redirects blocked or throttled domains through a user-specified SOCKS5 proxy while allowing direct connections for all other traffic. This tool is designed to work on both Linux PCs and routers.

![image](https://github.com/user-attachments/assets/f772e8a4-f3f2-499f-8c6b-5d7d414b6592)

## Features

- Redirects blocked or DPI-throttled domains through a proxy
- Support SOCKS5 proxy or sending though net interface(like wg0)
- Allows direct connections for non-blocked domains
- Configurable proxy list and block list
- Works on Linux PCs and **routers**
- Uses nftables/iptables for transparent proxying

## Usage

1. Download the appropriate binary for your system from the [Releases](https://github.com/Jipok/dpi-bypass-proxy/releases) page.

2. Run the binary with root privileges:

   ```
   sudo ./dpi-bypass-proxy [flags]
   ```

   Common flags:
   - `-socks5`: SOCKS5 proxy address (default: "127.0.0.1:1080")
   - `-interface`: Network interface to use for proxyList domains, ignores `-socks5`
   - `-proxyList`: File with list of domains to proxy (recommended: [antifilter domains.lst](https://antifilter.download/list/domains.lst))
   - `-blockList`: File with list of domains to BLOCK (recommended: [StevenBlack/hosts](https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts))
   - `-v`: Print all dials (verbose mode)

3. The tool will set up iptables rules and start redirecting traffic as configured.

## How It Works

1. The tool sets up iptables rules to redirect incoming HTTPS traffic (port 443) to itself.
2. It reads the server name from the TLS ClientHello message.
3. If the domain is in the block list, the connection is dropped.
4. If the domain is in the proxy list, it's redirected through the SOCKS5 proxy.
5. All other connections are handled directly.


- Requires root privileges to set up nf/iptables rules
- Cleans up iptables rules on exit
- Data copying is done using linux syscall [splice](https://en.wikipedia.org/wiki/Splice_%28system_call%29).
- After start the tool sets GID to 2354
- `-proxyList` and `-blockList` accepts a semicolon-separated list of files. Like `proxy.lst; my.txt`


## Wireguard
By default, when you start Wireguard using the `wg-quick up` command, it configures the system to route all traffic through the Wireguard tunnel. This can interfere with dpi-bypass-proxy's operation, as it won't be able to control which traffic should go through the proxy and which should go directly.

To use dpi-bypass-proxy together with Wireguard:

1. Add the line `Table = off` to the `[Interface]` section of your Wireguard configuration file. For example:

   ```
   [Interface]
   PrivateKey = your_private_key
   Address = 10.0.0.2/24
   Table = off
   ```

   This prevents automatic routing of all traffic through Wireguard.

2. Start Wireguard:

   ```
   sudo wg-quick up wg0
   ```

3. Now run dpi-bypass-proxy, specifying the Wireguard interface using the `-interface` flag:

   ```
   sudo ./dpi-bypass-proxy -interface wg0
   ```

This way, dpi-bypass-proxy will use Wireguard only for domains in the proxy list, while the rest of the traffic will go directly. This allows for more flexible control over which traffic goes through the VPN and which doesn't.
