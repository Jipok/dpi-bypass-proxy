# DPI Bypass Proxy

A Go-based proxy tool that redirects blocked or throttled domains through a user-specified SOCKS5 proxy while allowing direct connections for all other traffic. This tool is designed to work on both Linux PCs and routers.

## Features

- Redirects blocked or DPI-throttled domains through a SOCKS5 proxy
- Allows direct connections for non-blocked domains
- Configurable proxy list and block list
- Works on Linux PCs and **routers**
- Uses iptables for transparent proxying

## Usage

1. Download the appropriate binary for your system from the [Releases](https://github.com/yourusername/your-repo-name/releases) page.

2. Run the binary with root privileges:

   ```
   sudo ./dpi-bypass-proxy [flags]
   ```

   Available flags:
   - `-socks5`: SOCKS5 proxy address (default: "127.0.0.1:1080")
   - `-proxyList`: File/URL with list of domains to redirect (default: "https://antifilter.download/list/urls.lst")
   - `-blockList`: File/URL with list of domains to BLOCK (default: "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts")
   - `-v`: Print all dials (verbose mode)

3. The tool will set up iptables rules and start redirecting traffic as configured.

## How It Works

1. The tool sets up iptables rules to redirect incoming HTTPS traffic (port 443) to itself.
2. It reads the server name from the TLS ClientHello message.
3. If the domain is in the block list, the connection is dropped.
4. If the domain is in the proxy list, it's redirected through the SOCKS5 proxy.
5. All other connections are handled directly.

## Notes

- Requires root privileges to set up iptables rules
- After setting up rules, the tool drops privileges to UID 2354
- Cleans up iptables rules on exit
