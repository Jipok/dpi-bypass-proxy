# DNSR (DNS Router)

> [!NOTE]
> **Major Update (4.0)**: 
> - Now uses DNS-based routing instead of transparent proxy
> - Better performance and reliability, especially on routers
> - If you need SOCKS5 proxy support, use old [v3 release](https://github.com/Jipok/dpi-bypass-proxy/releases/tag/3.0.0)

A tool that automatically routes traffic through VPN or any other network interface based on DNS responses. Designed to bypass DPI blocks and throttling while keeping other traffic direct. Works on both Linux PCs and **routers**.

## Key Features

- Bypasses DPI blocks and throttling for specified domains
- Works on Linux PCs and routers (OpenWrt, etc.)
- Selective domain routing through any network interface
- Built-in WireGuard support (can automatically set up from config)
- Support for OpenVPN, WireGuard, or any other network interface
- DNS-based traffic analysis and routing
- Domain blocking capability
- Automatically cleans up routes and rules on exit
- Memory-efficient domain matching with glob pattern support

## Usage

1. Download the [latest release](https://github.com/Jipok/dpi-bypass-proxy/releases/latest) or build from source
2. Prepare your domain lists:
   ```bash
   # For proxy list (recommended)
   wget https://github.com/1andrevich/Re-filter-lists/raw/refs/heads/main/domains_all.lst -O proxy.lst
   
   # For block list (optional)
   wget https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts -O blocks.lst
   ```

3. Run with either a WireGuard config or existing interface:
   ```bash
   # Using WireGuard config (automatic setup)
   sudo ./dnsr ~/my-wireguard.conf
   
   # Or using any existing network interface
   sudo ./dnsr --interface tun0    # OpenVPN interface
   sudo ./dnsr --interface wg0     # WireGuard interface
   ```

### Command Line Options

```
Usage: dnsr [--interface INTERFACE] [--proxy-list PROXY-LIST] [--block-list BLOCK-LIST] 
           [--silent] [--verbose] [--no-clear] [WG-CONFIG]

Positional arguments:
  WG-CONFIG             Path to WireGuard configuration file (optional)

Options:
  --interface, -i      Use existing network interface (OpenVPN, WireGuard, etc.)
  --proxy-list         Domains to route through specified interface [default: proxy.lst]
  --block-list         Domains to block [default: blocks.lst]
  --preset-ips         File with IP addresses to proxy immediately, without waiting for DNS resolution
  --silent, -s         Don't show when new routes are added
  --verbose, -v        Enable verbose output
  --persistent, -p     Keep WireGuard interface (if created) and routes after exit
  --help, -h           Show this help message
  --version            Show version

Multiple proxy/block/ips lists can be specified using semicolon (;)
Example: proxy1.lst;proxy2.lst;proxy3.lst
```

## How It Works

1. The tool monitors DNS responses using NFQUEUE
2. When a domain from the proxy list is resolved:
   - Creates specific routes for the resolved IP addresses
   - Directs matching traffic through specified interface
3. All other traffic continues to use the default route
4. Domains in the block list are dropped
