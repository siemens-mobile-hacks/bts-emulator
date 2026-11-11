#!/usr/bin/env python3
"""Write the operator proxy and MMSC lists from config/operators.csv into OUTPUT_DIR.

  operator-proxies.nft       nftables defines OPERATOR_PROXIES and OPERATOR_MMSCS with proxy and MMSC IPv4 addresses
  operator-proxy-hosts.txt   proxy host names, one per line
  operator-mmsc-domains.txt  MMSC host names, one per line
  operator-mmsc-ips.txt      MMSC IPv4 addresses, one per line

Usage: operator_config.py OUTPUT_DIR
"""

import csv
import ipaddress
import os
import re
import sys
from urllib.parse import urlsplit

import stack

HOST_NAME = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*")
OPERATORS_CSV = os.path.join(stack.CONFIG_DIR, "operators.csv")


def proxy_host(proxy):
    host, _, port = proxy.rpartition(":")
    if not port.isdigit():
        raise ValueError(f"bad proxy {proxy!r}")
    return host.lower()


def mmsc_host(url):
    host = urlsplit(url).hostname
    if not host:
        raise ValueError(f"bad MMSC URL {url!r}")
    return host


def is_ipv4(host):
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        return False
    return True


def collect(profiles):
    proxy_ips, proxy_names = set(), set()
    mmsc_ips, mmsc_names = set(), set()
    for profile in profiles:
        hosts = [(proxy_host(profile["proxy"]), proxy_ips, proxy_names)] if profile["proxy"] else []
        hosts += [(mmsc_host(url), mmsc_ips, mmsc_names) for url in profile["mmsc"].split()]
        for host, ips, names in hosts:
            if is_ipv4(host):
                ips.add(ipaddress.IPv4Address(host))
            elif HOST_NAME.fullmatch(host):
                names.add(host)
            else:
                raise ValueError(f"bad host {host!r}")
    proxy_ips.discard(ipaddress.IPv4Address("0.0.0.0"))
    return sorted(proxy_ips), sorted(proxy_names), sorted(mmsc_ips), sorted(mmsc_names)


def nft_define(name, ips):
    elements = ",\n".join(f"\t{ip}" for ip in ips)
    return f"define {name} = {{\n{elements}\n}}\n"


def write_lines(path, lines):
    stack.write(path, "".join(f"{line}\n" for line in lines))


def main():
    output_dir = sys.argv[1]
    with open(OPERATORS_CSV, newline="", encoding="utf-8") as file:
        proxy_ips, proxy_names, mmsc_ips, mmsc_names = collect(csv.DictReader(file))

    os.makedirs(output_dir, exist_ok=True)
    stack.write(os.path.join(output_dir, "operator-proxies.nft"),
                nft_define("OPERATOR_PROXIES", proxy_ips) + nft_define("OPERATOR_MMSCS", mmsc_ips))
    write_lines(os.path.join(output_dir, "operator-proxy-hosts.txt"), proxy_names)
    write_lines(os.path.join(output_dir, "operator-mmsc-domains.txt"), mmsc_names)
    write_lines(os.path.join(output_dir, "operator-mmsc-ips.txt"), mmsc_ips)


if __name__ == "__main__":
    main()
