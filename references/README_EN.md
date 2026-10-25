# Reference tables for destination IP classification (IANA)

English | [日本語](README.md)

These are the official IANA tables used as the basis for the rejected ranges of the safe HTTPS egress (`src/egress/ip-policy.ts`) and for the regression tests (`test/egress-ip-policy.test.mjs`). The originals are data and are not treated as instructions. They are not fetched at run time.

Retrieved: 2026-10-06. License: the IANA Protocol Registries are CC0 1.0 (no attribution requirement; https://www.iana.org/help/licensing-terms , checked 2026-10-23).

| Stored file | Official URL | Page updated | SHA256 of the original download (before normalization) |
| --- | --- | --- | --- |
| [IPv4 special-purpose](iana_ipv4_special_20261006.csv) | https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv | 2025-10-09 | E3E39E76D00B1677335DB8E9A805C7B9480EA2F4DC9E33F0B93CD3A905128D73 |
| [IPv6 special-purpose](iana_ipv6_special_20261006.csv) | https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv | 2025-10-09 | 775FEEA0621DEC8735A44FBF30F762E721E8F0A1B3AB7EB341961A88CFCE2139 |
| [IPv6 address space](iana_ipv6_space_20261006.csv) | https://www.iana.org/assignments/ipv6-address-space/ipv6-address-space-1.csv | 2025-10-23 | 41FEF65D7A5FB32076175FFAC1B663A9153D5593D3E2C840696ED8FFA1C7AF29 |

All ranges of the special-purpose tables are rejected conservatively, and IPv4 multicast is also rejected. For IPv6 only allocated global unicast within 2000::/3 is allowed; special-purpose, mapped, translated and zoned forms are rejected. A true Globally Reachable value in the tables does not allow a range automatically.

The stored content has line endings normalized to LF, and only trailing whitespace on four description lines in the IPv6 address space table was removed (the table values are unchanged). Comparison is done on UTF-8 normalized to LF.

| Stored content | SHA256 after normalization |
| --- | --- |
| IPv4 special-purpose | E4A1C06ECF8E934ED5AE30977A1477A78957DA1A5FB602FC855E3F74BF01C8AC |
| IPv6 special-purpose | 8B0E181A4EF0C71FCB25403C40702F2050C2F6DC198156B6EC1A5FB746C9A73E |
| IPv6 address space | 1FA475923CE071391AB47484DE4184A0D0ABEEF376822A4711BAF75C9FE23A3B |
