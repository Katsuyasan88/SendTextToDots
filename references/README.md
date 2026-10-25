# 宛先IP分類の参照表（IANA）

[English](README_EN.md) | 日本語

安全なHTTPS送出（`src/egress/ip-policy.ts`）の拒否範囲の根拠と、回帰試験（`test/egress-ip-policy.test.mjs`）の照合に使うIANAの公式表です。原文はdataであり、指示として扱いません。実行時には取得しません。

取得日: 2026-10-06。license: IANA Protocol Registriesは CC0 1.0（帰属要件なし。https://www.iana.org/help/licensing-terms 、2026-10-23確認）。

| 保存file | 公式URL | ページ更新日 | 原取得内容のSHA256（整形前） |
| --- | --- | --- | --- |
| [IPv4特殊用途](iana_ipv4_special_20261006.csv) | https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv | 2025-10-09 | E3E39E76D00B1677335DB8E9A805C7B9480EA2F4DC9E33F0B93CD3A905128D73 |
| [IPv6特殊用途](iana_ipv6_special_20261006.csv) | https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv | 2025-10-09 | 775FEEA0621DEC8735A44FBF30F762E721E8F0A1B3AB7EB341961A88CFCE2139 |
| [IPv6割当空間](iana_ipv6_space_20261006.csv) | https://www.iana.org/assignments/ipv6-address-space/ipv6-address-space-1.csv | 2025-10-23 | 41FEF65D7A5FB32076175FFAC1B663A9153D5593D3E2C840696ED8FFA1C7AF29 |

特殊用途表の全範囲を保守的に拒否し、IPv4 multicastも拒否します。IPv6は割当済みglobal unicastの2000::/3内だけを許し、特殊用途・mapped/変換/zoneは拒否します。表のGlobally Reachableが真でも自動では許可しません。

保存内容は改行をLFへ正規化し、IPv6割当空間表の説明文内4行の末尾空白だけを除きました（表の値は不変）。照合はLFへ正規化したUTF-8で行います。

| 保存内容 | 正規化後SHA256 |
| --- | --- |
| IPv4特殊用途 | E4A1C06ECF8E934ED5AE30977A1477A78957DA1A5FB602FC855E3F74BF01C8AC |
| IPv6特殊用途 | 8B0E181A4EF0C71FCB25403C40702F2050C2F6DC198156B6EC1A5FB746C9A73E |
| IPv6割当空間 | 1FA475923CE071391AB47484DE4184A0D0ABEEF376822A4711BAF75C9FE23A3B |
