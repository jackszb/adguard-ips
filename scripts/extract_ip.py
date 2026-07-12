#!/usr/bin/env python3
r"""
从 AdGuard DNS Filter 列表中提取 IP / CIDR 规则，生成 adguard-ip.json。

支持两种规则形式：
1. 字面量规则：  ||1.2.3.4^        ||1.2.3.0/24^
2. 正则表达式规则： /^1\.2\.3\.(4[0-9]|5[0-4]):/  等（AdGuard 部分规则用正则匹配一段 IP）

正则规则通过 exrex 枚举每个八位组可能取值，再用 ipaddress.collapse_addresses
折叠成最少数量的 CIDR。若某一行正则解析失败或过于宽泛（无法安全判断范围），
该行会被跳过并打印警告，不会中断整个任务。
"""  # noqa: W605

import re
import sys
import json
import ipaddress
import itertools
import urllib.request

try:
    import exrex
except ImportError:
    exrex = None

SOURCE_URL = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
OUTPUT_FILE = "adguard-ip.json"

LITERAL_RULE_RE = re.compile(r'\|\|(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\^')

# 单个八位组组合上限，超过则认为该行规则过于宽泛/无法安全展开，跳过
MAX_OCTET_COMBINATIONS = 20000
MAX_EXREX_ENUM = 5000


def fetch_source(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def is_valid_ip_or_cidr(s: str) -> bool:
    try:
        if "/" in s:
            ipaddress.ip_network(s, strict=False)
        else:
            ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def extract_literal_ips(text: str) -> set:
    """提取 ||IP[/CIDR]^ 形式的字面量规则（忽略白名单 @@ 规则和注释行）。"""
    ips = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("!") or line.startswith("@@"):
            continue
        for m in LITERAL_RULE_RE.finditer(line):
            candidate = m.group(1)
            if is_valid_ip_or_cidr(candidate):
                ips.add(candidate)
    return ips


def _enumerate_octet_values(segment: str):
    """
    枚举一个八位组正则片段可能代表的所有整数值 (0-255)。
    解析失败或范围过大（比如通配符后缀）时返回 None。
    """
    if exrex is None or not segment:
        return None

    seg = segment
    if seg.endswith("$"):
        seg = seg[:-1]

    # 在顶层（不在括号内）查找 ':'，之后的内容（比如端口号）不属于本八位组
    depth = 0
    colon_idx = None
    for i, ch in enumerate(seg):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == ":" and depth == 0:
            colon_idx = i
            break
    if colon_idx is not None:
        seg = seg[:colon_idx]

    if not seg:
        return None

    # 明显的通配符后缀（如 .{100,}），无法安全当作单个八位组处理
    if seg.startswith(".") or seg.startswith("{"):
        return None

    try:
        values = set()
        count = 0
        for s in exrex.generate(seg):
            count += 1
            if count > MAX_EXREX_ENUM:
                return None
            if s.isdigit():
                v = int(s)
                if 0 <= v <= 255:
                    values.add(v)
        return values or None
    except Exception:
        return None


def _literal_or_values(segment: str):
    if segment.isdigit():
        return {int(segment)}
    return _enumerate_octet_values(segment)


def _leading_segment_values(segment: str):
    """
    第一个八位组片段有时前面带有额外前缀（例如 '(https?:\\/\\/)213'），
    这里优先尝试直接判断是否纯数字，否则截取结尾的连续数字。
    """
    if segment.isdigit():
        return {int(segment)}
    m = re.search(r"(\d{1,3})$", segment)
    if m:
        return {int(m.group(1))}
    return _enumerate_octet_values(segment)


def parse_regex_ip_line(line: str):
    r"""
    解析形如 /^1\.2\.3\.(4[0-9]|5[0-4]):/ 或
    /(https?:\/\/)1\.2\.3\..{100,}/ 这样的正则行，
    返回覆盖到的最小 CIDR 列表（字符串），解析失败返回 None。
    """
    if not (line.startswith("/") and line.endswith("/")):
        return None

    body = line[1:-1]
    if body.startswith("^"):
        body = body[1:]

    if r"\." not in body:
        return None

    segments = body.split(r"\.")
    if len(segments) < 3:
        return None

    o1_vals = _leading_segment_values(segments[0])
    o2_vals = _literal_or_values(segments[1])
    o3_vals = _literal_or_values(segments[2])

    if not (o1_vals and o2_vals and o3_vals):
        return None

    o4_vals = _enumerate_octet_values(segments[3]) if len(segments) >= 4 else None

    # 第4个八位组无法安全解析（例如通配符后缀 .{100,}、或压根没有第4段），
    # 退而求其次：视为覆盖 o1.o2.o3.0/24 整个网段
    if o4_vals is None:
        nets = {f"{a}.{b}.{c}.0/24" for a, b, c in itertools.product(o1_vals, o2_vals, o3_vals)}
        return sorted(nets)

    total = len(o1_vals) * len(o2_vals) * len(o3_vals) * len(o4_vals)
    if total > MAX_OCTET_COMBINATIONS:
        return None

    ips = []
    for a, b, c, d in itertools.product(o1_vals, o2_vals, o3_vals, o4_vals):
        try:
            ips.append(ipaddress.IPv4Address(f"{a}.{b}.{c}.{d}"))
        except ValueError:
            continue

    if not ips:
        return None

    networks = [ipaddress.ip_network(f"{ip}/32") for ip in ips]
    collapsed = ipaddress.collapse_addresses(networks)
    return [str(n) for n in collapsed]


def extract_regex_ips(text: str) -> set:
    """提取正则表达式形式表示的 IP 段规则。"""
    results = set()
    if exrex is None:
        print("WARNING: exrex 未安装，跳过所有正则 IP 规则解析。", file=sys.stderr)
        return results

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not (line.startswith("/") and line.endswith("/")):
            continue
        # 快速过滤：行内必须包含至少两段 "数字\." 这种转义八位组，
        # 否则不太可能是一条基于正则的 IP 规则
        if len(re.findall(r"\d{1,3}\\\.", line)) < 2:
            continue
        try:
            nets = parse_regex_ip_line(line)
        except Exception as e:
            print(f"WARNING: 解析正则行失败，已跳过: {line!r} ({e})", file=sys.stderr)
            nets = None
        if nets:
            results.update(nets)
    return results


def sort_key(cidr: str):
    net = ipaddress.ip_network(cidr, strict=False)
    return (int(net.network_address), net.prefixlen)


def main():
    text = fetch_source(SOURCE_URL)

    literal_ips = extract_literal_ips(text)
    regex_ips = extract_regex_ips(text)

    merged = literal_ips | regex_ips
    networks = [ipaddress.ip_network(cidr, strict=False) for cidr in merged]
    collapsed = ipaddress.collapse_addresses(networks)

    def fmt(net):
        # 单个 IP（/32）去掉掩码后缀，保持和示例一致的写法
        if net.prefixlen == 32:
            return str(net.network_address)
        return str(net)

    all_ips = sorted((fmt(n) for n in collapsed), key=sort_key)

    data = {
        "version": 3,
        "rules": [
            {"ip_cidr": all_ips}
        ],
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"字面量 IP/CIDR 规则: {len(literal_ips)} 条")
    print(f"正则展开 IP/CIDR 规则: {len(regex_ips)} 条")
    print(f"共写入 {len(all_ips)} 条 -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
