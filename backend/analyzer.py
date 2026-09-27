"""
SIH26106 - AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence
Core analysis engine.

Pipeline:
  raw .eml text -> parse_email() -> hop extraction -> geolocate hops
                -> authentication check -> content/link analysis
                -> weighted "AI" risk scoring -> structured report dict
"""

import re
import email
import hashlib
import ipaddress
from email import policy
from urllib.parse import urlparse
import requests

# --------------------------------------------------------------------------
# 1. Reference intelligence tables (would be pulled from a live threat feed
#    in production; kept local here so the demo runs fully offline for the
#    parts that don't need geolocation).
# --------------------------------------------------------------------------

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st",
}

# Weighted phishing-language lexicon. This is the lightweight "AI" language
# model used for the demo: a weighted bag-of-terms scorer. It is written so
# it can be swapped for a trained classifier (e.g. sklearn / transformers)
# without changing the rest of the pipeline - see classify_text().
PHISH_LEXICON = {
    "verify your account": 12, "account suspended": 14, "click here": 8,
    "urgent action required": 12, "confirm your identity": 10,
    "unusual activity": 9, "limited time": 6, "wire transfer": 14,
    "gift card": 12, "bitcoin": 10, "crypto": 8, "password expired": 12,
    "update your payment": 11, "your account will be closed": 13,
    "act now": 8, "security alert": 9, "invoice attached": 7,
    "immediate attention": 9, "irs": 10, "tax refund": 10,
    "lottery": 12, "winner": 8, "prize": 7, "ceo": 5, "wire the funds": 14,
}

SUSPICIOUS_ATTACH_EXT = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar", ".ps1",
    ".msi", ".hta", ".wsf", ".lnk",
}

PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "::1/128", "fc00::/7",
)]

IP_RE = re.compile(
    r"((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})"
)
URL_RE = re.compile(r"https?://[^\s\"'<>\)]+", re.IGNORECASE)


# --------------------------------------------------------------------------
# 2. Header / hop parsing
# --------------------------------------------------------------------------

def _is_private_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_NETS)
    except ValueError:
        return True


def extract_ips_from_received(received_value):
    return list(dict.fromkeys(IP_RE.findall(received_value)))


def parse_received_chain(msg):
    """Return hops oldest->newest, each with the raw line and any IPs found."""
    received_headers = msg.get_all("Received", [])
    hops = []
    # Received headers appear newest-first in the raw message; reverse so
    # index 0 is the originating (oldest) hop, matching the real delivery path.
    for i, raw in enumerate(reversed(received_headers)):
        ips = extract_ips_from_received(raw)
        from_match = re.search(r"from\s+([^\s]+)", raw)
        by_match = re.search(r"by\s+([^\s]+)", raw)
        date_match = re.search(r";\s*(.+)$", raw)
        hops.append({
            "hop_index": i,
            "raw": raw.strip(),
            "from_host": from_match.group(1) if from_match else None,
            "by_host": by_match.group(1) if by_match else None,
            "timestamp": date_match.group(1).strip() if date_match else None,
            "ips": ips,
            "public_ips": [ip for ip in ips if not _is_private_ip(ip)],
        })
    return hops


def parse_authentication_results(msg):
    """Extract spf / dkim / dmarc verdicts from Authentication-Results."""
    auth_headers = " ".join(msg.get_all("Authentication-Results", []) or [])
    result = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", auth_headers, re.IGNORECASE)
        result[mech] = m.group(1).lower() if m else "none"
    return result


def domain_of(address):
    if not address:
        return None
    m = re.search(r"@([\w\.-]+)", address)
    return m.group(1).lower() if m else None


def extract_body_and_links(msg):
    text_parts = []
    links = []
    if msg.is_multipart():
        parts = msg.walk()
    else:
        parts = [msg]
    for part in parts:
        ctype = part.get_content_type()
        if ctype in ("text/plain", "text/html"):
            try:
                content = part.get_content()
            except Exception:
                content = ""
            if isinstance(content, str):
                text_parts.append(content)
                links.extend(URL_RE.findall(content))
                if ctype == "text/html":
                    # anchor text vs href mismatch detection
                    for href, anchor in re.findall(
                        r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                        content, re.IGNORECASE | re.DOTALL,
                    ):
                        anchor_urls = URL_RE.findall(anchor)
                        for au in anchor_urls:
                            if urlparse(au).netloc and urlparse(au).netloc != urlparse(href).netloc:
                                links.append(href)  # ensure captured
    return "\n".join(text_parts), list(dict.fromkeys(links))


def analyze_links(links):
    findings = []
    for link in links:
        parsed = urlparse(link)
        host = parsed.netloc.lower()
        issues = []
        if IP_RE.fullmatch(host.split(":")[0] or ""):
            issues.append("Uses raw IP address instead of a domain name")
        if any(sh in host for sh in URL_SHORTENERS):
            issues.append("Known URL-shortener domain (masks true destination)")
        if host.count("-") >= 3:
            issues.append("Unusually hyphen-heavy domain, common in lookalike phishing sites")
        if re.search(r"(paypal|bank|apple|microsoft|google|amazon)-", host):
            issues.append("Brand name combined with extra text - possible lookalike domain")
        if issues:
            findings.append({"url": link, "issues": issues})
    return findings


def extract_attachments(msg):
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            filename = part.get_filename()
            if filename:
                try:
                    payload = part.get_payload(decode=True) or b""
                except Exception:
                    payload = b""
                ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
                attachments.append({
                    "filename": filename,
                    "content_type": part.get_content_type(),
                    "size_bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest() if payload else None,
                    "md5": hashlib.md5(payload).hexdigest() if payload else None,
                    "suspicious_extension": ext in SUSPICIOUS_ATTACH_EXT,
                    "double_extension": len(re.findall(r"\.\w+", filename)) >= 2 and ext in SUSPICIOUS_ATTACH_EXT,
                })
    return attachments


def classify_text(text):
    """Weighted-lexicon 'AI' language scorer -> pseudo-probability of phishing intent."""
    lowered = text.lower()
    hits = []
    raw_score = 0
    for phrase, weight in PHISH_LEXICON.items():
        if phrase in lowered:
            hits.append(phrase)
            raw_score += weight
    # squashed into 0-100 confidence band
    confidence = min(100, round(100 * (1 - pow(2.71828, -raw_score / 35.0))))
    return {"matched_phrases": hits, "language_risk_score": confidence}


# --------------------------------------------------------------------------
# 3. Geolocation
# --------------------------------------------------------------------------

def geolocate_ip(ip, timeout=4):
    if _is_private_ip(ip):
        return {"ip": ip, "status": "private", "country": "Internal/Private network"}
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query"},
            timeout=timeout,
        )
        data = resp.json()
        if data.get("status") != "success":
            return {"ip": ip, "status": "failed", "message": data.get("message", "lookup failed")}
        return {
            "ip": ip, "status": "success", "country": data.get("country"),
            "country_code": data.get("countryCode"), "region": data.get("regionName"),
            "city": data.get("city"), "lat": data.get("lat"), "lon": data.get("lon"),
            "isp": data.get("isp"), "org": data.get("org"), "asn": data.get("as"),
        }
    except Exception as e:
        return {"ip": ip, "status": "error", "message": str(e)}


def geolocate_hops(hops):
    for hop in hops:
        hop["geolocation"] = [geolocate_ip(ip) for ip in hop["public_ips"]]
    return hops


# --------------------------------------------------------------------------
# 4. Threat scoring
# --------------------------------------------------------------------------

def score_email(headers, auth, hops, link_findings, attachments, language_result):
    findings = []
    score = 0

    def add(points, label, severity="medium"):
        nonlocal score
        score += points
        findings.append({"points": points, "label": label, "severity": severity})

    if auth["spf"] not in ("pass",):
        add(20, f"SPF check did not pass (result: {auth['spf']})", "high")
    if auth["dkim"] not in ("pass",):
        add(20, f"DKIM signature missing or invalid (result: {auth['dkim']})", "high")
    if auth["dmarc"] not in ("pass",):
        add(15, f"DMARC alignment failed (result: {auth['dmarc']})", "high")

    from_domain = domain_of(headers.get("From"))
    return_domain = domain_of(headers.get("Return-Path"))
    reply_domain = domain_of(headers.get("Reply-To"))
    if from_domain and return_domain and from_domain != return_domain:
        add(15, f"From domain ({from_domain}) does not match Return-Path domain ({return_domain})", "high")
    if reply_domain and from_domain and reply_domain != from_domain:
        add(10, f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})", "medium")

    if len(hops) > 8:
        add(5, f"Unusually long delivery chain ({len(hops)} hops)", "low")

    ip_link_hits = sum(1 for f in link_findings if any("raw IP" in i for i in f["issues"]))
    shortener_hits = sum(1 for f in link_findings if any("shortener" in i for i in f["issues"]))
    lookalike_hits = sum(1 for f in link_findings if any("lookalike" in i or "hyphen" in i for i in f["issues"]))
    if ip_link_hits:
        add(min(15 * ip_link_hits, 30), f"{ip_link_hits} link(s) point directly to a raw IP address", "high")
    if shortener_hits:
        add(min(10 * shortener_hits, 20), f"{shortener_hits} link(s) use a URL shortener", "medium")
    if lookalike_hits:
        add(min(10 * lookalike_hits, 20), f"{lookalike_hits} link(s) resemble brand lookalike domains", "medium")

    if language_result["language_risk_score"] >= 20:
        add(min(round(language_result["language_risk_score"] * 0.3), 25),
            f"Message body contains phishing-style language ({len(language_result['matched_phrases'])} indicator phrase(s))",
            "medium")

    for a in attachments:
        if a["suspicious_extension"]:
            add(25, f"Attachment '{a['filename']}' has a high-risk executable extension", "critical")
        if a["double_extension"]:
            add(10, f"Attachment '{a['filename']}' uses a disguised double extension", "high")

    score = max(0, min(100, score))
    if score >= 70:
        level = "Critical"
    elif score >= 45:
        level = "High"
    elif score >= 20:
        level = "Medium"
    else:
        level = "Low"

    return {"score": score, "risk_level": level, "findings": findings}


# --------------------------------------------------------------------------
# 5. Top-level orchestration
# --------------------------------------------------------------------------

def analyze_raw_email(raw_bytes):
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    headers = {k: v for k, v in msg.items()}
    auth = parse_authentication_results(msg)
    hops = parse_received_chain(msg)
    hops = geolocate_hops(hops)
    body_text, links = extract_body_and_links(msg)
    link_findings = analyze_links(links)
    attachments = extract_attachments(msg)
    language_result = classify_text(body_text + " " + (headers.get("Subject") or ""))
    threat = score_email(headers, auth, hops, link_findings, attachments, language_result)

    origin_geo = None
    if hops and hops[0]["geolocation"]:
        for g in hops[0]["geolocation"]:
            if g.get("status") == "success":
                origin_geo = g
                break

    return {
        "summary": {
            "subject": headers.get("Subject"),
            "from": headers.get("From"),
            "to": headers.get("To"),
            "date": headers.get("Date"),
            "message_id": headers.get("Message-ID"),
            "return_path": headers.get("Return-Path"),
        },
        "authentication": auth,
        "hops": hops,
        "origin_geolocation": origin_geo,
        "links": link_findings,
        "attachments": attachments,
        "language_analysis": language_result,
        "threat": threat,
    }
