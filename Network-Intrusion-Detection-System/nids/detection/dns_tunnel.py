"""
DNS tunneling and DNS-based C2 beaconing detector.

DNS tunneling exploits the fact that DNS traffic is rarely inspected
or blocked at perimeter firewalls.  Tools such as iodine, dns2tcp,
and DNScat encode arbitrary data into DNS query/response labels.

Detection signals
-----------------
1. Subdomain entropy
   Legitimate hostnames use human-readable labels with low entropy
   (e.g. "www", "mail", "api").  Base32 / base64 encoded payloads
   approach maximum entropy for their alphabet.

   Calibration (empirical):
     Normal hostnames:        1.5 – 3.0 bits
     Hex-encoded chunks:      3.5 – 4.0 bits
     Base32 (iodine default): 4.0 – 4.5 bits
     Base64 (random data):    4.5 – 5.2 bits

2. Maximum label length
   RFC 1035 permits labels up to 63 chars.  Normal usage is ≤ 15 chars.
   Tunneling tools pack data into labels: iodine uses ~50-char labels,
   dns2tcp uses hex chunks of ~59 chars.

3. Query rate per base domain (beaconing)
   A C2 agent polling via DNS sends regular queries — a steady >10/min
   rate to a non-CDN domain is a strong beacon signal.

4. Oversized DNS response
   Exfiltration over DNS encodes stolen data in TXT / NULL / CNAME
   responses.  Legitimate DNS responses are rarely >200 bytes.

MITRE ATT&CK: T1071.004 — Application Layer Protocol: DNS (C2)
"""

from __future__ import annotations

import time
from collections import defaultdict

from nids.capture.parser import ParsedPacket
from nids.detection.models import Alert, Severity
from nids.utils.stats import SlidingWindowCounter, WelfordAccumulator, shannon_entropy

# Thresholds
_ENTROPY_THRESHOLD: float     = 3.8   # bits — fires on likely base32/64
_LABEL_LEN_THRESHOLD: int     = 40    # chars — unusually long subdomain label
_BEACON_RATE_THRESHOLD: float = 10.0  # queries / 60 s to same domain
_RESPONSE_SIZE_THRESHOLD: int = 200   # bytes — large DNS payload
_SUPPRESSION_S: float         = 30.0


class DNSTunnelDetector:
    """
    Multi-signal DNS tunneling and C2 beaconing detector.

    Uses Shannon entropy, label-length heuristics, query-rate analysis,
    and response-size inspection in combination — single signals alone
    produce too many false positives.
    """

    def __init__(self) -> None:
        # (src_ip + base_domain) → query counter (60 s window)
        self._query_rates: dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(60.0)
        )
        # Per-source entropy baseline (to detect anomalous *change* in entropy)
        self._entropy_baseline: dict[str, WelfordAccumulator] = defaultdict(
            WelfordAccumulator
        )
        self._last_alert: dict[str, float] = {}

    # ------------------------------------------------------------------ #

    # Domains that legitimately produce high-entropy or high-rate queries.
    # mDNS service labels (_tcp.local, _udp.local) and CDN/analytics hostnames
    # are the most common sources of false positives.
    _WHITELIST_SUFFIXES: frozenset[str] = frozenset({
        "local",           # mDNS / Bonjour (Apple, Chromecast, printers …)
        "internal",        # RFC-2606 private namespace
        "localhost",
        "arpa",            # reverse-DNS PTR queries
        "in-addr.arpa",
        "ip6.arpa",
    })

    def process(self, pkt: ParsedPacket) -> list[Alert]:
        if pkt.protocol != "DNS" or not pkt.dns_qname:
            return []

        alerts: list[Alert] = []
        src   = pkt.src_ip or "unknown"
        qname = pkt.dns_qname.lower().rstrip(".")
        labels = qname.split(".")

        if len(labels) < 2:
            return []

        # Skip whitelisted TLDs / pseudo-TLDs — these produce structural
        # high-entropy labels (e.g. _googlecast._tcp.local) that are benign.
        tld = labels[-1]
        if tld in self._WHITELIST_SUFFIXES:
            return []

        base_domain = ".".join(labels[-2:])
        subdomain   = ".".join(labels[:-2]) if len(labels) > 2 else ""

        # ── Signal 1 + 2: high-entropy long subdomain ────────────────────
        if subdomain:
            entropy      = shannon_entropy(subdomain)
            max_label_len = max((len(l) for l in subdomain.split(".") if l), default=0)

            # Update per-source entropy baseline (continuous learning)
            self._entropy_baseline[src].update(entropy)

            if (
                entropy > _ENTROPY_THRESHOLD
                and max_label_len > _LABEL_LEN_THRESHOLD
                and not self._suppressed(f"entropy:{src}:{base_domain}")
            ):
                self._suppress(f"entropy:{src}:{base_domain}")
                z = self._entropy_baseline[src].z_score(entropy)
                alerts.append(Alert(
                    severity=Severity.HIGH,
                    title="DNS Tunneling Detected",
                    description=(
                        f"High-entropy DNS query from {src} to "
                        f"{base_domain!r} (entropy={entropy:.2f} bits, "
                        f"label_len={max_label_len})"
                    ),
                    detector="dns_tunnel",
                    mitre_key="dns_tunnel",
                    src_ip=src,
                    evidence={
                        "qname":              qname[:120],
                        "base_domain":        base_domain,
                        "subdomain_entropy":  round(entropy, 3),
                        "max_label_length":   max_label_len,
                        "entropy_z_score":    round(z, 2),
                        "entropy_threshold":  _ENTROPY_THRESHOLD,
                        "signal":             "high_entropy_subdomain",
                    },
                ))

        # ── Signal 3: high query rate / beaconing ────────────────────────
        rate_key = f"{src}:{base_domain}"
        self._query_rates[rate_key].add(pkt.timestamp)
        query_rate = self._query_rates[rate_key].rate() * 60  # per-minute

        if (
            query_rate > _BEACON_RATE_THRESHOLD
            and not self._suppressed(f"beacon:{rate_key}")
        ):
            self._suppress(f"beacon:{rate_key}")
            alerts.append(Alert(
                severity=Severity.MEDIUM,
                title="DNS Beaconing / C2 Detected",
                description=(
                    f"{src} is making {query_rate:.0f} queries/min to "
                    f"{base_domain!r} — consistent with C2 polling interval"
                ),
                detector="dns_tunnel",
                mitre_key="dns_tunnel",
                src_ip=src,
                evidence={
                    "base_domain":          base_domain,
                    "query_rate_per_min":   round(query_rate, 1),
                    "beacon_threshold":     _BEACON_RATE_THRESHOLD,
                    "signal":               "high_query_rate",
                },
            ))

        # ── Signal 4: oversized DNS response (exfiltration) ──────────────
        if (
            pkt.dns_is_response
            and pkt.dns_payload_len > _RESPONSE_SIZE_THRESHOLD
            and not self._suppressed(f"large:{src}:{base_domain}")
        ):
            self._suppress(f"large:{src}:{base_domain}")
            severity = (
                Severity.HIGH
                if pkt.dns_payload_len > 450
                else Severity.MEDIUM
            )
            alerts.append(Alert(
                severity=severity,
                title="Oversized DNS Response",
                description=(
                    f"DNS response to {src} for {base_domain!r} is "
                    f"{pkt.dns_payload_len} bytes — potential exfiltration channel"
                ),
                detector="dns_tunnel",
                mitre_key="dns_tunnel",
                src_ip=src,
                evidence={
                    "base_domain":    base_domain,
                    "response_bytes": pkt.dns_payload_len,
                    "answer_count":   pkt.dns_ancount,
                    "threshold":      _RESPONSE_SIZE_THRESHOLD,
                    "signal":         "large_dns_response",
                },
            ))

        return alerts

    # ------------------------------------------------------------------ #

    def _suppressed(self, key: str) -> bool:
        return (time.time() - self._last_alert.get(key, 0.0)) < _SUPPRESSION_S

    def _suppress(self, key: str) -> None:
        self._last_alert[key] = time.time()
