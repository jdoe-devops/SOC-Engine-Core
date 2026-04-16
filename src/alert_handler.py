"""
alert_handler.py — Alert Triage and Enrichment Pipeline

This module processes correlated incidents from the correlation engine,
enriches them with threat intelligence lookups, and applies configurable
triage rules to determine response actions.

Author: Nur Aisyah (@nuraisyah-dev)
Copyright (c) 2025-2026 CyberAlam Solutions Sdn Bhd
"""

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("soc_engine.alerts")


class AlertSeverity(Enum):
    """Alert severity classification levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_string(cls, value: str) -> "AlertSeverity":
        try:
            return cls(value.lower())
        except ValueError:
            logger.warning(f"Unknown severity '{value}', defaulting to LOW")
            return cls.LOW


class ResponseAction(Enum):
    """Automated response actions that can be triggered by alerts."""
    LOG_ONLY = "log_only"
    NOTIFY = "notify"
    ISOLATE = "isolate"
    BLOCK = "block"
    ESCALATE = "escalate"


@dataclass
class ThreatIntelResult:
    """Result from a threat intelligence lookup."""
    indicator: str
    source: str
    confidence: float  # 0.0 - 1.0
    threat_type: Optional[str] = None
    malware_family: Optional[str] = None
    first_seen: Optional[datetime] = None
    tags: list[str] = field(default_factory=list)


@dataclass
class EnrichedAlert:
    """
    An alert that has been enriched with threat intelligence
    and assigned a triage classification.
    """
    alert_id: str
    incident_id: str
    severity: AlertSeverity
    category: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    threat_intel: list[ThreatIntelResult] = field(default_factory=list)
    recommended_action: ResponseAction = ResponseAction.LOG_ONLY
    analyst_notes: str = ""
    resolved: bool = False


class ThreatIntelligenceService:
    """
    Integrates with external threat intelligence feeds to enrich
    indicators of compromise (IOCs) found in security events.

    Supported feeds:
    - AlienVault OTX
    - AbuseIPDB
    - VirusTotal (API key required)
    - Internal IOC database
    """

    def __init__(self, api_keys: Optional[dict] = None):
        self.api_keys = api_keys or {}
        self._cache: dict[str, ThreatIntelResult] = {}

    def lookup_ip(self, ip_address: str) -> Optional[ThreatIntelResult]:
        """
        Query threat intelligence feeds for information about an IP address.
        Results are cached to avoid redundant API calls.
        """
        if ip_address in self._cache:
            return self._cache[ip_address]

        # Check internal blocklist first
        result = self._check_internal_blocklist(ip_address)
        if result:
            self._cache[ip_address] = result
            return result

        # Query external feeds
        for feed_name, api_key in self.api_keys.items():
            result = self._query_feed(feed_name, ip_address, api_key)
            if result and result.confidence > 0.7:
                self._cache[ip_address] = result
                return result

        return None

    def lookup_hash(self, file_hash: str) -> Optional[ThreatIntelResult]:
        """Look up a file hash across threat intelligence databases."""
        if file_hash in self._cache:
            return self._cache[file_hash]

        # Normalize hash format
        file_hash = file_hash.lower().strip()

        for feed_name, api_key in self.api_keys.items():
            result = self._query_feed(feed_name, file_hash, api_key)
            if result:
                self._cache[file_hash] = result
                return result

        return None

    def _check_internal_blocklist(self, indicator: str) -> Optional[ThreatIntelResult]:
        """Check against the internally maintained blocklist."""
        # Internal blocklist lookup logic
        return None

    def _query_feed(self, feed: str, indicator: str, api_key: str) -> Optional[ThreatIntelResult]:
        """Query a specific threat intelligence feed."""
        logger.debug(f"Querying {feed} for indicator: {indicator}")
        # Feed-specific API call logic
        return None


class TriageEngine:
    """
    Applies configurable rules to determine the appropriate response
    action for each enriched alert.

    Rules are evaluated in priority order. The first matching rule
    determines the response action.
    """

    DEFAULT_RULES = [
        {
            "name": "critical_known_threat",
            "condition": {"severity": "critical", "threat_intel_match": True},
            "action": ResponseAction.BLOCK,
        },
        {
            "name": "high_repeated_source",
            "condition": {"severity": "high", "event_count_gte": 10},
            "action": ResponseAction.ISOLATE,
        },
        {
            "name": "medium_with_intel",
            "condition": {"severity": "medium", "threat_intel_match": True},
            "action": ResponseAction.ESCALATE,
        },
        {
            "name": "any_high",
            "condition": {"severity": "high"},
            "action": ResponseAction.NOTIFY,
        },
        {
            "name": "default",
            "condition": {},
            "action": ResponseAction.LOG_ONLY,
        },
    ]

    def __init__(self, custom_rules: Optional[list[dict]] = None):
        self.rules = custom_rules or self.DEFAULT_RULES

    def evaluate(self, alert: EnrichedAlert) -> ResponseAction:
        """
        Evaluate an alert against the triage ruleset and return
        the appropriate response action.
        """
        for rule in self.rules:
            if self._matches(alert, rule["condition"]):
                logger.info(
                    f"Alert {alert.alert_id} matched rule '{rule['name']}' "
                    f"-> {rule['action'].value}"
                )
                return rule["action"]

        return ResponseAction.LOG_ONLY

    def _matches(self, alert: EnrichedAlert, condition: dict) -> bool:
        """Check if an alert matches a rule condition."""
        if not condition:
            return True  # Empty condition matches everything

        if "severity" in condition:
            if alert.severity.value != condition["severity"]:
                return False

        if condition.get("threat_intel_match"):
            if not alert.threat_intel:
                return False

        return True


class AlertHandler:
    """
    Main alert processing pipeline. Coordinates enrichment, triage,
    and response dispatch for incoming incidents.
    """

    def __init__(self, config: dict):
        self.threat_intel = ThreatIntelligenceService(
            api_keys=config.get("threat_intel", {}).get("api_keys", {})
        )
        self.triage = TriageEngine(
            custom_rules=config.get("triage_rules")
        )
        self._alert_counter = 0
        self._alert_history: list[EnrichedAlert] = []

    def process_incident(self, incident: dict) -> EnrichedAlert:
        """
        Process a correlated incident through the full alert pipeline:
        1. Create enriched alert
        2. Run threat intelligence lookups
        3. Apply triage rules
        4. Dispatch response action
        """
        self._alert_counter += 1
        alert_id = self._generate_alert_id(incident)

        alert = EnrichedAlert(
            alert_id=alert_id,
            incident_id=incident["incident_id"],
            severity=AlertSeverity.from_string(incident.get("severity", "low")),
            category=incident.get("category", "unknown"),
            source_ip=incident.get("source"),
        )

        # Enrich with threat intelligence
        if alert.source_ip:
            ti_result = self.threat_intel.lookup_ip(alert.source_ip)
            if ti_result:
                alert.threat_intel.append(ti_result)

        # Apply triage rules
        alert.recommended_action = self.triage.evaluate(alert)

        # Dispatch the response
        self._dispatch_response(alert)

        # Record in history
        self._alert_history.append(alert)

        return alert

    def _generate_alert_id(self, incident: dict) -> str:
        """Generate a deterministic alert ID based on incident data."""
        hash_input = f"{incident['incident_id']}-{self._alert_counter}"
        return f"ALR-{hashlib.sha256(hash_input.encode()).hexdigest()[:8].upper()}"

    def _dispatch_response(self, alert: EnrichedAlert):
        """Execute the recommended response action."""
        action = alert.recommended_action

        if action == ResponseAction.LOG_ONLY:
            logger.info(f"[{alert.alert_id}] Logged: {alert.category}")

        elif action == ResponseAction.NOTIFY:
            logger.info(f"[{alert.alert_id}] Notification sent to SOC team")

        elif action == ResponseAction.ISOLATE:
            logger.warning(
                f"[{alert.alert_id}] ISOLATE action triggered for {alert.source_ip}"
            )

        elif action == ResponseAction.BLOCK:
            logger.warning(
                f"[{alert.alert_id}] BLOCK action triggered for {alert.source_ip}"
            )

        elif action == ResponseAction.ESCALATE:
            logger.warning(
                f"[{alert.alert_id}] ESCALATED to senior analyst"
            )

    def get_statistics(self) -> dict:
        """Return summary statistics of processed alerts."""
        total = len(self._alert_history)
        by_severity = {}
        by_action = {}

        for alert in self._alert_history:
            sev = alert.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
            act = alert.recommended_action.value
            by_action[act] = by_action.get(act, 0) + 1

        return {
            "total_alerts": total,
            "by_severity": by_severity,
            "by_action": by_action,
        }
