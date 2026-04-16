"""
engine.py — Core Ingestion and Processing Engine

This module handles the main event loop for the SOC Engine.
It polls configured data sources, normalizes incoming events,
and routes them to the alert correlation pipeline.

Author: Ahmad Razif (@ahmdrazif)
Copyright (c) 2025-2026 CyberAlam Solutions Sdn Bhd
"""

import argparse
import logging
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger("soc_engine.core")


@dataclass
class SecurityEvent:
    """Represents a normalized security event from any data source."""

    event_id: str
    source: str
    timestamp: datetime
    severity: str  # "low", "medium", "high", "critical"
    category: str
    raw_data: dict = field(default_factory=dict)
    enrichments: dict = field(default_factory=dict)
    correlated: bool = False

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "category": self.category,
            "correlated": self.correlated,
        }


class DataSourceConnector:
    """
    Abstract connector for ingesting events from external sources.

    Supported source types:
    - syslog (UDP/TCP)
    - windows_event_log (WMI/WinRM)
    - cloud_audit (AWS CloudTrail, Azure Activity Log)
    - custom_api (REST webhook receivers)
    """

    SUPPORTED_SOURCES = ["syslog", "windows_event_log", "cloud_audit", "custom_api"]

    def __init__(self, source_type: str, endpoint: str, credentials: Optional[dict] = None):
        if source_type not in self.SUPPORTED_SOURCES:
            raise ValueError(f"Unsupported source type: {source_type}")
        self.source_type = source_type
        self.endpoint = endpoint
        self.credentials = credentials or {}
        self._connected = False

    def connect(self) -> bool:
        """Establish connection to the data source."""
        logger.info(f"Connecting to {self.source_type} at {self.endpoint}")
        # Connection logic handled by specific connector implementations
        self._connected = True
        return self._connected

    def poll(self) -> list[SecurityEvent]:
        """Poll the data source for new events."""
        if not self._connected:
            raise RuntimeError("Connector not initialized. Call connect() first.")
        # Polling logic implemented by subclasses
        return []

    def disconnect(self):
        """Gracefully close the connection."""
        logger.info(f"Disconnecting from {self.source_type}")
        self._connected = False


class CorrelationEngine:
    """
    Correlates related security events using temporal windowing
    and contextual similarity analysis.

    Events within the same time window sharing common attributes
    (source IP, target host, attack signature) are grouped into
    a single correlated incident.
    """

    DEFAULT_WINDOW_SECONDS = 300  # 5-minute correlation window

    def __init__(self, window_seconds: int = DEFAULT_WINDOW_SECONDS):
        self.window_seconds = window_seconds
        self._event_buffer: list[SecurityEvent] = []
        self._incident_counter = 0

    def ingest(self, event: SecurityEvent):
        """Add an event to the correlation buffer."""
        self._event_buffer.append(event)
        self._prune_expired()

    def correlate(self) -> list[dict]:
        """
        Run correlation analysis on the current event buffer.
        Returns a list of incident groups.
        """
        incidents = []
        # Group events by source IP within the time window
        groups: dict[str, list[SecurityEvent]] = {}
        for event in self._event_buffer:
            source_key = event.raw_data.get("src_ip", "unknown")
            groups.setdefault(source_key, []).append(event)

        for source, events in groups.items():
            if len(events) >= 3:  # Minimum events to form an incident
                self._incident_counter += 1
                incidents.append({
                    "incident_id": f"INC-{self._incident_counter:06d}",
                    "source": source,
                    "event_count": len(events),
                    "severity": self._calculate_max_severity(events),
                    "first_seen": min(e.timestamp for e in events).isoformat(),
                    "last_seen": max(e.timestamp for e in events).isoformat(),
                })
                for event in events:
                    event.correlated = True

        return incidents

    def _prune_expired(self):
        """Remove events outside the correlation window."""
        now = datetime.now(timezone.utc)
        self._event_buffer = [
            e for e in self._event_buffer
            if (now - e.timestamp).total_seconds() <= self.window_seconds
        ]

    @staticmethod
    def _calculate_max_severity(events: list[SecurityEvent]) -> str:
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        max_sev = max(events, key=lambda e: severity_order.get(e.severity, 0))
        return max_sev.severity


class SOCEngine:
    """
    Main orchestration class for the SOC Engine.

    Manages the lifecycle of data source connectors, the correlation
    engine, and notification dispatching.
    """

    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.connectors: list[DataSourceConnector] = []
        self.correlation = CorrelationEngine(
            window_seconds=self.config.get("correlation", {}).get("window", 300)
        )
        self._running = False
        self._setup_signal_handlers()

    def _load_config(self, config_path: str) -> dict:
        """Load and validate the YAML configuration file."""
        path = Path(config_path)
        if not path.exists():
            logger.error(f"Configuration file not found: {config_path}")
            sys.exit(1)

        with open(path) as f:
            config = yaml.safe_load(f)

        logger.info(f"Configuration loaded from {config_path}")
        return config

    def _setup_signal_handlers(self):
        """Register handlers for graceful shutdown."""
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    def _handle_shutdown(self, signum, frame):
        """Gracefully stop the engine."""
        logger.info(f"Received signal {signum}. Shutting down...")
        self._running = False

    def initialize_connectors(self):
        """Create and connect all configured data source connectors."""
        sources = self.config.get("data_sources", [])
        for source_cfg in sources:
            connector = DataSourceConnector(
                source_type=source_cfg["type"],
                endpoint=source_cfg["endpoint"],
                credentials=source_cfg.get("credentials"),
            )
            if connector.connect():
                self.connectors.append(connector)
                logger.info(f"Connector initialized: {source_cfg['type']}")
            else:
                logger.warning(f"Failed to connect: {source_cfg['type']}")

    def run(self):
        """Start the main processing loop."""
        self._running = True
        poll_interval = self.config.get("ingestion", {}).get("poll_interval", 30)
        logger.info(f"SOC Engine started. Polling every {poll_interval}s")

        while self._running:
            for connector in self.connectors:
                try:
                    events = connector.poll()
                    for event in events:
                        self.correlation.ingest(event)
                except Exception as e:
                    logger.error(f"Error polling {connector.source_type}: {e}")

            # Run correlation
            incidents = self.correlation.correlate()
            for incident in incidents:
                logger.info(f"New incident detected: {incident['incident_id']}")
                self._dispatch_notification(incident)

            time.sleep(poll_interval)

        # Cleanup
        for connector in self.connectors:
            connector.disconnect()
        logger.info("SOC Engine stopped.")

    def _dispatch_notification(self, incident: dict):
        """Send incident notifications to configured channels."""
        webhooks = self.config.get("webhooks", {})

        if webhooks.get("slack", {}).get("enabled"):
            logger.info(f"Sending Slack notification for {incident['incident_id']}")
            # Slack webhook dispatch logic

        if webhooks.get("teams", {}).get("enabled"):
            logger.info(f"Sending Teams notification for {incident['incident_id']}")
            # Microsoft Teams webhook dispatch logic


def main():
    parser = argparse.ArgumentParser(
        description="SOC Engine Core — CyberAlam Solutions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config/settings.yaml",
        help="Path to the YAML configuration file",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Set the logging level",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    engine = SOCEngine(args.config)
    engine.initialize_connectors()
    engine.run()


if __name__ == "__main__":
    main()
