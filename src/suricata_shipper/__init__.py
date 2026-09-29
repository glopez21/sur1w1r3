"""Sur1W1r3: forward Suricata EVE telemetry to a SOC.

ThreatPulse is the Tier-1 platform; alerts that clear its correlation and
triage thresholds are escalated to Augur by the alerting service, so this agent
never talks to Augur directly. It ships two streams and nothing else:

* ``flow``  -> network-monitor ``/api/v1/traffic/ingest/batch`` (X-API-Key)
* ``alert`` -> siem-app ``/api/v1/webhooks`` (HMAC X-Webhook-Signature)
"""

__version__ = "1.0.0"
