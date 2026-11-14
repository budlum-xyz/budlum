"""Ensure an unavailable host exporter cannot silently mask the disk alert."""

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class NodeExporterAlertTests(unittest.TestCase):
    def test_missing_host_exporter_alerts_instead_of_masking_disk_status(self):
        rules = (ROOT / "ops/monitoring/alerts.yml").read_text(encoding="utf-8")
        for profile in ("ops/prometheus.yml", "ops/monitoring/testnet-local-prometheus.yml"):
            with self.subTest(profile=profile):
                scrape = (ROOT / profile).read_text(encoding="utf-8")
                self.assertIn("job_name: node", scrape)
                self.assertIn('targets: ["host.docker.internal:9100"]', scrape)
        self.assertIn("alert: BudlumNodeExporterUnavailable", rules)
        self.assertIn('expr: up{job="node"} == 0 or absent(up{job="node"})', rules)
        self.assertIn("alert: BudlumDiskFillingUp", rules)


if __name__ == "__main__":
    unittest.main()
