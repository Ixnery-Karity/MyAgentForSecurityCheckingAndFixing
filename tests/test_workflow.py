import unittest

from security_agent.investigation import decode_base64
from security_agent.log_analyzer import SAMPLE_LOG, analyze_web_log
from security_agent.targets import normalize_target, resolve_target
from security_agent.workflow import SecurityWorkflow


class SecurityWorkflowTests(unittest.TestCase):
    def test_url_target_is_normalized_without_network_request(self):
        target = normalize_target("https://freemodel.dev/dashboard/usage")
        self.assertEqual(target["kind"], "url")
        self.assertEqual(target["host_kind"], "domain")
        self.assertEqual(target["hostname"], "freemodel.dev")
        self.assertEqual(target["path"], "/dashboard/usage")
        self.assertEqual(resolve_target(target, perform_dns=False)["resolution"], "skipped")

    def test_invalid_target_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_target("javascript:alert(1)")

    def test_segmented_base64_decode(self):
        result = decode_base64("c3lz.R2V0U2hlbGwoKQ==")
        self.assertEqual(result["decoded"], "sys.GetShell()")

    def test_rule_log_analysis(self):
        result = analyze_web_log(SAMPLE_LOG, use_llm=False)
        self.assertTrue(result["is_malicious"])
        self.assertEqual(result["attack_type"], "SQL Injection")

    def test_complete_workflow(self):
        alert = {
            "alert_id": "TEST-001",
            "type": "SQL Injection Attempt",
            "source_ip": "192.168.3.73",
            "payload": "c3lz.R2V0U2hlbGwoKQ==",
            "http_status": 200,
        }
        report = SecurityWorkflow().run(alert, SAMPLE_LOG, "192.168.3.73", use_llm=False)
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["severity"], "Critical")
        self.assertEqual(len(report["events"]), 7)
        self.assertEqual(report["vulnerabilities"][0]["cve"], "CVE-2021-41773")

    def test_domain_target_can_match_resolved_lab_ip(self):
        alert = {"alert_id": "DOMAIN-001", "type": "Asset Check", "payload": ""}
        report = SecurityWorkflow().run(
            alert,
            target="lab.example.com",
            use_llm=False,
            perform_dns=False,
        )
        self.assertEqual(report["target"]["kind"], "domain")
        self.assertEqual(report["target"]["resolution"], "skipped")
        self.assertEqual(report["scan"]["services"], [])


if __name__ == "__main__":
    unittest.main()
