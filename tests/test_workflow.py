import unittest

from security_agent.investigation import decode_base64
from security_agent.log_analyzer import SAMPLE_LOG, analyze_web_log
from security_agent.workflow import SecurityWorkflow


class SecurityWorkflowTests(unittest.TestCase):
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
        self.assertEqual(len(report["events"]), 6)
        self.assertEqual(report["vulnerabilities"][0]["cve"], "CVE-2021-41773")


if __name__ == "__main__":
    unittest.main()
