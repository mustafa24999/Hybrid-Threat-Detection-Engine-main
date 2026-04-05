# tests/test_zenith_engine.py
# Deep Testing Suite for Zenith Threat Detection Engine.
import unittest
import sys
import os
from pathlib import Path

# Fix python path for imports
sys.path.append(os.getcwd() + "/hybrid-threat-detector")

from backend.url_analyzer import compute_url_score
from backend.file_analyzer import analyze_file
from backend.scoring import classify, build_explanation

class TestZenithHeuristics(unittest.TestCase):
    
    # 1. URL Analysis Verification
    def test_url_dga(self):
        # High entropy hostname
        url = "https://x7w2q9z4k1m8p0j3.xyz"
        res = compute_url_score(url)
        self.assertGreaterEqual(res["score"], 0.25)
        self.assertTrue(any("DGA" in r for r in res["reasons"]))

    def test_url_homograph(self):
        url = "https://bank--of--america.signin.update.com"
        res = compute_url_score(url)
        self.assertGreaterEqual(res["score"], 0.30)
        self.assertTrue(any("keywords" in r.lower() for r in res["reasons"]))
        self.assertTrue(any("character repetition" in r.lower() for r in res["reasons"]))

    def test_url_ip_obfuscation(self):
        url = "http://192.168.1.1/login.exe"
        res = compute_url_score(url)
        self.assertGreaterEqual(res["score"], 0.65) # Zenith threshold for malicious
        self.assertTrue(any("IP address" in r for r in res["reasons"]))
        self.assertTrue(any(".exe" in r for r in res["reasons"]))

    # 2. File Analysis Verification
    def test_file_pdf_js(self):
        path = Path("test_samples/sample_js.pdf")
        res = analyze_file(path)
        self.assertGreaterEqual(res["score"], 0.35)
        self.assertTrue(any("JavaScript" in r for r in res["reasons"]))

    def test_file_macro_doc(self):
        path = Path("test_samples/sample_macro.docm")
        res = analyze_file(path)
        self.assertGreaterEqual(res["score"], 0.50)
        self.assertTrue(any("VBA Macros" in r for r in res["reasons"]))

    def test_file_malformed_pe(self):
        path = Path("test_samples/malformed_pe.exe")
        res = analyze_file(path)
        # PE signature mismatch + suspicious extension
        self.assertGreaterEqual(res["score"], 0.50)
        self.assertTrue(any("Malformed PE signature" in r for r in res["reasons"]))

    def test_file_text_mask(self):
        path = Path("test_samples/mask_test.txt")
        res = analyze_file(path)
        self.assertGreaterEqual(res["score"], 0.25)
        self.assertTrue(any("Binary content" in r for r in res["reasons"]))

    def test_file_high_entropy(self):
        path = Path("test_samples/high_entropy.bin")
        res = analyze_file(path)
        self.assertGreaterEqual(res["score"], 0.30)
        self.assertTrue(any("entropy" in r.lower() for r in res["reasons"]))

    # 3. Scoring Engine Verification
    def test_scoring_labels(self):
        self.assertEqual(classify(0.1), "Safe")
        self.assertEqual(classify(0.4), "Suspicious")
        self.assertEqual(classify(0.8), "Malicious")

    def test_explanation_logic(self):
        expl = build_explanation("Malicious", ["DGA detected"], "URL")
        self.assertTrue("High Risk" in expl)

if __name__ == "__main__":
    unittest.main()
