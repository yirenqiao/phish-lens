import contextlib
import io
import json
import os
import unittest
from email.message import EmailMessage

import phish_lens as pl

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "samples")


def make(sender="Alice <alice@example.com>", subject="Hello", text="Hi there.", html=None,
         auth="mx; spf=pass; dkim=pass; dmarc=pass", reply_to=None, attachments=()):
    m = EmailMessage()
    m["From"] = sender
    m["To"] = "bob@example.org"
    m["Subject"] = subject
    if auth:
        m["Authentication-Results"] = auth
    if reply_to:
        m["Reply-To"] = reply_to
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    for name in attachments:
        m.add_attachment(b"data", maintype="application", subtype="octet-stream", filename=name)
    return pl.analyze_bytes(bytes(m))


def checks(report):
    return {f.check for f in report.findings}


class HelperTests(unittest.TestCase):
    def test_registrable_domain(self):
        self.assertEqual(pl.registrable_domain("mail.example.co.jp"), "example.co.jp")
        self.assertEqual(pl.registrable_domain("a.b.example.com"), "example.com")
        self.assertEqual(pl.registrable_domain("192.0.2.1"), "192.0.2.1")

    def test_lookalikes_detected(self):
        for domain, brand in [("paypa1.com", "paypal"), ("rnicrosoft-support.com", "microsoft"),
                              ("amaz0n-orders.net", "amazon"), ("secure-netflix-billing.com", "netflix"),
                              ("dhl-tracking.info", "dhl"), ("gooogle.com", "google")]:
            self.assertEqual(pl.impersonated_brand(domain), brand, domain)

    def test_real_domains_not_flagged(self):
        for domain in ["paypal.com", "mail.paypal.com", "amazon.co.jp", "outlook.com",
                       "notifications.github.com", "apply-now.com", "example.com", "rakuten.co.jp"]:
            self.assertIsNone(pl.impersonated_brand(domain), domain)

    def test_brand_subdomain(self):
        self.assertEqual(pl.brand_in_subdomain("paypal.com.account-review.top"), "paypal.com")
        self.assertEqual(pl.brand_in_subdomain("login.apple.com.verify.xyz"), "apple.com")
        self.assertIsNone(pl.brand_in_subdomain("www.paypal.com"))

    def test_levenshtein(self):
        self.assertEqual(pl.levenshtein("kitten", "sitting"), 3)


class SampleTests(unittest.TestCase):
    def test_credential_phish_is_high(self):
        r = pl.analyze_file(os.path.join(SAMPLES, "credential-phish.eml"))
        self.assertEqual(r.verdict, "high")
        self.assertTrue({"lookalike-sender", "deceptive-link", "double-extension",
                         "dmarc-fail", "brand-subdomain-link", "ip-link"} <= checks(r))

    def test_ceo_fraud_is_suspicious(self):
        r = pl.analyze_file(os.path.join(SAMPLES, "ceo-gift-card.eml"))
        self.assertEqual(r.verdict, "medium")
        self.assertIn("freemail-executive", checks(r))
        self.assertIn("display-name-address", checks(r))

    def test_legit_newsletter_is_clean(self):
        r = pl.analyze_file(os.path.join(SAMPLES, "legit-newsletter.eml"))
        self.assertEqual((r.score, r.verdict), (0, "low"))


class CheckTests(unittest.TestCase):
    def test_clean_message(self):
        self.assertEqual(make().score, 0)

    def test_real_brand_sender_is_clean(self):
        r = make(sender="GitHub <noreply@github.com>", text="A new sign-in to your account.")
        self.assertNotIn("display-name-brand", checks(r))
        self.assertNotIn("lookalike-sender", checks(r))

    def test_missing_auth_is_info_only(self):
        r = make(auth=None)
        self.assertIn("auth-missing", checks(r))
        self.assertEqual(r.score, 0)

    def test_softfail(self):
        self.assertIn("spf-softfail", checks(make(auth="mx; spf=softfail; dkim=pass; dmarc=pass")))

    def test_reply_to_freemail_is_high(self):
        r = make(reply_to="someone@gmail.com")
        self.assertEqual([f.severity for f in r.findings if f.check == "reply-to-mismatch"], ["high"])

    def test_link_tricks(self):
        html = ('<a href="https://bit.ly/x1">a</a> <a href="http://user@evil.example/">b</a> '
                '<a href="https://xn--pypal-4ve.com/">c</a> <a href="https://shop.example.zip/">d</a> '
                '<form action="https://collect.example/"></form>')
        found = checks(make(html=html))
        self.assertTrue({"shortener-link", "userinfo-link", "punycode-link",
                         "suspicious-tld", "html-form"} <= found)

    def test_matching_link_text_is_fine(self):
        html = '<a href="https://www.example.com/docs">www.example.com/docs</a>'
        self.assertNotIn("deceptive-link", checks(make(html=html)))

    def test_attachments(self):
        found = checks(make(attachments=["setup.exe", "report.docm", "files.iso", "invoice.pdf.js"]))
        self.assertTrue({"executable-attachment", "macro-attachment",
                         "container-attachment", "double-extension"} <= found)
        self.assertNotIn("double-extension", checks(make(attachments=["archive.tar.gz", "photo.jpg"])))

    def test_score_counts_each_check_once(self):
        html = "".join(f'<a href="http://192.0.2.{i}/">x</a>' for i in range(10))
        r = make(html=html)
        self.assertEqual(sum(1 for f in r.findings if f.check == "ip-link"), 10)
        self.assertEqual(r.score, 15)

    def test_html_body_language_detected(self):
        r = make(text="", html="<p>Your account <b>has been suspended</b>. Verify your account now.</p>")
        self.assertIn("pressure-language", checks(r))


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = pl.main(list(args))
        return code, buf.getvalue()

    def test_json_output(self):
        code, out = self.run_cli(os.path.join(SAMPLES, "credential-phish.eml"), "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["verdict"], "high")

    def test_exit_code_reflects_worst_verdict(self):
        code, _ = self.run_cli(os.path.join(SAMPLES, "legit-newsletter.eml"),
                               os.path.join(SAMPLES, "credential-phish.eml"), "--exit-code", "--no-color")
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
