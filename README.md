# phish-lens

A small command-line tool that reads a saved email (`.eml`) and tells you how phishy it looks, with a reason for every point it adds.

## Why I built it

In SOC and helpdesk work, a lot of time goes into one question: "is this email real?" Most of the evidence is already in the message — authentication results, sender and Reply-To headers, link targets, attachment names — but checking it by hand is slow and easy to get wrong. I wanted a transparent first-pass triage tool: no black-box model, just readable rules, so an analyst can see exactly why a message was flagged and decide what to do next.

## Quick start

Python 3.9+ and the standard library only — nothing to install.

```bash
python phish_lens.py samples/credential-phish.eml
python phish_lens.py samples/*.eml           # several files at once
python phish_lens.py suspicious.eml --json   # machine-readable output
python phish_lens.py suspicious.eml --exit-code   # exit 0/1/2 for low/suspicious/high
```

To get an `.eml` file: Gmail → *Show original → Download original*; Outlook → *Save as*; Thunderbird → *Save As → File*.

Links are parsed but never visited, and attachments are never opened.

## Example output

Real output for the synthetic sample `samples/credential-phish.eml` (truncated):

```
phish-lens report: samples/credential-phish.eml
  Subject : URGENT: Your account has been suspended
  From    : PayPal Security <service@paypa1-security.com>
  Score   : 100/100  HIGH RISK

  [HIGH  ]  +30  Sender domain imitates PayPal
                  paypa1-security.com resembles paypal but is not one of its real domains (paypal-communication.com, paypal.com, paypal.me).
  [HIGH  ]  +30  Attachment hides its real type
                  "Account_Statement.pdf.html" looks like a .pdf file but is actually .html.
  [HIGH  ]  +25  DMARC failed
                  The receiving server reported dmarc=fail: the message was not authorized by the domain it claims to come from.
  [HIGH  ]  +25  Link text shows a different destination
                  The link reads "https://www.paypal.com/signin" but actually opens http://192.0.2.44/paypal/login.php.
  [HIGH  ]  +20  Replies go to a different domain
                  From is service@paypa1-security.com but Reply-To is paypal.support.team@gmail.com.
  ...
```

## What it checks

- **Authentication:** SPF, DKIM and DMARC results from the `Authentication-Results` header (fail, softfail, missing).
- **Sender:** Reply-To or Return-Path on a different domain, an address hidden in the display name, brand names or executive titles sent from unrelated or free-mail domains.
- **Lookalike domains:** character swaps (`paypa1`, `rnicrosoft`), one-letter typos, brand-plus-keyword domains, punycode.
- **Links:** visible text that doesn't match the real target, raw IP hosts, brand names used as subdomains (`paypal.com.account-review.top`), URL shorteners, high-abuse TLDs, plain HTTP, embedded forms.
- **Language:** urgency, account threats, credential or money requests (gift cards, wire transfers), secrecy ("don't call").
- **Attachments:** executables and scripts, double extensions, macro-enabled Office files, HTML/SVG attachments, archives.

## How scoring works

Each rule has a weight. Each type of check counts once toward the total (its highest-weighted hit), so ten bad links don't drown out everything else, but every occurrence is still listed. The total is capped at 100:

| Score | Verdict |
|-------|---------|
| 0–29 | Low risk |
| 30–59 | Suspicious |
| 60–100 | High risk |

The three samples in `samples/` (fictitious domains, documentation IP ranges) score 100 (credential phish), 50 (CEO gift-card fraud with no links) and 0 (a normal newsletter).

## Tests

```bash
python -m unittest -v
```

20 tests cover each check, the samples, and false-positive cases such as real brand domains and `amazon.co.jp`.

## Limitations

- It's a triage aid, not a verdict. A low score doesn't prove an email is safe — mail sent from a compromised legitimate account will pass most checks.
- Authentication results are only as trustworthy as the server that added the header; make sure the top `Authentication-Results` comes from your own mail system.
- The domain logic uses a simplified approximation instead of the full Public Suffix List.
- No reputation lookups, sandboxing, or image/QR-code analysis.

## Roadmap

- Use the Public Suffix List for domain parsing
- Detect links hidden in QR-code images
- Optional threat-intel lookups (e.g. URL reputation), off by default
- Read mailboxes directly (IMAP / Microsoft 365) for batch triage

## Author

Yiren Qiao — MSc Advanced Cyber Security, King's College London.

## License

MIT — see [LICENSE](LICENSE).
