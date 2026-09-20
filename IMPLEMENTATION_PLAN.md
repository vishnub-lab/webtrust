# WebTrust Enhancement Implementation Plan

## Project Goal
Turn the current WebTrust project from a strong educational website trust scanner into a more competitive, market-ready cybersecurity product by improving detection quality, scoring, reporting, and product features.

---

## Current Implementation Status

| Area | Status | Notes |
| --- | --- | --- |
| Core URL validation and scan errors | Complete | Normalization, validation, timeout/SSL/DNS/connection errors, logging, and redirect evidence are implemented. |
| Domain, SSL, and DNS intelligence | Complete | WHOIS age, TLS inspection, DNS resolution, and MX checks are implemented. |
| Explainable scoring | Complete | Findings include categories, severity, confidence, evidence, and explanations. |
| Result dashboard | Complete | The result page shows score, verdict, findings, infrastructure, redirects, and exports. |
| Reports and exports | Complete | TXT, PDF, JSON, and history CSV exports are available. |
| Basic scan history | Complete | Scans are stored and displayed with a trend chart. |
| API, batch scans, accounts, favorites | Complete | `POST /api/scan`, authentication, dashboard, and saved scans are available. |
| Browser extension starter | Complete | A Manifest V3 local API client is included. |
| Runtime protections | Complete | Bounded responses, caching, concurrent batches, rate limiting, and logging are implemented. |
| History search and domain comparison | Remaining | History currently needs filtering, pagination, and side-by-side comparison. |
| Production security hardening | Partial | SSRF defenses are implemented; CSRF protection, secure cookie settings, and stronger account controls remain. |
| Comprehensive automated testing | Partial | Core unit tests exist; route, authentication, export, error, and security tests remain. |
| External reputation intelligence | Future | No third-party threat-intelligence API is currently integrated. |

---

## Phase 1: Stabilize and Improve the Core Scanner

### Objective
Make the current scanner more reliable, explainable, and production-friendly.

### Tasks
1. Improve input validation
   - Accept and normalize common URL variants
   - Reject malformed inputs early
   - Handle `www.` and non-standard domain cases cleanly

2. Improve error handling
   - Distinguish between timeout, SSL, DNS, and connection failures
   - Return more meaningful user warnings
   - Log scan errors for debugging

3. Add stronger evidence collection
   - Capture redirect chain details clearly
   - Detect whether the final target differs from the original URL
   - Record HTTP status and final response URL

4. Improve trust signal detection
   - Improve About / Contact / Privacy / Terms detection
   - Check multiple page types and patterns
   - Reduce false positives for generic links

5. Refine risk scoring logic
   - Make weights more realistic
   - Add confidence labels
   - Add evidence-based explanations for each category

### Deliverables
- More accurate analysis results
- Cleaner scan output
- Better user trust in the scoring system

---

## Phase 2: Add Domain and SSL Intelligence

### Objective
Increase the tool's value by checking signals beyond the homepage HTML.

### Features to Add
1. WHOIS domain age analysis
   - Determine how old the domain is
   - Flag very new domains as higher risk

2. SSL certificate inspection
   - Check expiry date
   - Check issuing authority
   - Flag self-signed or invalid certificates

3. DNS record checks
   - Check whether the domain resolves correctly
   - Inspect MX records and basic hosting patterns

4. Domain reputation heuristics
   - Flag suspicious subdomain behavior
   - Check common phishing-like patterns

### Suggested Libraries
- `python-whois` or equivalent
- `dnspython`
- `ssl` standard library improvements

### Deliverables
- Better quality of risk judgment
- More credible enterprise-style trust analysis

---

## Phase 3: Improve the Risk Model

### Objective
Move from a simple rules engine to a more explainable and smarter decision model.

### Improvements
1. Add confidence scoring
   - low confidence
   - medium confidence
   - high confidence

2. Split findings by category
   - SSL / Encryption
   - Domain / Reputation
   - URL Structure
   - Redirects
   - Content Trust
   - Security Headers

3. Add severity labels
   - Informational
   - Warning
   - Risk
   - Critical

4. Add user-facing explanations
   - Example: “This site uses HTTP instead of HTTPS and exposes login fields over an insecure connection.”

5. Add scoring thresholds
   - 0–29: Likely trustworthy
   - 30–65: Needs caution
   - 66–100: High risk

### Deliverables
- More understandable assessments
- Stronger credibility with users

---

## Phase 4: Upgrade the Frontend Experience

### Objective
Make the app feel like a modern product, not just a demo.

### UI Changes
1. Build a cleaner result dashboard
   - risk score card
   - verdict badge
   - trust breakdown chart
   - quick explanations

2. Add scan detail sections
   - security headers list
   - redirect chain summary
   - page title, links, forms count
   - trust page status

3. Improve visual hierarchy
   - better spacing
   - darker premium theme
   - clear status colors
   - section-based layout

4. Add summary cards
   - HTTPS status
   - domain status
   - final verdict
   - recommendation

### Deliverables
- Better user experience
- More polished presentation

---

## Phase 5: Add Reporting and Export Features

### Objective
Make results useful for sharing, documentation, and evaluation.

### Features
1. Downloadable PDF report
   - using `reportlab` or `weasyprint`

2. Better text report
   - include risk summary
   - add category breakdown
   - include evidence list

3. JSON export
   - structured machine-readable output

4. CSV export for history
   - useful for analysis or reporting

### Deliverables
- Professional reporting capability
- Better business/product usability

---

## Phase 6: Add Scan History and Trend Analysis

### Objective
Let users compare website health over time and monitor patterns.

### Features
1. Save richer scan records
   - domain
   - score
   - verdict
   - scan timestamp
   - factors detected

2. Trend comparisons
   - score over time
   - risk trend chart
   - compare multiple scans for the same domain

3. Search and filter history
   - by domain
   - by verdict
   - by date

### Implementation status
- [x] Store richer scan records
- [x] Show a historical risk chart
- [ ] Add domain, verdict, and date filters
- [ ] Add pagination or a bounded history window
- [ ] Add side-by-side comparison for two scans of the same domain

### Deliverables
- Improved user retention
- Better analytics and product depth

---

## Phase 7: Add a Developer/Business Layer

### Objective
Add product value beyond the single-user scanner.

### Features
1. REST API endpoint
   - `POST /api/scan`
   - returns JSON analysis results

2. Batch scanning support
   - multiple URLs in one request

3. User accounts
   - saved scans
   - dashboard
   - favorites

4. Browser extension / bookmarklet
   - scan any website directly from the browser

### Deliverables
- More product potential
- Better scalability and market viability

---

## Phase 8: Add Smart Detection Features

### Objective
Increase the scanner’s value with more advanced detection logic.

### Features to Consider
1. Suspicious page content detection
   - login-heavy pages
   - urgency phrases
   - fake support prompts
   - copycat branding patterns

2. Phishing and scam indicators
   - mismatched brand names
   - suspicious form fields
   - mass redirect behavior

3. Brand impersonation heuristics
   - visual similarity checks
   - brand keyword detection in text and metadata

4. External threat intelligence integration
   - allow optional API-based reputation data

### Implementation status
- [x] Passive suspicious-content, urgency, fake-support, login-form, form-action, and brand-mismatch heuristics
- [ ] Improve false-positive evaluation with a labeled test corpus
- [ ] Add optional, provider-agnostic threat-intelligence integration
- [ ] Add visual or DOM similarity checks only after measuring their performance and cost

### Deliverables
- Higher real-world usefulness
- Stronger competitive differentiation

---

## Phase 9: Performance and Reliability

### Objective
Ensure the product remains stable under real usage.

### Improvements
1. Add multithreading or asynchronous requests
   - handle multiple scans efficiently

2. Limit request sizes safely
   - avoid huge response memory use

3. Add caching
   - reused scans for repeated domains

4. Add rate limiting
   - protect system resources

5. Improve logging
   - debugging and production monitoring

### Deliverables
- Better performance and scalability

---

## Phase 10: Productization and Launch Readiness

### Objective
Prepare the project for presentation, demo, or deployment.

### Tasks
1. Set up proper environment management
   - virtual environment
   - requirements lock file

2. Add deployment-ready configuration
   - environment variables
   - config file separation

3. Add testing
   - unit tests for URL normalization
   - tests for scoring logic
   - tests for scan result parsing
   - route and API tests
   - authentication and authorization tests
   - export and error-path tests
   - security regression tests

4. Add deployment docs
   - installation
   - usage guide
   - API docs
   - troubleshooting guide

5. Create a polished landing page
   - features
   - demo screenshots
   - pricing or project pitch if applicable

### Implementation status
- [x] Environment example, configuration separation, and pinned requirements
- [x] Deployment, API, troubleshooting, and safety documentation
- [x] Focused unit tests for normalization, parsing, caching, and scoring
- [x] Product-focused landing page content
- [ ] Replace legacy script-style tests with a maintained test suite
- [ ] Add CI to run syntax checks, tests, and dependency checks
- [ ] Add production WSGI startup configuration and health checks
- [ ] Add database backup and migration guidance
- [ ] Add security headers, CSRF protection, secure cookies, and account lockout/session controls

### Deliverables
- Market-ready demo
- Easy setup for users and evaluators

---

## Remaining Work: Recommended Next Steps

### Priority 1: Production Security

Before exposing the scanner to untrusted users or public traffic:

1. Add SSRF protection:
   - allow only `http` and `https`
   - reject localhost, loopback, private, link-local, multicast, and reserved IP ranges
   - resolve DNS and re-check the destination before connecting
   - limit redirects and prevent redirects into blocked networks
   - **Implemented:** public-address preflight validation, redirect destination
     validation, and a five-hop redirect limit are now enforced by
     `checker.py`.
2. Add CSRF protection to browser forms.
3. Set secure, HTTP-only, SameSite session cookies in production.
4. Enforce stronger passwords and add login throttling or account lockout.
5. Validate report filenames and keep generated files outside directly served paths.

### Priority 2: Test and Operate Reliably

1. Add Flask route tests for successful scans, invalid URLs, API batches, rate
   limits, authentication, favorites, and exports.
2. Add tests for timeout, TLS, DNS, WHOIS, redirect, and malformed-response
   failures.
3. Add a CI workflow for tests and syntax validation.
4. Add a `/health` endpoint and structured log fields such as request ID,
   duration, URL hostname, and error type.
5. Move cache and rate-limit state to a shared backend if multiple processes
   will run in production.

### Priority 3: Improve History and Product UX

1. Add history search, filters, pagination, and delete controls.
2. Add a domain comparison view showing score and finding changes over time.
3. Add scan cancellation and progress feedback for larger batches.
4. Add accessible keyboard navigation, responsive mobile layouts, and a clear
   privacy/data-retention page.

### Priority 4: Differentiate the Detection Model

1. Build a small labeled evaluation set of benign, suspicious, and phishing-like
   pages.
2. Measure precision, recall, false-positive rate, and scan latency.
3. Calibrate weights and confidence from those measurements rather than adding
   rules without evaluation.
4. Add optional threat-intelligence providers behind environment flags, with
   clear provider attribution and failure handling.

---

## Recommended Priority Order

### Highest Priority
1. Add SSRF protection and production web security controls
2. Expand route, API, authentication, export, and failure-path tests
3. Add CI, health checks, structured logs, and deployment startup configuration
4. Add history search, filtering, pagination, and domain comparison
5. Review scoring against a labeled evaluation set

### Medium Priority
1. Shared cache and rate-limit storage for multi-process deployment
2. Accessible and responsive dashboard improvements
3. Better batch progress and cancellation
4. Data retention, backup, and database migration workflows

### Longer-Term
1. Optional external threat-intelligence integration
2. ML-assisted phishing detection evaluated against labeled data
3. Visual/DOM brand similarity analysis
4. SaaS multi-tenant billing, quotas, teams, and audit logs

---

## Suggested MVP Feature Set for a Stronger Product

The first strong upgrade version is implemented:
- [x] Domain age detection through WHOIS analysis in `checker.py`
- [x] SSL certificate inspection for validity, issuer, and expiry in `checker.py`
- [x] Suspicious URL and content heuristics in `checker.py` and `risk_score.py`
- [x] Clearer risk explanations, evidence, severity, and confidence in `risk_score.py`
- [x] Improved categorized result dashboard in `templates/result.html`
- [x] Rich TXT, PDF, JSON, and CSV reports in `app.py`
- [x] Historical scan tracking and trend charts in `app.py` and `templates/history.html`

This minimum set is now in place and makes the project substantially more
professional and competitive. The next improvements should focus on
production deployment, stronger automated tests, and external reputation
intelligence.

---

## Final Recommendation
The best path is to keep the current educational foundation and evolve it into a more credible trust-analysis product by adding:
- deeper domain intelligence
- better score transparency
- stronger reporting
- modern dashboard UX
- product-ready APIs and history

This is the route most likely to make the project feel genuinely competitive in the market.
