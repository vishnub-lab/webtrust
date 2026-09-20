"""
risk_score.py - Transparent Risk Scoring Engine
===============================================
This module calculates an educational trust & risk score between 0 and 100.

SCORING PHILOSOPHY:
- 0 to 29:   "Likely Trustworthy"   (Low risk, good security habits)
- 30 to 65:  "Needs Caution"        (Moderate risk, some signals missing)
- 66 to 100: "High Risk Indicators" (Significant number of warning signs)

RULES EXPLANATION:
Every rule has an assigned weight. Points are added when suspicious patterns
or missing security standards are detected.
"""


CATEGORY_NAMES = (
    "SSL / Encryption",
    "Domain / Reputation",
    "URL Structure",
    "Redirects",
    "Content Trust",
    "Security Headers",
)


def _finding_details(message: str, positive: bool = False) -> tuple[str, str, str]:
    """Map a legacy signal message to an explainable finding record."""
    lowered = message.lower()
    if any(term in lowered for term in ("https", "ssl", "tls", "certificate", "encrypted", "http ")):
        category = "SSL / Encryption"
    elif any(term in lowered for term in ("redirect", "destination")):
        category = "Redirects"
    elif any(term in lowered for term in ("url", "@ symbol", "keyword", "hyphen", "subdomain")):
        category = "URL Structure"
    elif any(term in lowered for term in ("header", "hsts", "csp", "frame", "mime", "referrer")):
        category = "Security Headers"
    elif any(term in lowered for term in ("domain", "ip address", "dns", "registered", "brand impersonation", "brand name")):
        category = "Domain / Reputation"
    else:
        category = "Content Trust"

    if positive:
        return category, "Informational", f"Positive evidence: {message}"
    if any(term in lowered for term in ("invalid", "expired", "password", "could not", "insecure", "unencrypted", "raw ip", "@ symbol")):
        severity = "Critical" if any(term in lowered for term in ("password", "insecure", "invalid", "expired")) else "Risk"
    else:
        severity = "Warning"
    return category, severity, message


def _build_findings(
    positive_signals: list[str],
    warning_signals: list[str],
    risk_signals: list[str],
) -> list[dict]:
    findings = []
    for message in positive_signals:
        category, severity, explanation = _finding_details(message, positive=True)
        findings.append({
            "category": category,
            "severity": severity,
            "message": message,
            "explanation": explanation,
        })
    for message in warning_signals + risk_signals:
        category, severity, explanation = _finding_details(message)
        findings.append({
            "category": category,
            "severity": severity,
            "message": message,
            "explanation": explanation,
        })
    return findings


def calculate_risk(analysis_data: dict) -> dict:
    """
    Calculates the risk score (0-100) and produces detailed signals and category breakdown.
    
    Category Breakdown:
    - HTTPS: 0 to 25 points
    - Domain: 0 to 25 points
    - URL Structure: 0 to 20 points
    - Redirects: 0 to 15 points
    - Website Content: 0 to 20 points
    - Security Headers: 0 to 20 points
    
    Returns a dictionary containing:
    - 'score': Final clamped score (0-100)
    - 'verdict': Text classification
    - 'verdict_color': CSS color code
    - 'breakdown': Points per category (for Graph 1)
    - 'positive_signals': List of good findings
    - 'warning_signals': List of caution findings
    - 'risk_signals': List of high-risk findings
    - 'summary': Short sentence summarizing the score
    """
    url_data = analysis_data.get("url_data", {})
    headers = analysis_data.get("security_headers", {})
    trust_pages = analysis_data.get("trust_pages", {})
    
    # Track points per category
    cat_https = 0
    cat_domain = 0
    cat_url = 0
    cat_redirects = 0
    cat_content = 0
    cat_headers = 0
    
    positive_signals = []
    warning_signals = []
    risk_signals = []
    evidence = []
    
    # -------------------------------------------------------------------------
    # RULE 1: HTTPS & SSL ENCRYPTION
    # HTTPS encrypts data between the visitor and the server.
    # -------------------------------------------------------------------------
    if url_data.get("is_https"):
        positive_signals.append("HTTPS is enabled for encrypted communication.")
    else:
        cat_https += 25
        risk_signals.append("Unencrypted HTTP is used. Sensitive data can be intercepted.")

    # If an SSL error occurred during connection
    if analysis_data.get("error_type") == "ssl":
        cat_https += 20
        risk_signals.append("SSL/TLS Certificate is invalid or untrusted.")
        evidence.append({"category": "HTTPS", "finding": "Invalid SSL/TLS certificate", "confidence": "High"})
    tls = analysis_data.get("tls_certificate", {})
    if tls.get("checked") and tls.get("valid") is False:
        cat_https += 20
        risk_signals.append("TLS certificate inspection failed.")
    elif tls.get("days_until_expiry") is not None:
        days = tls["days_until_expiry"]
        if days < 0:
            cat_https += 20
            risk_signals.append("TLS certificate is expired.")
        elif days <= 30:
            cat_https += 5
            warning_signals.append(f"TLS certificate expires soon ({days} days remaining).")
        else:
            positive_signals.append("TLS certificate is valid and not near expiry.")

    # -------------------------------------------------------------------------
    # RULE 2: DOMAIN & IP ADDRESS CHECK
    # Legitimate websites use registered domains (e.g. google.com), not raw IPs.
    # -------------------------------------------------------------------------
    if url_data.get("is_ip_address"):
        cat_domain += 25
        risk_signals.append("Domain is a raw IP address, frequently seen in phishing/attacks.")
    else:
        positive_signals.append("Uses a standard registered domain name.")

    if url_data.get("excessive_subdomains"):
        cat_domain += 10
        warning_signals.append(f"Excessive subdomains detected ({url_data.get('subdomain_count')} subdomains).")
    else:
        positive_signals.append("Normal subdomain structure.")

    dns = analysis_data.get("dns", {})
    if dns.get("resolved"):
        positive_signals.append("Domain resolves through DNS.")
    elif analysis_data.get("success"):
        cat_domain += 15
        risk_signals.append("Domain did not resolve through DNS.")

    whois = analysis_data.get("whois", {})
    if whois.get("domain_age_days") is not None:
        age = whois["domain_age_days"]
        if age < 30:
            cat_domain += 10
            warning_signals.append(f"Domain appears newly registered ({age} days old).")
            evidence.append({"category": "Domain", "finding": "Very new domain registration", "confidence": "Medium"})
        elif age >= 365:
            positive_signals.append("Domain registration is at least one year old.")

    # -------------------------------------------------------------------------
    # RULE 3: URL STRUCTURE & PHISHING PATTERNS
    # Malicious links often use special tricks (like '@') or deceptive keywords.
    # -------------------------------------------------------------------------
    if url_data.get("has_at_symbol"):
        cat_url += 15
        risk_signals.append("The '@' symbol was detected in the URL, which can disguise destination hosts.")
        evidence.append({"category": "URL Structure", "finding": "URL contains @", "confidence": "High"})
    
    if url_data.get("is_long_url"):
        cat_url += 10
        warning_signals.append(f"URL is unusually long ({url_data.get('url_length')} characters).")
    else:
        positive_signals.append("URL length is normal and concise.")

    if url_data.get("excessive_hyphens"):
        cat_url += 10
        warning_signals.append("Multiple hyphens found in domain, often used in typosquatting.")

    found_kw = url_data.get("found_keywords", [])
    if found_kw:
        cat_url += 10
        warning_signals.append(f"Sensitive keywords in URL: {', '.join(found_kw)}.")

    # -------------------------------------------------------------------------
    # RULE 4: REDIRECTS
    # Multiple redirects can be used to hide the true final destination.
    # -------------------------------------------------------------------------
    redirect_count = analysis_data.get("redirect_count", 0)
    if redirect_count == 0:
        positive_signals.append("Direct response without redirect hops.")
    elif redirect_count <= 2:
        positive_signals.append(f"Normal redirect behavior ({redirect_count} redirect(s)).")
    else:
        cat_redirects += 15
        warning_signals.append(f"High number of redirects detected ({redirect_count} hops).")
    final_url = analysis_data.get("final_url")
    original_url = analysis_data.get("original_url") or url_data.get("url")
    if final_url and original_url and final_url.rstrip("/") != original_url.rstrip("/"):
        warning_signals.append(f"Final destination differs from the submitted URL: {final_url}")
        evidence.append({
            "category": "Redirects",
            "finding": "Final destination differs from submitted URL",
            "confidence": "High",
        })

    # -------------------------------------------------------------------------
    # RULE 5: WEBSITE CONTENT & TRUST PAGES
    # Legitimate commercial or organizational sites usually feature basic trust pages.
    # Missing these does NOT mean a site is fake, but provides a minor signal.
    # -------------------------------------------------------------------------
    if analysis_data.get("success"):
        content_signals = analysis_data.get("content_signals", {})
        urgency = content_signals.get("urgency_phrases", [])
        support = content_signals.get("support_scam_phrases", [])
        external_actions = content_signals.get("external_form_actions", [])
        brand_mismatch = content_signals.get("brand_mismatch", [])
        login_form_count = content_signals.get("login_form_count", 0)

        if urgency:
            cat_content += min(8, len(urgency) * 3)
            warning_signals.append(
                f"Urgency language detected ({', '.join(urgency[:3])})."
            )
            evidence.append({
                "category": "Content Trust",
                "finding": "Urgency phrases found in visible page content",
                "confidence": "Medium",
            })
        if support:
            cat_content += min(10, len(support) * 4)
            risk_signals.append("Potential fake-support or malware-scare language detected.")
            evidence.append({
                "category": "Content Trust",
                "finding": f"Support/scare phrases: {', '.join(support[:3])}",
                "confidence": "Medium",
            })
        if login_form_count >= 2:
            cat_content += 5
            warning_signals.append(
                f"Multiple login-style forms detected ({login_form_count})."
            )
        if external_actions:
            cat_content += 8
            warning_signals.append(
                "A form submits data to a different domain than the page host."
            )
            evidence.append({
                "category": "Content Trust",
                "finding": "Cross-domain form action detected",
                "confidence": "High",
            })
        if brand_mismatch:
            cat_content += min(10, len(brand_mismatch) * 4)
            warning_signals.append(
                f"Brand name may not match the domain: {', '.join(brand_mismatch[:3])}."
            )
            evidence.append({
                "category": "Domain / Reputation",
                "finding": f"Possible brand impersonation: {', '.join(brand_mismatch[:3])}",
                "confidence": "Medium",
            })

        # Status code check
        status = analysis_data.get("status_code", 0)
        if status == 200:
            positive_signals.append("Website responded with HTTP 200 OK.")
        elif status in [401, 403]:
            cat_content += 10
            warning_signals.append(f"Website returned restricted status code {status}.")
        elif status >= 400:
            cat_content += 15
            warning_signals.append(f"Website returned client/server error code {status}.")

        # Check trust pages
        if trust_pages.get("privacy"):
            positive_signals.append("Privacy Policy page link detected.")
        else:
            cat_content += 5
            warning_signals.append("Privacy Policy link not detected on the homepage.")

        if trust_pages.get("contact"):
            positive_signals.append("Contact page link detected.")
        else:
            cat_content += 5
            warning_signals.append("Contact information page not detected on the homepage.")

        if trust_pages.get("about"):
            positive_signals.append("About page link detected.")
        else:
            cat_content += 3
            warning_signals.append("About page not detected.")

        if trust_pages.get("terms"):
            positive_signals.append("Terms of Service link detected.")
        else:
            cat_content += 2
            warning_signals.append("Terms of Service link not detected.")

        # Forms and password fields
        if analysis_data.get("has_password_field") and not url_data.get("is_https"):
            cat_content += 20
            risk_signals.append("Login form / password field detected over insecure HTTP connection!")
    else:
        # Connection failed or error
        cat_content += 20
        risk_signals.append(f"Could not retrieve webpage content: {analysis_data.get('error_message')}")
        evidence.append({
            "category": "Website Content",
            "finding": analysis_data.get("error_message") or "Page could not be retrieved",
            "confidence": "High" if analysis_data.get("error_type") else "Medium",
        })

    # -------------------------------------------------------------------------
    # RULE 6: SECURITY HEADERS
    # Headers protect against common web attacks.
    # -------------------------------------------------------------------------
    header_checks = [
        # Missing headers are useful caution signals, but should not outweigh
        # direct evidence such as an invalid certificate or unsafe form.
        ("hsts", "Strict-Transport-Security (HSTS)", 4),
        ("csp", "Content-Security-Policy (CSP)", 4),
        ("x_frame_options", "X-Frame-Options (Clickjacking defense)", 3),
        ("x_content_type_options", "X-Content-Type-Options (MIME sniffing defense)", 2),
        ("referrer_policy", "Referrer-Policy", 1)
    ]
    
    missing_headers = []
    present_headers = []
    
    for key, name, weight in header_checks:
        if headers.get(key):
            present_headers.append(name)
        else:
            cat_headers += weight
            missing_headers.append(name)
            
    if present_headers:
        positive_signals.append(f"Security headers enabled: {len(present_headers)} of {len(header_checks)} recommended headers detected.")
    if missing_headers:
        warning_signals.append(f"Missing security headers: {', '.join([h.split()[0] for h in missing_headers])}.")

    if analysis_data.get("trust_page_evidence"):
        evidence.append({
            "category": "Website Content",
            "finding": "Trust-page evidence collected from page links and headings",
            "confidence": "Medium",
        })

    # -------------------------------------------------------------------------
    # CALCULATE FINAL SCORE
    # -------------------------------------------------------------------------
    total_raw_score = (
        cat_https +
        cat_domain +
        cat_url +
        cat_redirects +
        cat_content +
        cat_headers
    )
    
    # Cap total score strictly between 0 and 100
    final_score = min(100, max(0, total_raw_score))

    # Confidence describes how much observable evidence supports this scan.
    confidence_score = 20
    if analysis_data.get("success"):
        confidence_score += 35
    if analysis_data.get("status_code") is not None:
        confidence_score += 15
    if analysis_data.get("final_url"):
        confidence_score += 10
    if analysis_data.get("dns", {}).get("resolved"):
        confidence_score += 10
    if analysis_data.get("tls_certificate", {}).get("checked"):
        confidence_score += 5
    if analysis_data.get("whois", {}).get("available"):
        confidence_score += 5
    confidence_score = min(100, confidence_score)
    confidence = (
        "High" if confidence_score >= 75
        else "Medium" if confidence_score >= 45
        else "Low"
    )
    
    # Determine classification
    if final_score < 30:
        verdict = "Likely Trustworthy"
        verdict_color = "#10b981"  # Emerald Green
        verdict_badge = "trustworthy"
        summary = "This website shows more positive than negative signals, but no automated scan proves a site is safe."
    elif final_score <= 65:
        verdict = "Needs Caution"
        verdict_color = "#f59e0b"  # Amber / Yellow
        verdict_badge = "caution"
        summary = "Some safety signals or security configurations are missing. Review the evidence before trusting this site."
    else:
        verdict = "High Risk Indicators"
        verdict_color = "#ef4444"  # Red
        verdict_badge = "high-risk"
        summary = "Multiple high-risk indicators were detected. Avoid entering sensitive information until independently verified."

    findings = _build_findings(positive_signals, warning_signals, risk_signals)
    findings_by_category = {
        category: [finding for finding in findings if finding["category"] == category]
        for category in CATEGORY_NAMES
    }
    severity_counts = {
        severity: sum(1 for finding in findings if finding["severity"] == severity)
        for severity in ("Informational", "Warning", "Risk", "Critical")
    }

    return {
        "score": final_score,
        "verdict": verdict,
        "verdict_badge": verdict_badge,
        "verdict_color": verdict_color,
        "summary": summary,
        "confidence": confidence,
        "confidence_score": confidence_score,
        "thresholds": {
            "Likely Trustworthy": "0-29",
            "Needs Caution": "30-65",
            "High Risk Indicators": "66-100",
        },
        "evidence": evidence,
        "findings": findings,
        "findings_by_category": findings_by_category,
        "severity_counts": severity_counts,
        "breakdown": {
            "HTTPS": cat_https,
            "Domain": cat_domain,
            "URL Structure": cat_url,
            "Redirects": cat_redirects,
            "Website Content": cat_content,
            "Security Headers": cat_headers
        },
        "positive_signals": positive_signals,
        "warning_signals": warning_signals,
        "risk_signals": risk_signals
    }
