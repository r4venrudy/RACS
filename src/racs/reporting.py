"""Escaped HTML and network-free PDF reports from persisted findings."""

import textwrap
from html import escape
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer


def html_report(report):
    s = report["session"]

    def e(value):
        return escape(str(value), quote=True)

    parts = [
        f"<!doctype html><html lang='en'><meta charset='utf-8'><title>RACS report {e(s['id'])}</title>",
        "<style>body{font:16px/1.6 system-ui;max-width:1000px;margin:48px auto;padding:0 24px;color:#14222c}h1{font-size:36px}article{border-top:2px solid #ccd6db;margin:36px 0;padding-top:16px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#eef2f4;padding:20px}small{color:#536470}.badge{font-weight:700}h2{margin-bottom:8px}</style>",
        "<h1>RACS security report</h1><p>Authorized testing only. Findings describe the tested scope, not a guarantee of security.</p>",
        f"<p><b>Target:</b> {e(s['origin'])}<br><b>Session:</b> {e(s['id'])}<br><b>Status:</b> {e(s['status'])}<br>{e(s['detail'])}</p>",
        "<h2>Coverage and limitations</h2>",
    ]
    seen = set()
    for o in report["outcomes"]:
        seen.add(o["check"])
        parts.append(f"<p><b>{e(o['check'])}: {e(o['status'])}</b> — {e(o['detail'])}</p>")
    for name in ("headers", "xss", "sqli", "idor"):
        if name not in seen:
            parts.append(
                f"<p><b>{name}: not performed</b> — Not selected or interrupted before this check.</p>"
            )
    for f in report["findings"]:
        parts.append(
            f"<article><h2>{e(f['type'])}</h2><p class='badge'>{e(f['severity'])} severity · {e(f['confidence'])} confidence · {e(f['verification_status'])}</p><p>{e(f['affected_url'])} · parameter: {e(f['affected_parameter'] or 'none')}</p>"
        )
        for label, key in (
            ("Confidence rationale", "confidence_rationale"),
            ("Evidence", "evidence"),
            ("Remediation", "remediation"),
        ):
            parts.append(f"<h3>{label}</h3><p>{e(f[key])}</p>")
        parts.append(
            "<h3>Reproduction</h3><ol>"
            + "".join(f"<li>{e(step)}</li>" for step in f["reproduction_steps"])
            + "</ol>"
        )
        parts.append(
            f"<h3>Sample fix</h3><pre>{e(f['sample_fix_snippet'])}</pre><small>Finding ID: {e(f['id'])}</small></article>"
        )
    if not report["findings"]:
        parts.append(
            "<p>No verified findings were recorded. Review coverage and skipped/inconclusive checks; this is not proof that the target is safe.</p>"
        )
    return "".join(parts) + "</html>"


def pdf_report(report):
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=(595.28, 841.89),
        rightMargin=45,
        leftMargin=45,
        topMargin=45,
        bottomMargin=45,
    )
    styles = getSampleStyleSheet()
    styles["Normal"].fontSize = 10
    styles["Normal"].leading = 14
    story = []

    def para(text, style="Normal"):
        # No images, markup from findings, remote URLs, file paths or renderer fetches.
        story.append(Paragraph(escape(str(text)), styles[style]))
        story.append(Spacer(1, 8))

    para("RACS SECURITY REPORT", "Title")
    para("Authorized testing only. Results cover only the declared endpoints and controls.")
    s = report["session"]
    para(s["origin"], "Heading2")
    para("Session: " + s["id"])
    para("Status: " + s["status"] + " — " + s["detail"])
    para("Coverage and limitations", "Heading1")
    seen = set()
    for o in report["outcomes"]:
        seen.add(o["check"])
        para(o["check"] + " / " + o["status"], "Heading2")
        para(o["detail"])
    for name in ("headers", "xss", "sqli", "idor"):
        if name not in seen:
            para(name + ": not performed (not selected or interrupted).")
    for f in report["findings"]:
        para(f["type"], "Heading1")
        para(
            f"{f['severity']} severity | {f['confidence']} confidence | {f['verification_status']}"
        )
        para(str(f["affected_url"]) + " / parameter: " + str(f["affected_parameter"] or "none"))
        for label, key in (
            ("Confidence rationale", "confidence_rationale"),
            ("Evidence", "evidence"),
            ("Remediation", "remediation"),
        ):
            para(label, "Heading2")
            para(f[key])
        para("Reproduction", "Heading2")
        for i, step in enumerate(f["reproduction_steps"], 1):
            para(f"{i}. {step}")
        para("Sample fix", "Heading2")
        wrapped = "\n".join(
            "\n".join(
                textwrap.wrap(line, 82, replace_whitespace=False, drop_whitespace=False) or [""]
            )
            for line in f["sample_fix_snippet"].splitlines()
        )
        style = styles["Code"]
        style.fontSize = 8
        style.leading = 10
        story.append(Preformatted(wrapped, style))
    if not report["findings"]:
        para(
            "No verified findings recorded. Skipped checks are not passes; absence of findings is not a security guarantee."
        )

    def footer(canvas, doc):
        canvas.setFillColor(colors.HexColor("#536470"))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(45, 25, "RACS | " + s["id"])
        canvas.drawRightString(550, 25, str(doc.page))

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
