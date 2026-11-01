from __future__ import annotations

import csv
import io
import uuid
from datetime import timedelta
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from .analytics import attack_matrix, executive_overview
from .config import get_settings
from .models import (
    Incident,
    IncidentTimeline,
    Indicator,
    IndicatorAttack,
    IndicatorRelationship,
    IndicatorSource,
    IndicatorTag,
    Report,
    Tag,
    User,
)
from .security import allowed_tlps
from .utils import TLP_ORDER, iso, utcnow

settings = get_settings()

TLP_MARKINGS = {
    "clear": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "green": "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
    "amber": "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
    "red": "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
}


def _pattern(indicator: Indicator) -> str:
    value = indicator.value.replace("\\", "\\\\").replace("'", "\\'")
    mapping = {
        "ip": "ipv4-addr:value" if ":" not in indicator.value else "ipv6-addr:value",
        "domain": "domain-name:value",
        "url": "url:value",
        "hash_md5": "file:hashes.'MD5'",
        "hash_sha1": "file:hashes.'SHA-1'",
        "hash_sha256": "file:hashes.'SHA-256'",
        "email": "email-addr:value",
    }
    return f"[{mapping[indicator.type]} = '{value}']"


def _stix_id(indicator: Indicator) -> str:
    object_type = "vulnerability" if indicator.type == "cve" else "indicator"
    return f"{object_type}--{indicator.id}"


def _stix_object(indicator: Indicator, object_id: str, metadata: dict, now: str) -> dict:
    created = indicator.created_at.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    modified = max(indicator.created_at, indicator.updated_at).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    common = {
        "spec_version": "2.1",
        "id": object_id,
        "created": created,
        "modified": modified,
        "name": indicator.value if indicator.type == "cve" else f"{indicator.type.upper()} {indicator.value[:120]}",
        "confidence": indicator.confidence,
        "labels": [indicator.type, *metadata["tags"], *metadata["attack"]],
        "object_marking_refs": [TLP_MARKINGS[indicator.tlp]],
        "x_threatlens_severity_score": indicator.severity_score,
        "x_threatlens_tlp": indicator.tlp,
        "x_threatlens_internal_sightings": indicator.internal_sightings,
        "x_threatlens_generated_at": now,
    }
    if indicator.notes:
        common["description"] = indicator.notes[:1000]
    if metadata["sources"]:
        common["x_threatlens_sources"] = metadata["sources"]
    if indicator.type == "cve":
        return {
            "type": "vulnerability",
            **common,
            "external_references": [{"source_name": "cve", "external_id": indicator.value}],
        }
    valid_from = indicator.first_seen
    valid_until = max(indicator.first_seen, indicator.last_seen) + timedelta(days=90)
    return {
        "type": "indicator",
        **common,
        "indicator_types": ["malicious-activity"],
        "pattern": _pattern(indicator),
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": valid_from.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "valid_until": valid_until.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    }


def build_stix_bundle(db: Session, indicators: list[Indicator]) -> dict:
    now = utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    ids = {indicator.id: _stix_id(indicator) for indicator in indicators}
    by_id = {indicator.id: indicator for indicator in indicators}
    objects: list[dict] = []
    tags_by_id: dict[str, list[str]] = {}
    attack_by_id: dict[str, list[str]] = {}
    if indicators:
        indicator_ids = [indicator.id for indicator in indicators]
        for indicator_id, name in db.execute(
            select(IndicatorTag.indicator_id, Tag.name)
            .join(Tag, Tag.id == IndicatorTag.tag_id)
            .where(IndicatorTag.indicator_id.in_(indicator_ids))
        ).all():
            tags_by_id.setdefault(indicator_id, []).append(name)
        for indicator_id, technique in db.execute(
            select(IndicatorAttack.indicator_id, IndicatorAttack.technique_id).where(
                IndicatorAttack.indicator_id.in_(indicator_ids)
            )
        ).all():
            attack_by_id.setdefault(indicator_id, []).append(technique)
        source_rows = db.execute(
            select(IndicatorSource.indicator_id, IndicatorSource.source_name).where(
                IndicatorSource.indicator_id.in_(indicator_ids)
            )
        ).all()
        sources_by_id: dict[str, list[str]] = {}
        for indicator_id, name in source_rows:
            sources_by_id.setdefault(indicator_id, []).append(name)
    else:
        sources_by_id = {}
    for indicator in indicators:
        metadata = {
            "tags": tags_by_id.get(indicator.id, [])[:10],
            "attack": attack_by_id.get(indicator.id, [])[:10],
            "sources": sources_by_id.get(indicator.id, []),
        }
        objects.append(_stix_object(indicator, ids[indicator.id], metadata, now))
    for indicator in indicators:
        for edge in db.execute(
            select(IndicatorRelationship).where(
                IndicatorRelationship.source_id == indicator.id,
                IndicatorRelationship.target_id.in_(list(ids.keys())),
            )
        ).scalars().all():
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{edge.id}",
                    "created": now,
                    "modified": now,
                    "relationship_type": edge.relation_type,
                    "source_ref": ids[edge.source_id],
                    "target_ref": ids[edge.target_id],
                    "confidence": edge.confidence,
                    "object_marking_refs": [TLP_MARKINGS[max(
                        (by_id[edge.source_id].tlp, by_id[edge.target_id].tlp),
                        key=lambda value: TLP_ORDER[value],
                    )]],
                }
            )
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def _csv_safe(value) -> str:
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


def export_csv(db: Session, indicators: list[Indicator]) -> str:
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)
    writer.writerow(
        [
            "value", "type", "severity_score", "confidence", "tlp", "status",
            "first_seen", "last_seen", "country", "asn", "internal_sightings",
            "sources", "tags", "attack_techniques",
        ]
    )
    ids = [indicator.id for indicator in indicators]
    sources: dict[str, list[str]] = {}
    tags: dict[str, list[str]] = {}
    attacks: dict[str, list[str]] = {}
    if ids:
        for indicator_id, name in db.execute(
            select(IndicatorSource.indicator_id, IndicatorSource.source_name).where(
                IndicatorSource.indicator_id.in_(ids)
            )
        ).all():
            sources.setdefault(indicator_id, []).append(name)
        for indicator_id, name in db.execute(
            select(IndicatorTag.indicator_id, Tag.name)
            .join(Tag, Tag.id == IndicatorTag.tag_id)
            .where(IndicatorTag.indicator_id.in_(ids))
        ).all():
            tags.setdefault(indicator_id, []).append(name)
        for indicator_id, technique in db.execute(
            select(IndicatorAttack.indicator_id, IndicatorAttack.technique_id).where(
                IndicatorAttack.indicator_id.in_(ids)
            )
        ).all():
            attacks.setdefault(indicator_id, []).append(technique)
    for indicator in indicators:
        writer.writerow(
            [
                _csv_safe(indicator.value),
                indicator.type,
                indicator.severity_score,
                indicator.confidence,
                indicator.tlp,
                indicator.status,
                iso(indicator.first_seen),
                iso(indicator.last_seen),
                _csv_safe(indicator.country),
                _csv_safe(indicator.asn),
                indicator.internal_sightings,
                _csv_safe("; ".join(sources.get(indicator.id, []))),
                _csv_safe("; ".join(tags.get(indicator.id, []))),
                _csv_safe("; ".join(attacks.get(indicator.id, []))),
            ]
        )
    return output.getvalue()


def _footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(18 * mm, 12 * mm, "Sentinova ThreatLens · Confidential · TLP:AMBER")
    canvas.drawRightString(192 * mm, 12 * mm, f"Page {doc.page}")
    canvas.restoreState()


def generate_report(
    db: Session,
    *,
    user: User,
    title: str,
    kind: str = "executive",
    incident_id: str | None = None,
) -> Report:
    overview = executive_overview(db, user.role)
    report = Report(
        title=title[:240],
        kind=kind,
        requested_by=user.id,
        status="generating",
        options={"incident_id": incident_id},
    )
    db.add(report)
    db.flush()
    path = settings.report_dir / f"{report.id}.pdf"
    try:
        styles = getSampleStyleSheet()
        styles.add(
            ParagraphStyle(
                name="TLTitle", parent=styles["Title"], textColor=colors.HexColor("#0ea5e9"),
                fontSize=22, leading=26, spaceAfter=8,
            )
        )
        styles.add(
            ParagraphStyle(
                name="TLBody", parent=styles["BodyText"], fontSize=9, leading=13,
                textColor=colors.HexColor("#1e293b"),
            )
        )
        styles.add(
            ParagraphStyle(
                name="TLSmall", parent=styles["BodyText"], fontSize=7.5, leading=10,
                textColor=colors.HexColor("#475569"),
            )
        )
        document = SimpleDocTemplate(
            str(path),
            pagesize=A4,
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=20 * mm,
            bottomMargin=20 * mm,
            title=title,
            author="Sentinova ThreatLens",
        )
        story = [
            Paragraph("SENTINOVA THREATLENS", styles["TLTitle"]),
            Paragraph(escape(title), styles["Heading1"]),
            Paragraph(
                f"Generated {escape(iso(utcnow()) or '')} by {escape(user.name)} "
                f"({escape(user.role)}) · Report ID {report.id}",
                styles["TLSmall"],
            ),
            Spacer(1, 6 * mm),
        ]
        counts = overview["counts"]
        summary = (
            f"Current composite risk score is <b>{overview['risk_score']}/100</b>. "
            f"The platform tracks <b>{counts['active']}</b> active indicators, of which "
            f"<b>{counts['critical']}</b> are critical and <b>{counts['high']}</b> high severity. "
            f"{counts['sightings']} internal sightings have been correlated. "
            f"There are <b>{counts['open_alerts']}</b> open alerts and "
            f"<b>{counts['open_incidents']}</b> open incidents. "
            f"{counts['kev']} indicators reference CISA KEV entries."
        )
        story.append(Paragraph("Executive Summary", styles["Heading2"]))
        story.append(Paragraph(summary, styles["TLBody"]))
        story.append(Spacer(1, 4 * mm))

        trend_data = [["Date", "Indicators", "Avg score"]] + [
            [point["date"], str(point["count"]), str(point["avg_score"])]
            for point in overview["trend"][-10:]
        ]
        story.append(Paragraph("Risk Trend (last 10 days)", styles["Heading2"]))
        story.append(_table(trend_data, [70 * mm, 40 * mm, 40 * mm]))
        story.append(Spacer(1, 4 * mm))

        attack = attack_matrix(db, user.role)
        attack_rows = [["Tactic", "Mapped techniques", "Technology coverage"]]
        for tactic in attack["tactics"]:
            if tactic["mapped"]:
                coverage = (
                    f"{tactic['mapped']}/{tactic['total']}"
                    if tactic["total"]
                    else str(tactic["mapped"])
                )
                attack_rows.append(
                    [tactic["name"], str(tactic["mapped"]), coverage]
                )
        if len(attack_rows) > 1:
            story.append(Paragraph("ATT&CK Coverage", styles["Heading2"]))
            story.append(_table(attack_rows[:12], [70 * mm, 40 * mm, 40 * mm]))
            story.append(Spacer(1, 4 * mm))

        if overview["top_indicators"]:
            heading = "Top Priority Indicators" if user.role != "executive" else "Top Threat Categories"
            story.append(Paragraph(heading, styles["Heading2"]))
            if user.role == "executive" or allowed_tlps(user.role) == set():
                rows = [["Category", "Count"]]
                rows += [[escape(item["value"]), str(item["count"])] for item in overview["categories"]]
            else:
                rows = [["Indicator", "Type", "Score", "TLP", "Sightings"]]
                for item in overview["top_indicators"]:
                    rows.append(
                        [
                            escape(item["value"][:48]),
                            escape(item["type"]),
                            str(item["severity_score"]),
                            item["tlp"].upper(),
                            str(item["internal_sightings"]),
                        ]
                    )
            story.append(_table(rows, [80 * mm, 26 * mm, 18 * mm, 16 * mm, 22 * mm]))
            story.append(Spacer(1, 4 * mm))

        if kind == "incident" and incident_id:
            incident = db.get(Incident, incident_id)
            if incident:
                story.append(PageBreak())
                story.append(Paragraph("Incident Detail", styles["Heading1"]))
                story.append(Paragraph(escape(incident.title), styles["Heading2"]))
                story.append(Paragraph(escape(incident.summary or ""), styles["TLBody"]))
                story.append(
                    Paragraph(
                        f"Status: {escape(incident.status)} · Severity: "
                        f"{escape(incident.severity)} · Opened: {iso(incident.created_at)}",
                        styles["TLSmall"],
                    )
                )
                story.append(Spacer(1, 3 * mm))
                timeline = db.execute(
                    select(IncidentTimeline)
                    .where(IncidentTimeline.incident_id == incident.id)
                    .order_by(IncidentTimeline.created_at.asc())
                ).scalars().all()
                rows = [["Time", "Type", "Event"]]
                for entry in timeline:
                    rows.append(
                        [iso(entry.created_at) or "", entry.event_type, escape(entry.message[:220])]
                    )
                story.append(_table(rows, [34 * mm, 26 * mm, 122 * mm]))
        story.append(Spacer(1, 6 * mm))
        story.append(
            Paragraph(
                "Method note: severity scores are computed by the transparent ThreatLens v1 "
                "additive model (source confidence, recency, verdict ratio, internal sightings, "
                "exploitation). Enrichment marked as simulated is derived from feed provenance, "
                "not an independent third-party verdict.",
                styles["TLSmall"],
            )
        )
        document.build(story, onFirstPage=_footer, onLaterPages=_footer)
        report.status = "completed"
        report.completed_at = utcnow()
        report.storage_path = str(path)
        db.commit()
        return report
    except Exception:
        report.status = "failed"
        report.completed_at = utcnow()
        db.commit()
        raise


def _table(rows: list[list[str]], widths: list[float]) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def report_path_safe(path_value: str) -> Path:
    path = Path(path_value).resolve()
    root = settings.report_dir.resolve()
    if root not in path.parents:
        raise ValueError("Report path is outside the managed report directory")
    return path
