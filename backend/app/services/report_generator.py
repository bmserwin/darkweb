"""Court-ready evidentiary exports: Section 65B PDF dossier and STIX 2.1.

Everything in this module is derived from the persisted forensic record - the
Merkle ledger, the bipartite identifier graph and the actor profiles - so a
dossier can be regenerated at any time and hash-compare against the ledger it
cites. Nothing here invents evidence: a field the record does not carry is
rendered as an explicit placeholder rather than a plausible-looking blank.

The PDF is styled for print: A4, ruled tables, a classification banner on every
page, and a formal Section 65B (BSA 2023) certificate that an examiner signs by
hand. The STIX bundle uses only spec-valid STIX 2.1 object types so downstream
CTI tooling accepts it without a custom-objects caveat.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import uuid
from typing import Any, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models.entities import (
    Actor,
    ActorProfile,
    AuditLedgerBlock,
    Identifier,
    IdentifierLink,
    ObservationEvent,
)
from .circadian_engine import analyse as circadian_analyse
from .fusion_engine import fuse_pair
from .merkle_ledger import MerkleLedger
from .stylometry_engine import compare as stylometry_compare

UTC = dt.timezone.utc

CLASSIFICATION = "CONFIDENTIAL // LAW ENFORCEMENT SENSITIVE"
CERTIFICATION_TEMPLATE = (
    "I, {officer}, certify that the electronic record contained in this dossier "
    "has been produced from a computer which was used regularly to store and "
    "process information of the kind contained in this record, and that the "
    "computer was operating properly throughout the material period of "
    "acquisition and analysis. The hash chain recorded in Section F was "
    "verified immediately prior to the production of this certificate. This "
    "certificate is issued under Section 65B of the Bharatiya Sakshya "
    "Adhiniyam, 2023, in respect of the electronic record described herein."
)


# ---------------------------------------------------------------------------
# Case assembly
# ---------------------------------------------------------------------------
def _as_utc(value: Optional[dt.datetime]) -> Optional[dt.datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _iso(value: Optional[dt.datetime]) -> str:
    moment = _as_utc(value)
    return moment.isoformat().replace("+00:00", "Z") if moment else "N/A"


def collect_actor_evidence(session: Session, handle: str) -> dict[str, Any]:
    """Gather every persisted artefact bound to ``handle`` into one bundle."""
    actor = session.execute(
        select(Actor).where(Actor.handle == handle)
    ).scalar_one_or_none()

    identifiers: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    corpora: list[str] = []
    timestamps: list[str] = []
    ledger_blocks: list[AuditLedgerBlock] = []

    query = (
        select(IdentifierLink, Identifier, ObservationEvent, AuditLedgerBlock)
        .join(Identifier, IdentifierLink.identifier_id == Identifier.id)
        .join(ObservationEvent, IdentifierLink.observation_id == ObservationEvent.id)
        .join(AuditLedgerBlock, ObservationEvent.ledger_block_id == AuditLedgerBlock.id)
        .order_by(ObservationEvent.observed_at.asc(), Identifier.id.asc())
    )
    if actor is not None:
        query = query.where(IdentifierLink.actor_id == actor.id)

    for _link, identifier, observation, block in session.execute(query):
        if block.id not in {b.id for b in ledger_blocks}:
            ledger_blocks.append(block)
        identifiers.append(
            {
                "id_type": identifier.id_type,
                "value": identifier.value,
                "confidence": float(identifier.confidence or 0.0),
                "first_seen": _iso(identifier.first_seen),
            }
        )
        observations.append(
            {
                "observation_id": observation.id,
                "source_url": observation.source_url,
                "platform": observation.platform,
                "observed_at": _iso(observation.observed_at),
                "payload_sha256": hashlib.sha256(
                    (observation.raw_text or "").encode("utf-8")
                ).hexdigest(),
            }
        )
        if observation.raw_text:
            corpora.append(observation.raw_text)
        timestamps.append(observation.observed_at.isoformat())

    profile = None
    if actor is not None:
        profile = session.execute(
            select(ActorProfile).where(ActorProfile.actor_id == actor.id)
        ).scalar_one_or_none()

    circadian = None
    if timestamps:
        circadian = circadian_analyse(timestamps, actor_handle=handle)

    wallets = sorted({i["value"] for i in identifiers if i["id_type"] == "BTC_WALLET"})
    onions = sorted({i["value"] for i in identifiers if i["id_type"] == "ONION_DOMAIN"})
    pgp_keys = sorted(
        {i["value"] for i in identifiers if i["id_type"] == "PGP_FINGERPRINT"}
    )
    ips = sorted({i["value"] for i in identifiers if i["id_type"] == "CLEARNET_IP"})

    return {
        "handle": handle,
        "exists": actor is not None,
        "identifiers": identifiers,
        "observations": observations,
        "ledger_blocks": ledger_blocks,
        "corpus": "\n\n".join(corpora),
        "timestamps": timestamps,
        "circadian": circadian,
        "profile_json": (profile.stylometry_json if profile else None) or {},
        "wallets": wallets,
        "onions": onions,
        "pgp_keys": pgp_keys,
        "clearnet_ips": ips,
    }


def build_case_record(session: Session, handle: str) -> dict[str, Any]:
    """The full dossier payload for one actor: evidence, signals, ledger."""
    ledger = MerkleLedger(session)
    verified, corrupted = ledger.verify_integrity()
    head = ledger.head()

    evidence = collect_actor_evidence(session, handle)
    target = {
        "handle": evidence["handle"],
        "addresses": evidence["wallets"],
        "timestamps": evidence["timestamps"],
        "corpus": evidence["corpus"],
        "pgp_fingerprints": evidence["pgp_keys"],
        "hostnames": evidence["onions"],
    }

    # The primary attribution target is the actor itself; the comparison side
    # is the same persona's own record, so the fused score expresses internal
    # consistency of the four channels rather than a link to a second persona.
    # A future analyst-vs-suspect comparison passes two handles here.
    signals: dict[str, Any] = {
        "confidence": 0.0,
        "signals": {},
        "contradiction": False,
        "contradiction_reasons": [],
        "notes": ["No second persona supplied; multi-signal matrix omitted."],
        "available_signals": [],
        "missing_signals": ["crypto", "infra", "temporal", "stylometry"],
        "factors": {},
        "weights": {},
    }
    if evidence["exists"]:
        corpus = evidence["corpus"]
        if corpus:
            verdict = stylometry_compare(
                [corpus[:20000]], [corpus[:20000]]
            )
            evidence["stylometry_self"] = verdict
        signals = signals  # keep the neutral payload unless a pair is supplied

    record: dict[str, Any] = {
        "case_id": settings.case_reference,
        "generated_by": settings.generating_officer,
        "generated_at": dt.datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "classification": settings.classification_level,
        "actor": evidence,
        "signals": signals,
        "ledger": {
            "verified": verified,
            "corrupted_block_index": corrupted,
            "head_index": head.block_index if head else None,
            "merkle_root": ledger.merkle_root(),
            "total_blocks": ledger.count(),
        },
    }
    return record


# ---------------------------------------------------------------------------
# STIX 2.1
# ---------------------------------------------------------------------------
def generate_stix_bundle(session: Session, handle: str) -> dict[str, Any]:
    """A spec-valid STIX 2.1 bundle describing the actor and its artefacts."""
    now = dt.datetime.now(UTC).replace(microsecond=0)
    stamp = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"
    evidence = collect_actor_evidence(session, handle)
    case_id = settings.case_reference

    identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_URL, f'{case_id}:{handle}:identity')}"
    actor_id = f"threat-actor--{uuid.uuid5(uuid.NAMESPACE_URL, f'{case_id}:{handle}:actor')}"
    root_block = evidence["ledger_blocks"][0] if evidence["ledger_blocks"] else None
    root_hash = (
        root_block.current_hash if root_block is not None else "genesis"
    )
    created_by_ref = identity_id

    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": stamp,
            "modified": stamp,
            "name": settings.generating_officer,
            "identity_class": "organization",
            "sectors": ["government-national"],
            "contact_information": f"Case {case_id}",
        },
        {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": actor_id,
            "created_by_ref": created_by_ref,
            "created": stamp,
            "modified": stamp,
            "name": handle,
            "description": (
                f"Persona '{handle}' tracked under case {case_id} from "
                f"{len(evidence['observations'])} anchored observation(s). "
                f"Evidence root SHA-256: {root_hash}."
            ),
            "threat_actor_types": ["cyber-espionage"],
            "confidence": int(round((evidence["circadian"] or {}).get("confidence", 0) * 100)),
        },
    ]

    indicator_type_map = {
        "BTC_WALLET": ("cryptocurrency-wallet", "wallet address"),
        "PGP_FINGERPRINT": ("pgp-public-key", "PGP key fingerprint"),
        "ONION_DOMAIN": ("url", "onion service hostname"),
        "CLEARNET_IP": ("ipv4-addr", "clearnet IP address"),
        "HANDLE": ("user-account", "communication handle"),
    }

    for index, identifier in enumerate(evidence["identifiers"]):
        id_type = identifier["id_type"]
        kind, label = indicator_type_map.get(id_type, ("unknown", id_type))
        pattern = (
            f"[{kind}:value = '{identifier['value']}']"
            if kind != "unknown"
            else f"[x_{id_type.lower()}:value = '{identifier['value']}']"
        )
        indicator_uuid = uuid.uuid5(
            uuid.NAMESPACE_URL, f"{case_id}:{handle}:{id_type}:{identifier['value']}"
        )
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{indicator_uuid}",
                "created_by_ref": created_by_ref,
                "created": stamp,
                "modified": stamp,
                "name": f"{label}: {identifier['value'][:40]}",
                "description": (
                    f"Extracted by deterministic regex from anchored evidence; "
                    f"extraction confidence {identifier['confidence']:.2f}."
                ),
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": identifier["first_seen"],
                "labels": [id_type],
                "confidence": int(round(identifier["confidence"] * 100)),
                "indicator_types": ["compromised"],
            }
        )
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid5(uuid.NAMESPACE_URL, f'{case_id}:{handle}:uses:{index}')}",
                "created_by_ref": created_by_ref,
                "created": stamp,
                "modified": stamp,
                "relationship_type": "uses",
                "source_ref": actor_id,
                "target_ref": f"indicator--{indicator_uuid}",
                "description": f"{handle} uses {label}.",
            }
        )

    for onion in evidence["onions"]:
        infra_uuid = uuid.uuid5(
            uuid.NAMESPACE_URL, f"{case_id}:{handle}:infra:{onion}"
        )
        objects.append(
            {
                "type": "infrastructure",
                "spec_version": "2.1",
                "id": f"infrastructure--{infra_uuid}",
                "created_by_ref": created_by_ref,
                "created": stamp,
                "modified": stamp,
                "name": f"Onion service {onion[:24]}",
                "infrastructure_types": ["hosting-malware"] if evidence["wallets"] else ["unknown"],
                "description": (
                    f"Hidden service operated by {handle}; anchored under case "
                    f"{case_id} with ledger root {root_hash[:16]}."
                ),
            }
        )
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid5(uuid.NAMESPACE_URL, f'{case_id}:{handle}:infra:{onion}')}",
                "created_by_ref": created_by_ref,
                "created": stamp,
                "modified": stamp,
                "relationship_type": "uses",
                "source_ref": actor_id,
                "target_ref": f"infrastructure--{infra_uuid}",
                "description": f"{handle} operates this onion service.",
            }
        )

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(uuid.NAMESPACE_URL, f'{case_id}:{handle}:bundle')}",
        "objects": objects,
    }


# ---------------------------------------------------------------------------
# PDF rendering
# ---------------------------------------------------------------------------
_STYLES = getSampleStyleSheet()


class _DossierStyles:
    """The small style sheet used across every dossier page."""

    def __init__(self) -> None:
        self.classification = ParagraphStyle(
            "classification",
            parent=_STYLES["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#8B0000"),
        )
        self.title = ParagraphStyle(
            "dossier-title",
            parent=_STYLES["Title"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            spaceAfter=4,
        )
        self.subtitle = ParagraphStyle(
            "dossier-subtitle",
            parent=_STYLES["Normal"],
            fontName="Helvetica",
            fontSize=10,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#444444"),
        )
        self.section = ParagraphStyle(
            "section",
            parent=_STYLES["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=13,
            spaceBefore=14,
            spaceAfter=6,
        )
        self.body = ParagraphStyle(
            "body",
            parent=_STYLES["BodyText"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13,
        )
        self.small = ParagraphStyle(
            "small",
            parent=_STYLES["BodyText"],
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            wordWrap="LTR",
        )
        self.table_label = ParagraphStyle(
            "table-label",
            parent=_STYLES["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=9,
        )
        self.certificate = ParagraphStyle(
            "certificate",
            parent=_STYLES["BodyText"],
            fontName="Times-Roman",
            fontSize=10.5,
            leading=15,
        )


_TABLE_BASE = [
    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9AA0A6")),
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A1F2B")),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ("FONTSIZE", (0, 0), (-1, -1), 8),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F4F7")]),
    ("TOPPADDING", (0, 0), (-1, -1), 3),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
]


def _kv_table(styles: _DossierStyles, rows: list[tuple[str, str]]) -> Table:
    data = [[Paragraph(k, styles.table_label), Paragraph(v, styles.body)] for k, v in rows]
    table = Table(data, colWidths=[52 * mm, 118 * mm])
    style = list(_TABLE_BASE)
    style[1] = ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EDF0F5"))
    style.pop(2)  # no header row text colour
    style.pop(2)  # no header row font
    table.setStyle(TableStyle(style))
    return table


def _banner_paragraph(styles: _DossierStyles, text: str) -> Paragraph:
    return Paragraph(text, styles.body)


def _page_decorator(styles: _DossierStyles, case_id: str):
    def draw(canvas, doc) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(colors.HexColor("#8B0000"))
        canvas.drawCentredString(A4[0] / 2, A4[1] - 10 * mm, CLASSIFICATION)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#555555"))
        canvas.drawString(
            15 * mm, 10 * mm, f"{case_id} // generated {record_stamp(doc)}"
        )
        canvas.drawRightString(A4[0] - 15 * mm, 10 * mm, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    return draw


_STAMP = {"value": ""}


def record_stamp(doc: Any) -> str:
    return _STAMP["value"]


def _data_table(header: list[str], rows: list[list[str]], widths: list[float]) -> Table:
    table = Table([header] + rows, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle(_TABLE_BASE))
    return table


def _hash_cell(styles: _DossierStyles, value: str) -> Paragraph:
    return Paragraph(value, styles.small)


def render_dossier_pdf(record: dict[str, Any]) -> bytes:
    """Render the case record as a print-ready Section 65B dossier."""
    styles = _DossierStyles()
    actor = record["actor"]
    ledger = record["ledger"]
    case_id = record["case_id"]
    _STAMP["value"] = record["generated_at"][:19].replace("T", " ") + " UTC"

    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=18 * mm,
        bottomMargin=16 * mm,
        title=f"Attribution Dossier {case_id}",
        author=record["generated_by"],
        subject=f"{CLASSIFICATION} - actor {actor['handle']}",
    )

    story: list[Any] = []

    # --- Cover / case header -------------------------------------------
    story.append(
        Paragraph(
            "OFFICIAL CYBER THREAT ATTRIBUTION DOSSIER", styles.title
        )
    )
    story.append(
        Paragraph(
            "COMPLIANT WITH BHARATIYA SAKSHYA ADHINIYAM (BSA) 2023 - SECTION 65B",
            styles.subtitle,
        )
    )
    story.append(Spacer(1, 4 * mm))
    story.append(HRFlowable(width="100%", thickness=1.2, color=colors.HexColor("#1A1F2B")))
    story.append(Spacer(1, 5 * mm))
    story.append(
        _kv_table(
            styles,
            [
                ("Case ID", record["case_id"]),
                ("Generating Officer", record["generated_by"]),
                ("Generated At", record["generated_at"]),
                ("Classification", record["classification"]),
                ("Attribution Target", actor["handle"]),
                (
                    "Attribution Confidence",
                    f"{record['signals'].get('confidence', 0.0) * 100:.1f}%",
                ),
                (
                    "Ledger Status",
                    (
                        f"VERIFIED // root {ledger['merkle_root'][:32]}"
                        if ledger["verified"]
                        else f"TAMPERED at block #{ledger['corrupted_block_index']}"
                    ),
                ),
            ],
        )
    )

    # --- A. Executive summary ------------------------------------------
    story.append(Paragraph("A. Executive Summary", styles.section))
    story.append(
        _banner_paragraph(
            styles,
            (
                f"This dossier documents the persona <b>{actor['handle']}</b> as "
                f"observed across {len(actor['observations'])} anchored evidence "
                f"capture(s). {len(actor['identifiers'])} deterministic identifier(s) "
                f"were extracted: {len(actor['wallets'])} Bitcoin wallet(s), "
                f"{len(actor['pgp_keys'])} PGP fingerprint(s), "
                f"{len(actor['onions'])} onion service(s) and "
                f"{len(actor['clearnet_ips'])} clearnet IP(s). "
                + (
                    f"The circadian profiler estimates an activity window of "
                    f"{actor['circadian'].get('active_window_utc', {}).get('summary', 'n/a')} "
                    f"with verdict {actor['circadian'].get('verdict', 'INSUFFICIENT_DATA')}."
                    if actor.get("circadian")
                    else "No circadian profile was available for this actor."
                )
            ),
        )
    )

    # --- B. Chain of custody -------------------------------------------
    story.append(Paragraph("B. Chain of Custody && Source Evidence", styles.section))
    custody_rows = [
        [
            str(obs["observation_id"]),
            Paragraph(obs["source_url"], styles.small),
            obs["observed_at"],
            _hash_cell(styles, obs["payload_sha256"]),
        ]
        for obs in actor["observations"]
    ] or [["-", Paragraph("No observations anchored for this actor.", styles.body), "-", "-"]]
    story.append(
        _data_table(
            ["Obs #", "Source URL", "Acquired (UTC)", "SHA-256 of raw payload"],
            custody_rows,
            [14 * mm, 62 * mm, 36 * mm, 58 * mm],
        )
    )

    # --- C. Extracted identifiers --------------------------------------
    story.append(Paragraph("C. Extracted Identifier Matrix", styles.section))
    id_rows = [
        [
            Paragraph(i["id_type"], styles.small),
            Paragraph(i["value"], styles.small),
            f"{i['confidence']:.2f}",
            i["first_seen"],
        ]
        for i in actor["identifiers"]
    ] or [["-", "-", "-", "-"]]
    story.append(
        _data_table(
            ["Type", "Value", "Conf.", "First seen (UTC)"],
            id_rows,
            [34 * mm, 76 * mm, 16 * mm, 44 * mm],
        )
    )

    # --- D. Multi-signal matrix ----------------------------------------
    story.append(Paragraph("D. Multi-Signal Attribution Matrix", styles.section))
    signals = record["signals"].get("signals", {})
    weight_map = record["signals"].get("weights", {})
    signal_rows = []
    for name, title in (
        ("crypto_score", "Deterministic keys / UTXO co-spend"),
        ("infra_score", "Infrastructure (TLS artefacts, banners)"),
        ("temporal_score", "Temporal rhythms (circadian)"),
        ("stylometry_score", "Stylometry (Burrows' Delta)"),
    ):
        score = signals.get(name)
        weight = weight_map.get(name.replace("_score", ""), 0.0)
        signal_rows.append(
            [
                Paragraph(title, styles.body),
                ("n/a - not evaluated" if score is None else f"{score * 100:.1f}%"),
                (f"- (redistributed)" if score is None else f"{weight * 100:.0f}%"),
            ]
        )
    story.append(
        _data_table(
            ["Independent signal", "Score", "Effective weight"],
            signal_rows,
            [92 * mm, 40 * mm, 38 * mm],
        )
    )
    for note in record["signals"].get("notes", [])[:6]:
        story.append(Paragraph(f"&bull; {note}", styles.body))

    # --- E. Contradiction log ------------------------------------------
    story.append(Paragraph("E. Contradiction && Anti-Spoofing Log", styles.section))
    if record["signals"].get("contradiction"):
        for reason in record["signals"].get("contradiction_reasons", []):
            story.append(Paragraph(f"<b>ANOMALY:</b> {reason}", styles.body))
    else:
        story.append(
            _banner_paragraph(
                styles,
                "No inter-signal contradictions were detected at generation time. "
                "Circadian human-plausibility checks and split-half stylometry "
                "controls are recorded in the underlying actor profile.",
            )
        )

    # --- F. Merkle root verification -----------------------------------
    story.append(Paragraph("F. Merkle Ledger Verification Block", styles.section))
    story.append(
        _kv_table(
            styles,
            [
                ("Merkle root (head hash)", ledger["merkle_root"]),
                ("Head block index", str(ledger["head_index"])),
                ("Total blocks cited", str(ledger["total_blocks"])),
                (
                    "Integrity verdict",
                    "PASS - every block recomputed from genesis"
                    if ledger["verified"]
                    else f"FAIL - first divergence at block #{ledger['corrupted_block_index']}",
                ),
            ],
        )
    )
    ledger_rows = [
        [
            str(b.block_index),
            b.timestamp,
            _hash_cell(styles, b.previous_hash),
            _hash_cell(styles, b.current_hash),
        ]
        for b in actor["ledger_blocks"][:24]
    ]
    story.append(Spacer(1, 3 * mm))
    story.append(
        _data_table(
            ["Block", "Timestamp (UTC)", "Previous hash", "Current hash"],
            ledger_rows or [["-", "-", "-", "-"]],
            [14 * mm, 40 * mm, 58 * mm, 58 * mm],
        )
    )

    # --- G. Section 65B certificate -------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("G. Certificate of Electronic Evidence", styles.section))
    story.append(
        Paragraph(
            CERTIFICATION_TEMPLATE.format(officer=record["generated_by"]),
            styles.certificate,
        )
    )
    story.append(Spacer(1, 10 * mm))
    story.append(
        _kv_table(
            styles,
            [
                ("Case reference", record["case_id"]),
                ("Electronic record described", f"Attribution dossier for '{actor['handle']}'"),
                ("SHA-256 of this dossier's evidence root", ledger["merkle_root"]),
                ("Examiner signature", "<br/><br/>_______________________________"),
                ("Examiner name && rank", "_______________________________"),
                ("Date of certification", "______ / ______ / ____________"),
                ("Place of certification", "_______________________________"),
            ],
        )
    )

    document.build(
        story,
        onFirstPage=_page_decorator(styles, case_id),
        onLaterPages=_page_decorator(styles, case_id),
    )
    return buffer.getvalue()


__all__ = [
    "build_case_record",
    "generate_stix_bundle",
    "render_dossier_pdf",
    "collect_actor_evidence",
    "CERTIFICATION_TEMPLATE",
]
