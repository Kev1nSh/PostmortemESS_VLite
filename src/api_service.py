from email import message_from_bytes

from src.msg_converter import convert_msg_to_eml
from src.parser import parse_email
from src.analyzer import analyze
from src.reporter import generate_report


def readable_attachments(attachments: list) -> list:
    # The parsed [attachments] has raw bytes in 'data', which is not JSON compatible/readable and is not sendable
    # If not removed, the API server will crash with a TypeError when trying to send the response.
    # This will only keep metadata
    return [
        {
            'filename':     a['filename'],
            'content_type': a['content_type'],
            'size':         a['size'],
        }
        for a in attachments
    ]



def build_reason(result: dict) -> dict:
    """Create Swedish explanations for analyzer findings and verdict."""

    flags = result.get("all_flags") or []
    details = []
    seen = set()

    # Match specific findings before more general patterns.
    rules = [
        # Email authentication
        (
            ("DKIM signature present but verification failed",),
            "E-postautentisering", "high",
            "DKIM-signaturen kunde inte verifieras",
            "Signaturens giltighet kunde inte bekräftas. Det kan bero på "
            "att innehållet har ändrats eller att verifieringen misslyckades."
        ),
        (
            ("Could not extract sender domain",),
            "E-postautentisering", "medium",
            "Avsändardomänen kunde inte identifieras",
            "Analysmotorn kunde inte identifiera avsändardomänen och kunde "
            "därför inte genomföra de vanliga autentiseringskontrollerna."
        ),
        (
            ("No SPF record",),
            "E-postautentisering", "medium",
            "SPF-post saknas",
            "Ingen SPF-post hittades för avsändardomänen."
        ),
        (
            ("No DMARC record",),
            "E-postautentisering", "medium",
            "DMARC-post saknas",
            "Ingen DMARC-post hittades för avsändardomänen."
        ),
        (
            ("No DKIM DNS record",),
            "E-postautentisering", "medium",
            "DKIM-DNS-post kunde inte hittas",
            "Ingen DKIM-post hittades bland de selectors som kontrollerades. "
            "Det bevisar inte att alla möjliga selectors saknar poster."
        ),
        (
            ('DMARC policy is "none"',),
            "E-postautentisering", "medium",
            "DMARC-policyn är endast övervakande",
            "Domänens DMARC-policy är p=none. Policyn begär inte i sig "
            "att mottagaren ska sätta meddelandet i karantän eller avvisa det."
        ),

        # Email headers
        (
            ("Reply-To domain",),
            "E-posthuvuden", "medium",
            "Avvikande Reply-To-domän",
            "Svaradressen använder en annan domän än From. Kontrollera "
            "vart ett svar faktiskt skulle skickas."
        ),
        (
            ("Return-Path domain",),
            "E-posthuvuden", "medium",
            "Avvikande Return-Path-domän",
            "Return-Path-domänen skiljer sig från From-domänen. "
            "Avvikelsen kan vara legitim men bör granskas."
        ),
        (
            ("Message-ID domain",),
            "E-posthuvuden", "medium",
            "Message-ID-domänen avviker",
            "Domänen i Message-ID skiljer sig från From-domänen. "
            "Det är en avvikelse, men bevisar inte i sig att mejlet är skadligt."
        ),
        (
            ("No Received headers",),
            "E-posthuvuden", "medium",
            "Received-headers saknas",
            "Meddelandet saknar Received-headers som analysmotorn kan använda. "
            "Det kan försvåra spårningen av meddelandets väg."
        ),
        (
            ("Suspicious X-Mailer",),
            "E-posthuvuden", "medium",
            "Misstänkt e-postprogram identifierades",
            "X-Mailer-headern innehåller ett programnamn som matchar "
            "analysmotorns lista över misstänkta utskickningsverktyg."
        ),

        # Sender address reputation
        (
            ("has high OpenLookup email risk",),
            "Avsändarrykte", "high",
            "Hög riskbedömning för avsändaradressen",
            "OpenLookup har klassificerat avsändaradressen med hög risk."
        ),
        (
            ("has medium OpenLookup email risk",),
            "Avsändarrykte", "medium",
            "Avsändaradressen behöver granskas",
            "OpenLookup rekommenderar ytterligare granskning av avsändaradressen."
        ),
        (
            ("disposable/throwaway address",),
            "Avsändarrykte", "medium",
            "Engångsadress identifierad",
            "OpenLookup har identifierat avsändaradressen som en möjlig "
            "engångs- eller tillfällig adress."
        ),

        # Sender IP reputation
        (
            ("listed on Spamhaus ZEN",),
            "IP-reputation", "high",
            "Avsändarens IP finns på Spamhaus ZEN",
            "IP-adressen gav en träff i Spamhaus ZEN."
        ),
        (
            ("found in ThreatFox",),
            "IP-reputation", "high",
            "IP-adressen finns i ThreatFox",
            "IP-adressen matchade en indikator i ThreatFox."
        ),
        (
            ("has AbuseIPDB confidence score",),
            "IP-reputation", "high",
            "Hög riskpoäng i AbuseIPDB",
            "AbuseIPDB:s riskpoäng nådde analysmotorns gräns för hög risk."
        ),
        (
            ("has elevated AbuseIPDB score",),
            "IP-reputation", "medium",
            "Förhöjd riskpoäng i AbuseIPDB",
            "AbuseIPDB rapporterade en förhöjd riskpoäng för IP-adressen."
        ),
        (
            ("Sender IP", "VirusTotal engines"),
            "IP-reputation", "high",
            "Avsändarens IP flaggades av VirusTotal",
            "En eller flera VirusTotal-motorer flaggade avsändarens IP-adress."
        ),

        # URL reputation — keep these before generic VirusTotal rules.
        (
            ("URL flagged by Google Safe Browsing",),
            "URL-kontroll", "high",
            "URL flaggad av Google Safe Browsing",
            "Google Safe Browsing matchade URL:en mot en registrerad hotkategori."
        ),
        (
            ("URL found in URLhaus",),
            "URL-kontroll", "high",
            "URL finns i URLhaus",
            "URL:en matchade en post i databasen URLhaus."
        ),
        (
            ("URL domain on Spamhaus DBL",),
            "URL-kontroll", "high",
            "URL-domänen finns på Spamhaus DBL",
            "Domänen matchade Spamhaus DBL:s domänblocklista."
        ),
        (
            ("URL domain found in ThreatFox",),
            "URL-kontroll", "high",
            "URL-domänen finns i ThreatFox",
            "URL-domänen matchade en indikator i ThreatFox."
        ),
        (
            ("URL marked suspicious by", "VirusTotal engines"),
            "URL-kontroll", "medium",
            "URL markerad som misstänkt av VirusTotal",
            "En eller flera VirusTotal-motorer bedömde URL:en som misstänkt."
        ),
        (
            ("URL flagged by", "VirusTotal engines"),
            "URL-kontroll", "high",
            "URL flaggad av VirusTotal",
            "En eller flera VirusTotal-motorer flaggade URL:en."
        ),

        # Attachment checks
        (
            ("found in MalwareBazaar",),
            "Bilagor", "high",
            "Bilagan finns i MalwareBazaar",
            "Bilagans hash matchade en post i MalwareBazaar."
        ),
        (
            ("found in ThreatFox",),
            "Bilagor", "high",
            "Bilagans hash finns i ThreatFox",
            "Bilagans hash matchade en indikator i ThreatFox."
        ),
        (
            ("Attachment", "VirusTotal engines"),
            "Bilagor", "high",
            "Bilagan flaggades av VirusTotal",
            "En eller flera VirusTotal-motorer flaggade bilagans hash."
        ),
        (
            ("Dangerous attachment extension",),
            "Bilagor", "medium",
            "Potentiellt riskabel filändelse",
            "Bilagan har en filändelse som analysmotorn betraktar som riskabel. "
            "Det betyder inte automatiskt att filen innehåller skadlig kod."
        ),
        (
            ("MIME mismatch",),
            "Bilagor", "medium",
            "Filtyp och MIME-typ skiljer sig åt",
            "Filens identifierade innehållstyp stämmer inte överens med "
            "den deklarerade MIME-typen."
        ),
    ]

    for flag in flags:
        if not isinstance(flag, str) or flag in seen:
            continue
        seen.add(flag)

        matched = None

        for patterns, category, severity, title, description in rules:
            if all(pattern.lower() in flag.lower() for pattern in patterns):
                matched = (category, severity, title, description)
                break

        if matched:
            category, severity, title, description = matched
        else:
            category = "Övrigt analysfynd"
            severity = "info"
            title = "Ytterligare analysfynd"
            description = (
                "Analysmotorn registrerade ett fynd som ännu inte har en "
                "specifik svensk förklaring."
            )

        details.append({
            "category": category,
            "severity": severity,
            "title": title,
            "description": description,
            "technical_detail": flag,
        })

    # Presentation priority only; this is not a calibrated risk score.
    priority = {"high": 0, "medium": 1, "info": 2}
    details.sort(key=lambda item: priority[item["severity"]])

    verdict = result.get("verdict", "FURTHER ANALYSIS REQUIRED")

    if verdict == "MOST LIKELY UNSAFE":
        verdict_explanation = (
            "Analysmotorn hittade minst en indikator som uppfyller "
            "dess regler för sannolikt osäkra meddelanden."
        )
    elif verdict == "MOST LIKELY SAFE":
        verdict_explanation = (
            "Analysmotorn klassificerade meddelandet som sannolikt säkert "
            "utifrån sina regler. Detta garanterar inte att meddelandet är säkert."
        )
    else:
        verdict_explanation = (
            "Analysmotorn hittade osäkerheter eller saknade tillräckligt "
            "underlag för att klassificera meddelandet som sannolikt säkert."
        )

    if details:
        reason_summary = " ".join(
            item["description"] for item in details[:2]
        )
    else:
        reason_summary = (
            "Inga varningsflaggor registrerades. Det garanterar inte att "
            "meddelandet är säkert eller att alla externa kontroller kunde köras."
        )

    return {
        "reason_summary": reason_summary,
        "reason_details": details,
        "verdict_explanation": verdict_explanation,
    }


def analyze_email_bytes(raw_bytes: bytes, filename: str = "") -> dict:

    # This runs the whole analysis pipeline on the raw email bytes and returns a JSON dict.
    # This is for the API server to use, so it can return a JSON response to the client.
    # The [filename] is used to determine if the email is a .msg file.

    analysis_bytes = raw_bytes

    if not raw_bytes:
        raise ValueError("Email input must not be empty")

    # Convert MSG to EML intern
    if filename.lower().endswith(".msg"):
        analysis_bytes = convert_msg_to_eml(raw_bytes)
    else:
        analysis_bytes = raw_bytes

    # Parse the EML bytes into an email message objects
    message     = message_from_bytes(analysis_bytes)
    parsed      = parse_email(message) 

    # Run the analysis on the parsed email and generate a report
    result      = analyze(parsed, raw_bytes=analysis_bytes)
    report_text = generate_report(parsed, result)
    reasoning = build_reason(result)

    # Returns the email analysis result as a JSON dict
    return {
        'headers': parsed['headers'],
        'urls': parsed['urls'],
        'attachments': readable_attachments(parsed['attachments']),
        'verdict': result['verdict'],
        'domain': result['domain'],
        'sender_ip': result['sender_ip'],
        'header_findings': result['header_findings'],
        'auth_findings': result['auth_findings'],
        'rep_findings': result['rep_findings'],
        'url_findings': result['url_findings'],
        'att_findings': result['att_findings'],
        'all_flags': result['all_flags'],
        'report_id': result['report_id'],
        'report_text': report_text,
        'reason_summary': reasoning['reason_summary'],
        'reason_details': reasoning['reason_details'],
        'verdict_explanation': reasoning['verdict_explanation'],
    }