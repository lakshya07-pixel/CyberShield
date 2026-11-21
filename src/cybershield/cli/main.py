"""
Unified CLI Entry Point for CyberShield Network IDS & Threat Engine.
"""

import argparse
import json
import sys
from pathlib import Path

from src.cybershield.services.threat_pipeline import ThreatPipelineService


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cybershield",
        description="CyberShield: Network Intrusion Detection & Threat Engine CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: run-csv
    csv_parser = subparsers.add_parser("run-csv", help="Process a flow CSV file")
    csv_parser.add_argument("--csv", required=True, help="Path to input flow CSV")
    csv_parser.add_argument("--output", default=None, help="Path to save output JSON")
    csv_parser.add_argument("--nrows", type=int, default=None, help="Max rows to read")
    csv_parser.add_argument("--limit", type=int, default=10, help="Max rows to display in terminal")
    csv_parser.add_argument("--no-advisory", action="store_true", help="Exclude Threat Engine advisory")

    # Command: run-pcap
    pcap_parser = subparsers.add_parser("run-pcap", help="Extract and analyze a raw PCAP/PCAPNG file")
    pcap_parser.add_argument("--pcap", required=True, help="Path to input PCAP/PCAPNG file")
    pcap_parser.add_argument("--output", default=None, help="Path to save output JSON")
    pcap_parser.add_argument("--flow-csv", default=None, help="Path to save intermediate flow CSV")
    pcap_parser.add_argument("--limit", type=int, default=10, help="Max rows to display in terminal")
    pcap_parser.add_argument("--verbose", action="store_true", help="Verbose extraction logging")
    pcap_parser.add_argument("--no-advisory", action="store_true", help="Exclude Threat Engine advisory")

    # Command: run-url
    url_parser = subparsers.add_parser("run-url", help="Analyze a URL for phishing threats")
    url_parser.add_argument("--url", required=True, help="URL to analyze")
    url_parser.add_argument("--lite", action="store_true", help="Use lightweight Logistic Regression model")
    url_parser.add_argument("--no-advisory", action="store_true", help="Exclude Threat Engine advisory")
    url_parser.add_argument("--use-llama", action="store_true", default=False, help="Enable Llama on-device ExecuTorch advisory")
    url_parser.add_argument("--output", default=None, help="Path to save output JSON")

    # Command: run-sms
    sms_parser = subparsers.add_parser("run-sms", help="Analyze an SMS message for scam/fraud threats")
    sms_parser.add_argument("--text", required=True, help="SMS text content to analyze")
    sms_parser.add_argument("--no-advisory", action="store_true", help="Exclude Threat Engine advisory")
    sms_parser.add_argument("--use-llama", action="store_true", default=False, help="Enable Llama on-device ExecuTorch advisory")
    sms_parser.add_argument("--output", default=None, help="Path to save output JSON")

    # Command: summary
    summary_parser = subparsers.add_parser("summary", help="Summarize a threat results JSON file")
    summary_parser.add_argument("--json", required=True, dest="json_path", help="Path to threat results JSON")

    # Command: serve
    serve_parser = subparsers.add_parser("serve", help="Start the FastAPI REST gateway server")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port to bind")
    serve_parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")

    # Command: correlate
    corr_parser = subparsers.add_parser("correlate", help="Cross-channel threat correlation across event JSON files")
    corr_parser.add_argument("--inputs", nargs="+", required=True, help="Path(s) to detector result JSON file(s)")
    corr_parser.add_argument("--output", default=None, help="Path to save unified incident JSON")
    corr_parser.add_argument("--verify-integrity", action="store_true", help="Verify SHA-256 signature of incident records")
    corr_parser.add_argument("--format", choices=["judge", "compact", "json"], default="judge", help="Output display format (default: judge)")

    return parser


def handle_run_csv(args) -> int:
    service = ThreatPipelineService()
    try:
        results = service.run_csv_pipeline(
            csv_path=args.csv,
            output_json_path=args.output,
            nrows=args.nrows,
            include_advisory=not args.no_advisory
        )
    except Exception as e:
        sys.stderr.write(f"Error running CSV pipeline: {e}\n")
        return 1

    stats = getattr(service, "last_run_stats", {})
    if stats.get("discarded_rows", 0) > 0:
        disc = stats["discarded_rows"]
        tot = stats["total_input_rows"]
        inv = stats.get("invalid_rows", disc)
        dup = stats.get("duplicate_rows", 0)
        sys.stderr.write(
            f"Warning: Discarded {disc} of {tot} input rows "
            f"({inv} invalid/ragged/missing feature values, {dup} duplicate).\n"
        )

    print(f"Successfully processed {len(results)} flows.")
    print(f"\n--- First {min(len(results), args.limit)} Threat Results ---")
    for res in results[:args.limit]:
        tr = res["threat_result"]
        adv_str = f" | Advisory: {res['advisory']['severity']:<8}" if "advisory" in res else ""
        print(f"Flow #{res['flow_index']:<5} | Class: {tr['attack_class']:<12} | Severity: {tr['severity']:<6}{adv_str} | Confidence: {tr['confidence']:.4f}")

    if args.output:
        print(f"\nSaved all results to: {args.output}")

    return 0


def handle_run_pcap(args) -> int:
    service = ThreatPipelineService()
    try:
        results = service.run_pcap_pipeline(
            pcap_path=args.pcap,
            output_json_path=args.output,
            flow_csv_path=args.flow_csv,
            include_advisory=not args.no_advisory,
            verbose=args.verbose
        )
    except Exception as e:
        sys.stderr.write(f"Error running PCAP pipeline: {e}\n")
        return 1

    stats = getattr(service, "last_run_stats", {})
    if stats.get("discarded_rows", 0) > 0:
        disc = stats["discarded_rows"]
        tot = stats["total_input_rows"]
        inv = stats.get("invalid_rows", disc)
        dup = stats.get("duplicate_rows", 0)
        sys.stderr.write(
            f"Warning: Discarded {disc} of {tot} input rows "
            f"({inv} invalid/ragged/missing feature values, {dup} duplicate).\n"
        )

    print(f"Successfully processed {len(results)} flows.")
    print(f"\n--- First {min(len(results), args.limit)} Threat Results ---")
    for res in results[:args.limit]:
        tr = res["threat_result"]
        adv_str = f" | Advisory: {res['advisory']['severity']:<8}" if "advisory" in res else ""
        print(f"Flow #{res['flow_index']:<5} | Class: {tr['attack_class']:<12} | Severity: {tr['severity']:<6}{adv_str} | Confidence: {tr['confidence']:.4f}")

    if args.output:
        print(f"\nSaved all results to: {args.output}")

    return 0


def handle_summary(args) -> int:
    json_path = Path(args.json_path)
    if not json_path.exists():
        sys.stderr.write(f"JSON file not found: {json_path}\n")
        return 1

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    stats = ThreatPipelineService.compute_summary(data)
    print("\n=== THREAT ADVISORY SUMMARY REPORT ===")
    print(f"Total Flows Analyzed: {stats['total_flows']}")
    print(f"Benign Flows:         {stats['benign_flows']}")
    print(f"Intrusion Flows:      {stats['intrusion_flows']}")
    print("\nAdvisory Severity Distribution:")
    for sev, cnt in sorted(stats["advisory_severity_distribution"].items()):
        print(f"  {sev:<12}: {cnt}")
    print("\nAttack Class Distribution:")
    for cls, cnt in sorted(stats["attack_class_distribution"].items()):
        print(f"  {cls:<16}: {cnt}")

    return 0


def handle_run_url(args) -> int:
    try:
        from detectors.url import detect_url_threat, build_url_advisory
    except ImportError as e:
        sys.stderr.write(f"Error importing URL detector: {e}\n")
        return 1

    try:
        threat_result = detect_url_threat(url=args.url, use_lite=args.lite)
    except Exception as e:
        sys.stderr.write(f"Error analyzing URL: {e}\n")
        return 1

    advisory = None
    if not args.no_advisory:
        try:
            if getattr(args, "use_llama", False):
                from threat_engine.llama.adapter import generate_threat_advisory
                advisory = generate_threat_advisory(threat_result, use_llama=True)
            else:
                advisory = build_url_advisory(threat_result)
        except Exception as e:
            sys.stderr.write(f"Warning: Failed to generate advisory: {e}\n")

    print("\n=== URL THREAT ANALYSIS REPORT ===")
    print(f"Target URL:     {args.url}")
    print(f"Classification: {threat_result['threat_type'].upper()} ({threat_result['attack_class']})")
    print(f"Severity:       {threat_result['severity'].upper()}")
    print(f"Confidence:     {threat_result['confidence']:.4f}")
    if threat_result.get("indicators"):
        print(f"Indicators:     {', '.join(threat_result['indicators'])}")

    if advisory:
        print("\n--- Threat Engine Advisory ---")
        print(f"Advisory Severity: {advisory['severity'].upper()}")
        print(f"Explanation:       {advisory['threat_explanation']}")
        print(f"Recommendation:    {advisory['recommendation']}")

    payload = {
        "url": args.url,
        "threat_result": threat_result,
    }
    if advisory:
        payload["advisory"] = advisory

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"\nSaved analysis to: {args.output}")

    return 0


def handle_run_sms(args) -> int:
    try:
        from detectors.sms import detect_sms_threat, build_sms_advisory
    except ImportError as e:
        sys.stderr.write(f"Error importing SMS detector: {e}\n")
        return 1

    try:
        threat_result = detect_sms_threat(text=args.text)
    except Exception as e:
        sys.stderr.write(f"Error analyzing SMS: {e}\n")
        return 1

    advisory = None
    if not args.no_advisory:
        try:
            if getattr(args, "use_llama", False):
                from threat_engine.llama.adapter import generate_threat_advisory
                advisory = generate_threat_advisory(threat_result, use_llama=True)
            else:
                advisory = build_sms_advisory(threat_result)
        except Exception as e:
            sys.stderr.write(f"Warning: Failed to generate advisory: {e}\n")

    print("\n=== SMS THREAT ANALYSIS REPORT ===")
    preview = args.text if len(args.text) <= 60 else args.text[:57] + "..."
    print(f"SMS Content:    {preview}")
    print(f"Classification: {threat_result['threat_type'].upper()} ({threat_result['attack_class']})")
    print(f"Severity:       {threat_result['severity'].upper()}")
    print(f"Confidence:     {threat_result['confidence']:.4f}")
    if threat_result.get("indicators"):
        print(f"Indicators:     {', '.join(threat_result['indicators'])}")

    if advisory:
        print("\n--- Threat Engine Advisory ---")
        print(f"Advisory Severity: {advisory['severity'].upper()}")
        print(f"Explanation:       {advisory['threat_explanation']}")
        print(f"Recommendation:    {advisory['recommendation']}")

    payload = {
        "sms_text": args.text,
        "threat_result": threat_result,
    }
    if advisory:
        payload["advisory"] = advisory

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"\nSaved analysis to: {args.output}")

    return 0


def handle_serve(args) -> int:
    try:
        import uvicorn
        print(f"Starting CyberShield REST Gateway on http://{args.host}:{args.port} ...")
        uvicorn.run("src.cybershield.api.app:app", host=args.host, port=args.port, reload=args.reload)
        return 0
    except Exception as e:
        sys.stderr.write(f"Error launching server: {e}\n")
        return 1


def handle_correlate(args) -> int:
    from src.cybershield.correlation import CorrelationEngine, verify_incident_integrity

    events = []
    for inp in args.inputs:
        path = Path(inp)
        if not path.is_file():
            sys.stderr.write(f"Error: input file not found: {inp}\n")
            return 1
        with open(path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                if isinstance(data, list):
                    # Could be list of flow dicts from threat pipeline
                    for item in data:
                        if isinstance(item, dict) and "threat_result" in item:
                            tr = dict(item["threat_result"])
                            if "flow_index" in item:
                                tr["flow_index"] = item["flow_index"]
                            events.append(tr)
                        else:
                            events.append(item)
                elif isinstance(data, dict):
                    if "threat_result" in data:
                        events.append(data["threat_result"])
                    else:
                        events.append(data)
            except Exception as e:
                sys.stderr.write(f"Error parsing JSON from {inp}: {e}\n")
                return 1

    engine = CorrelationEngine()
    engine.ingest_events(events)
    incidents = engine.correlate()

    fmt = getattr(args, "format", "judge")

    if fmt == "json":
        print(json.dumps(incidents, indent=2))
    elif fmt == "compact":
        print(f"Ingested {len(events)} events across input files.")
        print(f"Correlated {len(incidents)} multi-channel incident(s).\n")
        for inc in incidents:
            print(f"=== Incident: {inc['incident_id']} ===")
            print(f"Status:     {inc['status']}")
            print(f"Severity:   {inc['severity']}")
            print(f"Confidence: {inc['confidence']}")
            print(f"Summary:    {inc['summary']}")
            print(f"Signature:  {inc['sha256_signature']}")
            if args.verify_integrity:
                valid = verify_incident_integrity(inc)
                print(f"Integrity:  {'VALID (PASS)' if valid else 'INVALID (FAIL)'}")
            print("Shared Indicators:")
            for sh in inc["shared_indicators"]:
                print(f"  - [{sh['indicator_type']}] {sh['indicator_value']} (Sources: {', '.join(sh['participating_sources'])})")
            print("Advisory Action Steps:")
            for step in inc["advisory"]["actionable_steps"]:
                print(f"  * {step}")
            print()
    else: # default: judge format
        from src.cybershield.correlation import format_judge_summary
        print(f"Ingested {len(events)} events across input files.")
        print(f"Correlated {len(incidents)} multi-channel incident(s).\n")
        for inc in incidents:
            verified_flag = verify_incident_integrity(inc) if args.verify_integrity else None
            summary_text = format_judge_summary(inc, verified_integrity=verified_flag)
            print(summary_text)
            print()

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(incidents, f, indent=2)
        print(f"Saved incident records to: {args.output}")

    return 0


def main(argv=None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "run-csv":
        return handle_run_csv(args)
    elif args.command == "run-pcap":
        return handle_run_pcap(args)
    elif args.command == "run-url":
        return handle_run_url(args)
    elif args.command == "run-sms":
        return handle_run_sms(args)
    elif args.command == "summary":
        return handle_summary(args)
    elif args.command == "serve":
        return handle_serve(args)
    elif args.command == "correlate":
        return handle_correlate(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
