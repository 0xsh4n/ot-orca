"""OT-ORCA command-line interface.

Examples
--------
List capture interfaces::

    otorca interfaces

Passively scan eth0 for 60 seconds and write an HTML report::

    otorca scan -i eth0 -d 60 -o report.html

Analyze an existing capture, add AI narrative via local Ollama (qwen2.5)::

    otorca scan -r plant.pcap --ai --ai-model qwen2.5 -o report.html

Launch the GUI::

    otorca gui
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from .version import __version__
from .config import AppConfig
from .core.capture import CaptureConfig, list_interfaces, tshark_version, find_tshark
from .core.session import ScanSession
from .ai.base import AIConfig


def _c(txt: str, code: str) -> str:
    return f"\033[{code}m{txt}\033[0m" if sys.stdout.isatty() else txt


def cmd_interfaces(_args) -> int:
    print(_c(f"OT-ORCA {__version__}  ·  {tshark_version()}", "1;36"))
    ifaces = list_interfaces()
    if not ifaces:
        print("No interfaces (or insufficient privileges to enumerate).")
        return 1
    print("\nCapture interfaces:")
    for name, desc in ifaces:
        print(f"  {_c(name,'1;32'):<28} {desc}")
    return 0


def _progress(summary: dict) -> None:
    sys.stdout.write(
        f"\r  packets={summary['packets']:<8} assets={summary['assets']:<5} "
        f"flows={summary['flows']:<5} events={summary['events']:<5} "
        f"t={summary['duration_s']}s   ")
    sys.stdout.flush()


def cmd_scan(args) -> int:
    cfg = AppConfig()
    cfg.capture = CaptureConfig(
        interface=args.interface, pcap=args.read, bpf=args.filter,
        display_filter=args.display_filter, duration=args.duration,
        packet_limit=args.count, promiscuous=not args.no_promisc,
        monitor_mode=args.monitor)
    if not args.interface and not args.read:
        print(_c("error: specify -i <iface> or -r <pcap>", "1;31"))
        return 2

    try:
        find_tshark()
    except Exception as exc:
        print(_c(str(exc), "1;31"))
        return 3

    src = args.read or f"interface {args.interface}"
    print(_c(f"🐋 OT-ORCA {__version__} — passive scan of {src}", "1;36"))
    if args.read:
        print(f"  reading capture file …")
    else:
        lim = []
        if args.duration:
            lim.append(f"{args.duration}s")
        if args.count:
            lim.append(f"{args.count} pkts")
        print(f"  listening{' ('+', '.join(lim)+')' if lim else ' (Ctrl-C to stop)'} …")

    session = ScanSession(cfg.capture, progress_cb=_progress)
    try:
        session.start_async()
        while session.running:
            time.sleep(0.3)
    except KeyboardInterrupt:
        print("\n  stopping …")
        session.stop()
    session.join(timeout=5)
    print()
    if session.error:
        print(_c(f"capture error: {session.error}", "1;31"))
        if session.inv.packet_count == 0:
            return 4

    # AI analyst
    ai_narrative, ai_source = "", ""
    result = session.build_result()
    if args.ai:
        from .ai.analyst import Analyst
        ai_cfg = AIConfig(provider=args.ai_provider, model=args.ai_model,
                          base_url=args.ai_url or "", api_key=args.ai_key or "")
        analyst = Analyst(ai_cfg)
        print(f"  AI analyst ({analyst.status()}) via {ai_cfg.provider}:{ai_cfg.model} …")
        ai_narrative, ai_source = analyst.analyze(result)
    else:
        from .ai.analyst import deterministic_narrative
        ai_narrative = deterministic_narrative(result)
        ai_source = "deterministic (no AI requested)"

    # Optional active nmap enrichment
    if args.active_nmap:
        from .integrations import nmap_scan
        targets = nmap_scan.targets_from_inventory(session.inv)
        print(_c(f"  [ACTIVE] nmap {args.nmap_profile} scan of {len(targets)} "
                 f"hosts (you consented) …", "1;33"))
        try:
            res = nmap_scan.run(targets, consent=True, profile=args.nmap_profile)
            nmap_scan.enrich_inventory(session.inv, res)
            result = session.build_result()  # rebuild with enrichment
        except Exception as exc:
            print(_c(f"  nmap skipped: {exc}", "1;33"))

    _write_outputs(args, result, session, ai_narrative, ai_source)
    _print_summary(result)
    return 0


def _write_outputs(args, result, session, ai_narrative, ai_source) -> None:
    from . import report as report_mod
    out = args.output
    base, ext = os.path.splitext(out) if out else ("otorca-report", ".html")
    outdir = os.path.dirname(out) if out else "."
    if outdir and not os.path.isdir(outdir):
        os.makedirs(outdir, exist_ok=True)

    if not out or ext.lower() in (".html", ".htm"):
        path = out or "otorca-report.html"
        report_mod.write_report(result, path, inv=session.inv,
                                ai_narrative=ai_narrative, ai_source=ai_source,
                                render_images=not args.no_images)
        print(_c(f"  → HTML report: {path}", "1;32"))
    if args.json:
        report_mod.write_json(result, args.json)
        print(_c(f"  → JSON: {args.json}", "1;32"))
    if args.markdown:
        report_mod.write_markdown(result, args.markdown, ai_narrative)
        print(_c(f"  → Markdown: {args.markdown}", "1;32"))
    if args.dot:
        from .viz import topology
        if topology.export_dot(session.inv, args.dot):
            print(_c(f"  → Topology DOT: {args.dot}", "1;32"))


def _print_summary(result) -> None:
    d = result.to_dict()
    sev = d["stats"].get("severity_matrix", {})
    print("\n" + _c("── Findings ──────────────────────────────────────", "1;36"))
    color = {"Critical": "1;41", "High": "1;31", "Medium": "1;33",
             "Low": "1;32", "Info": "1;34"}
    for f in d["findings"]:
        tag = _c(f" {f['severity']:^8} ", color.get(f["severity"], "0"))
        print(f"{tag} {f['rule_id']:<22} {f['title']} "
              f"{_c('x'+str(f.get('count',1)),'2;37')}")
    print(_c("──────────────────────────────────────────────────", "1;36"))
    print(f"  Critical={sev.get('Critical',0)} High={sev.get('High',0)} "
          f"Medium={sev.get('Medium',0)} Low={sev.get('Low',0)} "
          f"Info={sev.get('Info',0)}  "
          f"(assets={d['summary'].get('assets')}, flows={d['summary'].get('flows')})")


def cmd_gui(_args) -> int:
    try:
        from .gui.app import launch
    except Exception as exc:
        print(_c(f"GUI unavailable: {exc}", "1;31"))
        print("Tk may be missing. On Debian/Kali: sudo apt install python3-tk")
        return 1
    launch()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="otorca",
        description="OT-ORCA — passive OT/ICS network security scanner & toolkit.")
    p.add_argument("--version", action="version",
                   version=f"OT-ORCA {__version__}")
    sub = p.add_subparsers(dest="command")

    sub.add_parser("interfaces", help="list capture interfaces")
    sub.add_parser("gui", help="launch the graphical interface")

    s = sub.add_parser("scan", help="run a passive scan and generate a report")
    src = s.add_argument_group("source")
    src.add_argument("-i", "--interface", help="interface to listen on (e.g. eth0)")
    src.add_argument("-r", "--read", help="read an existing pcap/pcapng file")
    cap = s.add_argument_group("capture")
    cap.add_argument("-d", "--duration", type=int, default=0,
                     help="stop after N seconds (0 = until Ctrl-C)")
    cap.add_argument("-c", "--count", type=int, default=0,
                     help="stop after N packets")
    cap.add_argument("-f", "--filter", help="BPF capture filter (still passive)")
    cap.add_argument("-Y", "--display-filter", help="tshark display filter")
    cap.add_argument("--no-promisc", action="store_true",
                     help="do not request promiscuous mode")
    cap.add_argument("--monitor", action="store_true",
                     help="802.11 monitor mode (wireless)")
    out = s.add_argument_group("output")
    out.add_argument("-o", "--output", help="HTML report path (default report.html)")
    out.add_argument("--json", help="also write JSON result to this path")
    out.add_argument("--markdown", help="also write Markdown report")
    out.add_argument("--dot", help="also write Graphviz DOT topology")
    out.add_argument("--no-images", action="store_true",
                     help="skip chart/topology rendering (faster, text-only)")
    ai = s.add_argument_group("ai analyst (optional)")
    ai.add_argument("--ai", action="store_true", help="enable the AI analyst")
    ai.add_argument("--ai-provider", default="ollama",
                    choices=["ollama", "openai", "none"])
    ai.add_argument("--ai-model", default="qwen2.5",
                    help="model name (e.g. qwen2.5, qwen2.5:7b, gpt-4o-mini)")
    ai.add_argument("--ai-url", help="override backend base URL")
    ai.add_argument("--ai-key", help="API key for openai-compatible endpoints")
    act = s.add_argument_group("active (opt-in, not passive)")
    act.add_argument("--active-nmap", action="store_true",
                     help="ACTIVELY nmap discovered hosts (requires authorization)")
    act.add_argument("--nmap-profile", default="gentle",
                     choices=["gentle", "discovery", "standard"])
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    return {
        "interfaces": cmd_interfaces,
        "scan": cmd_scan,
        "gui": cmd_gui,
    }[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
