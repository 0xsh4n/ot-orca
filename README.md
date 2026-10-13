<div align="center">

# 🐋 OT-ORCA

**Operational Technology Observation, Reconnaissance & Compliance Analyzer**

*A strictly passive OT/ICS network security scanner, analyzer and reporting toolkit.*

Passive by design · Cross-platform GUI · 35 detections · AI-assisted reporting · Network topology mapping

</div>

---

## What it is

OT-ORCA is an advanced, **passive** network security toolkit for Operational
Technology / Industrial Control System environments. It listens to a live
interface (or an offline capture) via **tshark**, reconstructs the asset
inventory and protocol conversation map, runs a senior-pentester rules engine,
and produces **severity-rated findings with descriptions and concrete
mitigations** — delivered as an interactive HTML report, JSON, or Markdown, with
a Purdue-model network topology diagram.

> **Passive by default.** In its normal mode OT-ORCA transmits *nothing* onto the
> monitored network. It only reads frames. This is what makes it safe to run on
> fragile production control networks where an active scan could crash a PLC.
> The one active helper (nmap) is disabled unless you explicitly opt in.

### Why "passive" matters in OT
Active scanning (even a gentle nmap) has historically caused PLCs, RTUs and
field devices to fault, hang or drop control. OT-ORCA's whole architecture is
built around *watching* — an apex predator that never has to touch its prey.

---

## Highlights

| | |
|---|---|
| 🔎 **Deep OT dissection** | Modbus, DNP3, S7comm, EtherNet/IP+CIP, IEC‑104, BACnet, OPC UA, PROFINET, IEC 61850 GOOSE/SV/MMS, Omron FINS, HART‑IP, MQTT, EtherCAT |
| 🧠 **Senior-pentester rules engine** | 35 detections mapped to IEC 62443, NIST SP 800‑82r3, MITRE ATT&CK for ICS and CWE — each with **severity · description · mitigation** |
| 🗺️ **Network topology mapping** | Auto-generated Purdue‑model diagram (networkx + matplotlib); control/write command paths drawn in red; Graphviz DOT export |
| 📊 **numpy analytics** | Asset inventory with role & Purdue classification, protocol mix, top talkers/flows, polling‑periodicity anomaly scoring |
| 🤖 **AI analyst (optional)** | Executive summary + remediation roadmap via **Ollama** (e.g. `qwen2.5`), any **OpenAI‑compatible / Codex** endpoint, or **MCP** — with a deterministic fallback so reports never depend on an LLM |
| 🖥️ **Cross-platform GUI** | Pure Tkinter — ships with Python on Windows/macOS/Linux, no extra install. Pick an interface or IP, start/stop, live counters, colour-coded findings, topology viewer |
| 📄 **Professional reporting** | Self-contained HTML (charts embedded), JSON and Markdown |
| ⚙️ **Version-robust** | Field schema is validated against the local tshark build, so it degrades gracefully across Wireshark versions and platforms |

---

## Install

**Prerequisite:** Wireshark/tshark.

```bash
# Debian / Kali / Ubuntu
sudo apt install tshark python3-tk
# macOS
brew install wireshark
# then let non-root users capture (Linux):
sudo dpkg-reconfigure wireshark-common   # choose "Yes"
sudo usermod -aG wireshark "$USER"        # log out/in afterwards
```

```bash
git clone <your-repo-url> ot-orca && cd ot-orca
python3 -m pip install -r requirements.txt
# optional, only to (re)generate the demo capture:
python3 -m pip install scapy
```

No build step is required — run it straight from the source tree with
`python3 -m otorca`, or `pip install -e .` to get the `otorca` command.

---

## Quick start

```bash
# List capture interfaces
python3 -m otorca interfaces

# Passively scan eth0 for 60 seconds, write an HTML report
python3 -m otorca scan -i eth0 -d 60 -o plant-report.html

# Analyze an existing capture (no hardware needed)
python3 -m otorca scan -r plant.pcapng -o report.html --json result.json

# Add an AI executive narrative using a local Ollama model (data stays on-host)
python3 -m otorca scan -r plant.pcapng --ai --ai-model qwen2.5 -o report.html

# Launch the cross-platform GUI
python3 -m otorca gui
```

Try it immediately against the bundled demo capture:

```bash
python3 -m otorca scan -r sample/otdemo.pcap -o demo.html
# open demo.html in a browser
```

---

## The GUI

`python3 -m otorca gui` opens a friendly tabbed workspace:

- **Capture** — choose an **interface** from a dropdown (or type a BPF host
  filter / load a pcap), set duration/packet limits, **Start / Stop**, and watch
  live counters and a log.
- **Findings** — severity-coloured list; click any row for the full
  description, mitigation, evidence and references.
- **Assets** — the discovered OT inventory (role, Purdue level, vendor, product,
  protocols).
- **Topology** — the rendered network diagram, control flows in red.
- **Report & AI** — configure the optional AI analyst, opt into active nmap,
  and export HTML / JSON / Markdown.

---

## CLI reference (`scan`)

```
source:
  -i, --interface IFACE     interface to listen on (e.g. eth0)
  -r, --read FILE           read an existing pcap/pcapng instead
capture:
  -d, --duration N          stop after N seconds (0 = until Ctrl-C)
  -c, --count N             stop after N packets
  -f, --filter BPF          BPF capture filter (still passive)
  -Y, --display-filter EXPR tshark display filter
      --no-promisc          don't request promiscuous mode
      --monitor             802.11 monitor mode (wireless)
output:
  -o, --output FILE         HTML report path (default report.html)
      --json FILE           also write JSON
      --markdown FILE       also write Markdown
      --dot FILE            also write Graphviz DOT topology
      --no-images           skip chart/topology rendering (text-only)
ai analyst (optional):
      --ai                  enable the AI analyst
      --ai-provider {ollama,openai,none}
      --ai-model NAME       e.g. qwen2.5, qwen2.5:7b, gpt-4o-mini
      --ai-url URL          override backend base URL
      --ai-key KEY          API key for openai-compatible endpoints
active (opt-in, NOT passive):
      --active-nmap         ACTIVELY nmap discovered hosts (authorization required)
      --nmap-profile {gentle,discovery,standard}
```

---

## AI & MCP integration

The AI analyst turns a scan result into an executive summary, an attacker's-eye
view and a prioritized remediation roadmap. It is **optional** and **privacy-
conscious** — it sends finding *metadata and counts*, never raw secret values.

- **Ollama (recommended for OT):** everything stays on your host.
  ```bash
  ollama pull qwen2.5          # or qwen2.5:7b, llama3.1, mistral …
  python3 -m otorca scan -r plant.pcap --ai --ai-provider ollama --ai-model qwen2.5
  ```
- **OpenAI-compatible / Codex / LM Studio / vLLM / Groq:**
  ```bash
  python3 -m otorca scan -r plant.pcap --ai --ai-provider openai \
      --ai-url https://api.openai.com/v1 --ai-model gpt-4o-mini --ai-key $KEY
  ```
  > Sending OT-derived data to a remote endpoint moves information off-site —
  > opt in deliberately.
- **MCP:** `otorca/ai/mcp_client.py` is a minimal stdio JSON-RPC client
  (`initialize` / `tools/list` / `tools/call`) for handing a findings bundle to
  an MCP-exposed model or threat-intel tool in an agent runtime.

If no backend is reachable, OT-ORCA automatically falls back to a solid
**deterministic** narrative built from the findings themselves.

---

## Architecture

```
tshark  ──►  core/capture      flat, version-validated field rows (passive)
             core/inventory     asset identity · flows · protocol events
             protocols/dissect  table-driven OT/IT dissectors  (protocols/tables.py)
             analysis/rules     event + analytic rules  ──►  findings/catalog
             analysis/statistics  numpy aggregates & anomaly scoring
             viz/topology,charts  Purdue diagram + report charts
             ai/analyst          Ollama / OpenAI / MCP  (+ deterministic fallback)
             report              self-contained HTML · JSON · Markdown
             gui/app             Tkinter cross-platform workspace
```

Domain knowledge lives in just two declarative places — `protocols/tables.py`
(function-code maps and risk classes) and `findings/catalog.py` (the
severity/description/mitigation templates) — so extending coverage is mostly
data, not code. See [`docs/DETECTIONS.md`](docs/DETECTIONS.md) for the full
catalog.

---

## Safe & legal use

OT-ORCA is for **authorized** security assessment, monitoring and research of
networks you own or are contracted to test.

- Passive mode only reads traffic. Still, confirm you are permitted to monitor
  the segment (SPAN/mirror port or an inline tap).
- Captures can contain sensitive process data and credentials — the `.gitignore`
  deliberately excludes `*.pcap*`; treat reports as confidential.
- `--active-nmap` is the one feature that transmits; it refuses to run without
  explicit consent and uses a gentle profile, but **active scanning of OT
  devices can still cause faults.** You are responsible for authorization.

---

## Development

```bash
python3 -m pip install -r requirements.txt pytest scapy
python3 sample/make_sample_pcap.py sample/otdemo.pcap   # regenerate demo data
python3 -m pytest -q                                    # run the test suite
```

## License

MIT — see [LICENSE](LICENSE).
