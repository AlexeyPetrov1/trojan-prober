# trojan-prober

Trojan-Prober is an active HTTPS/TLS probing tool for fingerprinting Trojan tunnel implementations and distinguishing them from ordinary HTTPS servers. It sends crafted TLS/HTTP probes, aggregates the probe results into Trojan and HTTPS-server candidate matrices, and prints either a human-readable report or a machine-readable JSON report.

The primary workflow is `--probe all`, which runs the default probe profile and then derives a final verdict from the collected evidence.

## What this repository contains

- `src/` — Go source for the CLI, probe runner, parsers, aggregation logic, report generation, and tests.
- `src/probe_json/` — probe request definitions used by the runner.
- `src/log/` — logging helpers used by text output and diagnostics.
- `picture/` — images used by the project documentation/paper materials.
- `Makefile` — convenience build targets.
- `EXAMPLE_TEST.MD` — copy-pasteable command sets for local smoke, JSON, Caddy-negative, and Trojan-Go-positive/manual checks.

## Requirements

- Linux is recommended for full functionality.
- Go toolchain compatible with this module.
- CGO enabled for builds that include packet capture support.
- `libpcap` runtime and development headers for building/testing code that imports `github.com/google/gopacket/pcap`.
- `CAP_NET_RAW` or root privileges for FIN timing capture used by `H1-Close` and `H1-Incomplete`.
- Optional but useful CLI tools: `jq`, `timeout`, `curl`, `openssl`, and `caddy` for local negative testing.

`H1-Close` and `H1-Incomplete` use libpcap for FIN timing. If the binary is run without packet-capture privileges, those probes may become inconclusive or emit diagnostic messages such as `pcap open: any: You don't have permission...`.

## Build

```bash
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags "full" -o trojan-prober ./src
```

Alternative local build:

```bash
go build -o trojan-prober ./src
```

## Usage

Required flags:

```text
--targetServer <host-or-ip>
--targetPort <port>
--probe all|<probe-name>
```

Important shell note: values such as `<host>` and `<port>` in documentation are placeholders. Do not type the angle brackets in Bash. For example, use `--targetServer 127.0.0.1`, not `--targetServer <host>`.

### Main scenario: `--probe all`

Two independent switches define four common runs:

| prediction-mode | include-h1-incomplete | Probes run |
|-----------------|----------------------|------------|
| specific | false | H1-Close, Overbuffer-Incomplete, Short-ALPN-h2, H1-ALPN-h2 |
| specific | true | above + H1-Incomplete |
| any-trojan | false | same 4 probes |
| any-trojan | true | same 5 probes |

Examples:

```bash
./trojan-prober --targetServer 127.0.0.1 --targetPort 8443 --probe all
./trojan-prober --targetServer 127.0.0.1 --targetPort 8443 --probe all --prediction-mode specific --include-h1-incomplete=false
./trojan-prober --targetServer 89.127.202.106 --targetPort 443 --probe all --prediction-mode any-trojan --include-h1-incomplete=true
./trojan-prober --targetServer 89.127.202.106 --targetPort 443 --probe all --format json --output result.json
```

### Prediction modes

- **specific** — `DETECTED` only when a concrete Trojan type has decisive evidence, such as `Trojan-Go` or `Trojan-GFW`.
- **any-trojan** — `DETECTED` when there is decisive evidence for the Trojan family; `detected_type` may be empty if multiple concrete types conflict.

`POSSIBLE` candidate states are not the same as `DETECTED` verdicts.

### JSON output

`--format json` prints a JSON report. Use `--output <file>` when you want to save the report and inspect it later:

```bash
./trojan-prober --targetServer 89.127.202.106 --targetPort 443 --probe all --format json --output run.json
jq '.probes[] | {name, status, decisive, reason, duration_ms, error, request_bytes}' run.json
```

`--format json` always includes all 5 Trojan candidates and 6 HTTPS server candidates:

```text
Trojan-GFW, Trojan-Go, Trojan-R, Trojan-RS, Caddy-Trojan
Nginx, Apache, Caddy, Tomcat, Lighttpd, IIS
```

### Other flags

```text
--prediction-mode specific|any-trojan   (default: specific)
--include-h1-incomplete true|false      (default: false)
--stop-on-detected true|false           (default: false — full profile in all)
--probe-timeout 30s
--fin-timeout 45s
--overbuffer-timeout 20s
--incomplete-timeout 605s
--overbuffer-repeat-num 0               (0 = use JSON value)
--retries 1
--delay-between-probes 5s
--format text|json
--output result.json
--log 0|1                               (0 = debug/all logs, 1 = crucial logs only)
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | `NOT_DETECTED` |
| 10 | `DETECTED` |
| 20 | `INCONCLUSIVE` |
| 30 | Technical error / no reliable profile |

### Single probe

```bash
./trojan-prober --targetServer 89.127.202.106 --targetPort 443 --probe Overbuffer-Incomplete --format json
```

## Testing

Unit/integration tests:

```bash
go test ./src/...
```

If this fails with `fatal error: pcap.h: No such file or directory`, install the libpcap development package for your OS, for example `libpcap-dev` on Debian/Ubuntu.

For full manual verification commands, including a local Caddy negative target on `127.0.0.1:8443` and a Trojan-Go target on `89.127.202.106:443`, see [`EXAMPLE_TEST.MD`](EXAMPLE_TEST.MD).

## Cite

```bibtex
@article{lv2025trojanprobe,
  title={TrojanProbe: Fingerprinting Trojan tunnel implementations by actively probing crafted HTTP requests},
  author={Lv, Liuying and Zhou, Peng},
  journal={Computers \& Security},
  volume={148},
  pages={104147},
  year={2025},
  publisher={Elsevier}
}
```
