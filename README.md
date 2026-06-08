# trojan-prober

Trojan-Prober actively probes HTTPS/TLS servers and fingerprints Trojan tunnel implementations. The primary workflow is `--probe all` with configurable prediction mode and optional long-running `H1-Incomplete`.

## Build

```bash
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags "full" -o trojan-prober ./src
```

`H1-Close` and `H1-Incomplete` use libpcap for FIN timing (Linux, CAP_NET_RAW).

## Usage

Required flags:

```text
--targetServer <host>
--targetPort <port>
--probe all|<probe-name>
```

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
./trojan-prober --targetServer example.com --targetPort 443 --probe all
./trojan-prober --targetServer example.com --targetPort 443 --probe all --prediction-mode specific --include-h1-incomplete=false
./trojan-prober --targetServer example.com --targetPort 443 --probe all --prediction-mode any-trojan --include-h1-incomplete=true
./trojan-prober --targetServer example.com --targetPort 443 --probe all --format json --output result.json
```

### Prediction modes

- **specific** — `DETECTED` only when a concrete Trojan type has decisive evidence (e.g. `Trojan-Go`, `Trojan-GFW`).
- **any-trojan** — `DETECTED` when there is decisive evidence for the Trojan family; `detected_type` may be empty if multiple types conflict.

`POSSIBLE` / candidate states are never reported as `DETECTED`.

### JSON output

`--format json` always includes all 5 Trojan candidates and 6 HTTPS server candidates:

```text
Trojan-GFW, Trojan-Go, Trojan-R, Trojan-RS, Caddy-Trojan
Nginx, Apache, Caddy, Tomcat, Lighttpd, IIS
```

### Other flags

```text
--prediction-mode specific|any-trojan   (default: specific)
--include-h1-incomplete true|false     (default: false)
--stop-on-detected true|false          (default: false — full profile in all)
--probe-timeout 30s
--fin-timeout 45s
--overbuffer-timeout 20s
--incomplete-timeout 605s
--overbuffer-repeat-num 0              (0 = use JSON value)
--retries 1
--delay-between-probes 5s
--format text|json
--output result.json
--log 0|1
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | `NOT_DETECTED` |
| 10 | `DETECTED` |
| 20 | `INCONCLUSIVE` |
| 30 | Technical error (no reliable profile) |

### Single probe

```bash
./trojan-prober --targetServer example.com --targetPort 443 --probe Overbuffer-Incomplete --format json
```

## Tests

```bash
go test ./src/...
```

## Cite

```
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
