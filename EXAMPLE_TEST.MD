# Example test commands for trojan-prober

This file contains copy-pasteable command sets for checking the repository, the binary, JSON output, negative behavior against a local Caddy HTTPS server, and manual Trojan-Go probing against `89.127.202.106:443`.

> Notes:
>
> - `127.0.0.1:8443` is used below as the local negative HTTPS/Caddy target.
> - `89.127.202.106:443` is used below as the Trojan-Go target requested for positive/manual checks.
> - FIN timing probes (`H1-Close`, `H1-Incomplete`) need libpcap and packet-capture privileges (`CAP_NET_RAW` or root). Without privileges, FIN-related evidence may be inconclusive.
> - Do not type placeholder brackets such as `<host>` in Bash. Use a real host or IP.

## 1. Build and repository checks

```bash
go version
```

```bash
go env GOPATH GOMOD CGO_ENABLED
```

```bash
go mod download
```

```bash
go test ./src/log
```

```bash
go test ./src/...
```

```bash
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags "full" -o trojan-prober ./src
```

```bash
./trojan-prober --help
```

## 2. Optional: grant packet-capture capability to the binary

Use one of these approaches if FIN timing probes must be reliable.

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./trojan-prober
```

```bash
getcap ./trojan-prober
```

Alternative: run selected commands with `sudo`.

## 3. Start a local Caddy HTTPS server for negative checks (`127.0.0.1:8443`)

Create a temporary Caddy site:

```bash
mkdir -p /tmp/trojan-prober-caddy-site
printf 'hello from caddy\n' > /tmp/trojan-prober-caddy-site/index.html
```

Create a temporary Caddyfile:

```bash
cat > /tmp/trojan-prober-Caddyfile <<'CADDY'
127.0.0.1:8443 {
    root * /tmp/trojan-prober-caddy-site
    file_server
    tls internal
}
CADDY
```

Run Caddy in the foreground in a separate terminal:

```bash
caddy run --config /tmp/trojan-prober-Caddyfile --adapter caddyfile
```

Or run it in the background for scripted checks:

```bash
caddy run --config /tmp/trojan-prober-Caddyfile --adapter caddyfile > /tmp/trojan-prober-caddy.log 2>&1 &
echo $! > /tmp/trojan-prober-caddy.pid
sleep 2
```

Verify that Caddy is reachable:

```bash
curl -k https://127.0.0.1:8443/
```

```bash
openssl s_client -connect 127.0.0.1:8443 -servername 127.0.0.1 -alpn http/1.1 </dev/null
```

## 4. Negative Caddy runs (`127.0.0.1:8443`)

Default text output:

```bash
./trojan-prober --targetServer 127.0.0.1 --targetPort 8443 --probe all
```

JSON output to stdout:

```bash
./trojan-prober --targetServer 127.0.0.1 --targetPort 8443 --probe all --format json
```

JSON output to a file:

```bash
./trojan-prober --targetServer 127.0.0.1 --targetPort 8443 --probe all --format json --output caddy-negative.json
```

Inspect the final status:

```bash
jq '{target, final_status, detected_type, detected_family, exit_code, technical_error, probe_count: (.probes | length)}' caddy-negative.json
```

Inspect every probe:

```bash
jq '.probes[] | {name, status, decisive, reason, duration_ms, error, request_bytes}' caddy-negative.json
```

Run with no early stop and no long H1 incomplete probe:

```bash
./trojan-prober --targetServer 127.0.0.1 --targetPort 8443 --probe all --stop-on-detected=false --include-h1-incomplete=false --format json --output caddy-full-4.json
```

Run with the long `H1-Incomplete` probe included:

```bash
time ./trojan-prober --targetServer 127.0.0.1 --targetPort 8443 --probe all --include-h1-incomplete=true --incomplete-timeout 605s --format json --output caddy-full-5.json
```

Check expected probe counts:

```bash
jq '.probes | length' caddy-full-4.json
```

```bash
jq '.probes | length' caddy-full-5.json
```

Run every default probe individually against Caddy:

```bash
for p in H1-Close Overbuffer-Incomplete Short-ALPN-h2 H1-ALPN-h2; do
  echo "### $p"
  ./trojan-prober --targetServer 127.0.0.1 --targetPort 8443 --probe "$p" --format json \
    | jq '{final_status, technical_error, probe: .probes[0]}'
done
```

Run `Overbuffer-Incomplete` with a short timeout for a faster smoke check:

```bash
time ./trojan-prober --targetServer 127.0.0.1 --targetPort 8443 --probe Overbuffer-Incomplete --overbuffer-timeout 5s --format json
```

Run with debug diagnostics:

```bash
./trojan-prober --targetServer 127.0.0.1 --targetPort 8443 --probe all --format json --log 0 --output caddy-debug.json
```

## 5. Trojan-Go manual runs (`89.127.202.106:443`)

Basic text output:

```bash
./trojan-prober --targetServer 89.127.202.106 --targetPort 443 --probe all
```

JSON output to stdout:

```bash
./trojan-prober --targetServer 89.127.202.106 --targetPort 443 --probe all --format json
```

JSON output to a file:

```bash
./trojan-prober --targetServer 89.127.202.106 --targetPort 443 --probe all --format json --output trojan-go.json
```

Inspect the top-level verdict:

```bash
jq '{target, final_status, detected_type, detected_family, exit_code, technical_error, probe_count: (.probes | length)}' trojan-go.json
```

Inspect probe summaries:

```bash
jq '.probes[] | {name, status, decisive, reason, duration_ms, error, request_bytes}' trojan-go.json
```

Run with early stop enabled:

```bash
./trojan-prober --targetServer 89.127.202.106 --targetPort 443 --probe all --stop-on-detected=true --format json --output trojan-go-early-stop.json
```

Run with early stop disabled:

```bash
./trojan-prober --targetServer 89.127.202.106 --targetPort 443 --probe all --stop-on-detected=false --format json --output trojan-go-full.json
```

Compare probe counts:

```bash
jq '{early_stop_probe_count: (.probes | length)}' trojan-go-early-stop.json
jq '{full_probe_count: (.probes | length)}' trojan-go-full.json
```

Run in `specific` prediction mode:

```bash
./trojan-prober --targetServer 89.127.202.106 --targetPort 443 --probe all --prediction-mode specific --format json --output trojan-go-specific.json
```

Run in `any-trojan` prediction mode:

```bash
./trojan-prober --targetServer 89.127.202.106 --targetPort 443 --probe all --prediction-mode any-trojan --format json --output trojan-go-any.json
```

Compare prediction modes:

```bash
jq '{mode: .prediction_mode, final_status, detected_type, detected_family, exit_code, technical_error}' trojan-go-specific.json trojan-go-any.json
```

Run with the long `H1-Incomplete` probe included:

```bash
time ./trojan-prober --targetServer 89.127.202.106 --targetPort 443 --probe all --include-h1-incomplete=true --format json --output trojan-go-with-incomplete.json
```

Run every default probe individually:

```bash
for p in H1-Close Overbuffer-Incomplete Short-ALPN-h2 H1-ALPN-h2; do
  echo "### $p"
  ./trojan-prober --targetServer 89.127.202.106 --targetPort 443 --probe "$p" --format json \
    | jq '{final_status, technical_error, probe: .probes[0]}'
done
```

Run only the overbuffer probe with the default timeout:

```bash
time ./trojan-prober --targetServer 89.127.202.106 --targetPort 443 --probe Overbuffer-Incomplete --overbuffer-timeout 20s --format json
```

Run ALPN-related probes only:

```bash
for p in H1-ALPN-h2 Short-ALPN-h2; do
  ./trojan-prober --targetServer 89.127.202.106 --targetPort 443 --probe "$p" --format json \
    | jq '.probes[0] | {name, status, reason, error, duration_ms}'
done
```

## 6. JSON and exit-code checks

Capture stdout JSON and shell exit code separately:

```bash
set +e
./trojan-prober --targetServer 89.127.202.106 --targetPort 443 --probe all --format json --output trojan-go-exit.json
code=$?
set -e
echo "exit_code=$code"
jq '{json_exit_code: .exit_code, final_status, technical_error}' trojan-go-exit.json
```

Check that stdout can be piped directly to `jq`:

```bash
./trojan-prober --targetServer 127.0.0.1 --targetPort 8443 --probe all --format json \
  | jq '{target, final_status, exit_code, technical_error}'
```

Verify that generated JSON is valid:

```bash
jq empty caddy-negative.json
jq empty trojan-go.json
```

## 7. Cleanup local Caddy

If Caddy was started with the background command above:

```bash
kill "$(cat /tmp/trojan-prober-caddy.pid)"
rm -f /tmp/trojan-prober-caddy.pid /tmp/trojan-prober-Caddyfile /tmp/trojan-prober-caddy.log
rm -rf /tmp/trojan-prober-caddy-site
```
