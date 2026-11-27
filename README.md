# 🛡️ MailGuard

**An AI agent that checks suspicious email inside a disposable sandbox, running on Vultr.**

Email is the most common way attacks get in: phishing links, fake invoices, and
attachments that steal keys or wipe disks. MailGuard treats every email as hostile.
An LLM agent on **Vultr Serverless Inference** investigates it, but every risky step
(parsing the email, running its attachments) happens in a throwaway Docker container
with no network. Nothing is quarantined until a person clicks **Approve**.

## How it works

```
 .eml upload ──► Web app (FastAPI, Vultr VM)
                   │
                   ├─► Sandbox #1: parse email (no network)        analyzer.py
                   │      SPF/DKIM/DMARC, fake brand senders, lookalike
                   │      domains, link text ≠ real target, disguised
                   │      attachments (invoice.pdf.exe), EICAR, macros…
                   │
                   ├─► Agent loop (LLM on Vultr Serverless Inference) agent.py
                   │      reads the pre-scan, then calls tools:
                   │        detonate_attachment ─► Sandbox #2 (fresh per file) sandbox.py + tracer.py
                   │        check_url           ─► static URL checks (never fetched)
                   │      returns verdict + plain-language explanation
                   │
                   ├─► Guardrail: rule/sandbox evidence sets a floor; if the model
                   │   is talked into "clean" (prompt injection), stricter verdict wins
                   │
                   └─► Human approves or releases ──► data/quarantine + data/audit.jsonl
```

**Sandbox limits for every container:** `--network none`, read-only root filesystem,
user `nobody`, all capabilities dropped, `no-new-privileges`, 128 MB RAM, 0.5 CPU,
64 processes, 10 s timeout, fresh container each time (`--rm`). Decoy secrets are
planted in the environment so key theft shows up in the trace.

**Behaviour tracing:** Python attachments run under audit hooks (file opens, sockets,
subprocesses, `exec` of decoded code, secret env reads); shell scripts run under `sh -x`.

## Demo samples

`python3 mailguard/make_samples.py` writes four harmless emails to `mailguard/samples/`:

| Sample | What it shows | Verdict |
|---|---|---|
| `clean.eml` | Normal internal email | clean |
| `phishing.eml` | "PayPal" from `paypa1-support.xyz`, SPF/DMARC fail, link shows paypal.com but goes elsewhere | malicious |
| `eicar.eml` | `invoice.pdf.exe` with the EICAR antivirus **test** file | malicious |
| `hostile_script.eml` | Lookalike sender + a script that tries to steal keys, phone home, add a cron backdoor, `rm -rf`, run hidden code and loop forever. **The sandbox stops all of it.** | malicious |

The hostile script refuses to do anything unless it sees `MAILGUARD_SANDBOX=1`, so it is
safe even if someone runs it by accident. `eicar.eml` is generated rather than committed
so antivirus on your laptop doesn't quarantine the repo.

## Run it on a Vultr VM

1. Create an **Ubuntu 24.04** cloud compute instance (1 vCPU / 2 GB is enough).
2. In the Vultr console, open **Serverless Inference**, create a subscription and copy the API key.
3. SSH in and run:

```bash
curl -fsSL https://raw.githubusercontent.com/SpeckoJedno/Hackathon-Vultr/main/mailguard/deploy/setup_vm.sh -o setup_vm.sh
```

```bash
sudo bash setup_vm.sh https://github.com/SpeckoJedno/Hackathon-Vultr.git
```

4. Add the key (and optionally a model) and restart:

```bash
sudo nano /etc/mailguard.env
```

```bash
sudo systemctl restart mailguard
```

5. Open `http://<VM-IP>` and click a sample.

To list the models your key can use (leave `MODEL` empty to auto-pick one):

```bash
curl -s https://api.vultrinference.com/v1/models -H "Authorization: Bearer $VULTR_INFERENCE_API_KEY"
```

Without a key, MailGuard still works: a rule-based fallback agent runs the same sandboxed tools.

## Run locally (needs Docker)

```bash
cd mailguard && pip install -r requirements.txt && python3 make_samples.py
```

```bash
python3 sandbox.py
```

```bash
uvicorn app:app --port 8000
```

`python3 sandbox.py` is a containment self-test: it should print `NETWORK: blocked`,
`ROOTFS: blocked`, `UID: 65534` and `timed_out: true`.

## Configuration

| Variable | Default | |
|---|---|---|
| `VULTR_INFERENCE_API_KEY` | (empty → rule-based agent) | Serverless Inference key |
| `MODEL` | (auto-pick from `/v1/models`) | Chat model id |
| `VULTR_INFERENCE_BASE_URL` | `https://api.vultrinference.com/v1` | OpenAI-compatible endpoint |
| `SANDBOX_IMAGE` | `python:3.12-alpine` | Container image for sandboxes |
| `SANDBOX_TIMEOUT` | `10` | Seconds before an attachment is killed |

## Files

| File | Role |
|---|---|
| `mailguard/app.py` | Web app + API, human approval, audit log |
| `mailguard/agent.py` | Agent loop, tools, prompt-injection guardrail, offline fallback |
| `mailguard/sandbox.py` | Docker sandbox runner |
| `mailguard/tracer.py` | Runs inside the container, records what a script tries to do |
| `mailguard/analyzer.py` | Static email analysis (stdlib only) |
| `mailguard/static/index.html` | UI (renders email text with `textContent` only, never HTML) |

## Limits (honest list)

- Only `.py` and `.sh` attachments are executed; other files get static analysis.
- Links are checked statically, not opened. Next step: open them in a sandboxed headless
  browser and let a vision model judge whether the page is a fake login.
- Scans are kept in memory (the audit log and quarantine are on disk).
- Docker containers share the host kernel. For production, use gVisor (`--runtime runsc`)
  or a microVM per detonation.
