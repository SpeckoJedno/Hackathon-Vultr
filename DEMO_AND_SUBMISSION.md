# Demo script (~2 minutes)

1. **Problem (15 s).** "Most attacks start with an email. AI agents can help check them,
   but an agent that opens hostile attachments needs a cage. MailGuard is that cage."
2. **Clean email (15 s).** Click *clean* → green, delivered. No false alarm.
3. **Phishing (25 s).** Click *phishing*. Point at: SPF/DMARC fail, "PayPal" from
   `paypa1-support.xyz`, link that *shows* paypal.com but goes to `paypa1-login.xyz`.
4. **Containment moment (45 s).** Click *hostile script*. Show the agent's tool call
   `detonate_attachment`, then *What it tried to do* vs *What the sandbox stopped*:
   key theft → file missing / permission denied; exfiltration → no network;
   backdoor and `rm -rf` → read-only file system; infinite loop → killed at 10 s.
5. **Human in the loop (15 s).** Click *Approve quarantine*. Show it in History.
6. **Architecture (15 s).** Vultr VM runs the app + Docker; Vultr Serverless Inference
   runs the LLM; every risky step is a fresh, network-less container. Guardrail:
   if an email talks the model into "clean", sandbox evidence overrides it.

# Submission checklist

- [ ] Public URL `http://<VM-IP>` works from a phone
- [ ] `/api/health` shows `docker: true` and `llm_configured: true`
- [ ] Header shows "Agent: <model> on Vultr Serverless Inference" after a scan
- [ ] Repo link + 2-minute video
- [ ] Team / startup name added to README and page header
