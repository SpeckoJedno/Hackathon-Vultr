"""Writes demo/attachment.eml: an "invoice" whose attachment is the EICAR
antivirus TEST file (harmless, but every scanner treats it as malware).
Generated instead of committed so antivirus on laptops leaves the repo alone.
Run:  python3 demo/make_attachment_eml.py
"""
import base64
import pathlib

eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
b64 = base64.encodebytes(eicar.encode()).decode()
eml = f"""From: "Accounts Payable" <billing@nordic-supplies-invoice.test>
To: finance@contoso.com
Subject: Overdue invoice INV-4471 - payment required today
Date: Fri, 27 Nov 2026 06:12:40 +0000
Message-ID: <inv4471@nordic-supplies-invoice.test>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="mix"

--mix
Content-Type: text/plain; charset=utf-8

Hello,

Invoice INV-4471 is 30 days overdue. Open the attached invoice and pay today
to avoid a late fee of 15%.

Accounts Payable

--mix
Content-Type: application/octet-stream; name="Invoice_INV-4471.pdf.exe"
Content-Disposition: attachment; filename="Invoice_INV-4471.pdf.exe"
Content-Transfer-Encoding: base64

{b64}
--mix--
"""
out = pathlib.Path(__file__).with_name("attachment.eml")
out.write_text(eml)
print(f"wrote {out}")
