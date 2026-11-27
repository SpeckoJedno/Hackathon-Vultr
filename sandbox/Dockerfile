# MailGuard sandbox image: Playwright + Chromium + static file inspection tools.
# One fresh container is started from this image for every link and every
# attachment, then destroyed. It never gets secrets, volumes or the Docker socket.
FROM mcr.microsoft.com/playwright/python:v1.49.1-noble

RUN pip install --no-cache-dir playwright==1.49.1 oletools==0.60.2 puremagic==1.28

COPY runner.py /opt/mailguard/runner.py

# pwuser ships with the Playwright image. Never run as root.
USER pwuser
ENV HOME=/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /tmp
ENTRYPOINT ["python3", "/opt/mailguard/runner.py"]
