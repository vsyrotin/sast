FROM alpine:3.21.3

RUN apk add --no-cache git curl python3 py3-pip openssh-client-default
RUN python3 -m pip install --no-cache-dir --upgrade pip==25.0.1 --break-system-packages && \
    pip install --no-cache-dir \
    requests==2.32.3 \
    checkov==3.2.372 \
    semgrep==1.108.0 \
    --break-system-packages

RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz | tar -xz -C /usr/local/bin gitleaks
RUN chmod +x /usr/local/bin/gitleaks
RUN curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin
RUN chmod +x /usr/local/bin/grype

COPY sast.py /

ENTRYPOINT ["/bin/sh"]
