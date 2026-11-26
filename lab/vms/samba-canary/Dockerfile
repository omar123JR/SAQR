# SAQR Ultra-Light Samba Canary Share (<64MB RAM)
# Proves NON-VACUOUS "0 lateral spread" during graduation defense:
#   - Hosts a writable SMB2 share `finance` seeded with 50 canary documents.
#   - Generates a read-only SHA-256 manifest at /srv/canary/manifest.sha256.
#   - After ransomware containment, verify 50/50 files untouched:
#       docker exec saqr-samba-canary sha256sum -c /srv/canary/manifest.sha256

FROM alpine:3.20

RUN apk add --no-cache samba \
    && mkdir -p /srv/canary/finance /var/log/samba /run/samba

COPY smb.conf /etc/samba/smb.conf

# Seed 50 deterministic department canary documents + immutable SHA-256 manifest
RUN sh -c ' \
    set -eu; \
    i=1; \
    while [ "$i" -le 50 ]; do \
        num=$(printf "%03d" "$i"); \
        file="/srv/canary/finance/department_budget_${num}.txt"; \
        printf "SAQR_CANARY_DOCUMENT_ID=%s\nDEPARTMENT=Finance\nORG=Saraya_Hamra_Lab\nSTATUS=CONFIDENTIAL_BASELINE\n" "$num" > "$file"; \
        i=$((i + 1)); \
    done; \
    sha256sum /srv/canary/finance/*.txt > /srv/canary/manifest.sha256; \
    chmod 0444 /srv/canary/manifest.sha256; \
    chown -R nobody:nobody /srv/canary/finance; \
    chmod 0777 /srv/canary/finance \
'

EXPOSE 445/tcp

CMD ["smbd", "--foreground", "--no-process-group", "--log-stdout"]
