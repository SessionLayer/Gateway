#!/bin/sh
# Test-node sshd entrypoint.
#  - Injects the session-CA public key (TRUSTED_USER_CA env) into TrustedUserCAKeys.
#  - Optionally installs a host certificate (HOST_CERT env) for host-identity
#    verification tests (Design §9.3); host keys are generated if absent.
set -eu

if [ -n "${TRUSTED_USER_CA:-}" ]; then
	printf '%s\n' "$TRUSTED_USER_CA" >/etc/ssh/trusted_user_ca.pub
	chmod 644 /etc/ssh/trusted_user_ca.pub
fi

# Generate any missing host keys (idempotent).
ssh-keygen -A >/dev/null 2>&1 || true

if [ -n "${HOST_CERT:-}" ]; then
	printf '%s\n' "$HOST_CERT" >/etc/ssh/ssh_host_ecdsa_key-cert.pub
	chmod 644 /etc/ssh/ssh_host_ecdsa_key-cert.pub
	echo "HostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub" >>/etc/ssh/sshd_config
fi

mkdir -p /run/sshd
# Validate config, then run foreground with stderr logging.
/usr/sbin/sshd -t -f /etc/ssh/sshd_config
exec /usr/sbin/sshd -D -e "$@"
