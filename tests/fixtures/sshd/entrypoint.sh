#!/bin/sh
set -eu

if [ -n "${TRUSTED_USER_CA:-}" ]; then
	printf '%s\n' "$TRUSTED_USER_CA" >/etc/ssh/trusted_user_ca.pub
	chmod 644 /etc/ssh/trusted_user_ca.pub
fi

ssh-keygen -A >/dev/null 2>&1 || true

if [ -n "${HOST_CERT:-}" ]; then
	printf '%s\n' "$HOST_CERT" >/etc/ssh/ssh_host_ecdsa_key-cert.pub
	chmod 644 /etc/ssh/ssh_host_ecdsa_key-cert.pub
	echo "HostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub" >>/etc/ssh/sshd_config
fi

mkdir -p /run/sshd
/usr/sbin/sshd -t -f /etc/ssh/sshd_config
exec /usr/sbin/sshd -D -e "$@"
