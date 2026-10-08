#!/bin/sh
# Authenticode-sign a Windows binary with jsign, which reads keys from the cloud HSMs code-signing
# certificates must live in (Azure Trusted Signing, DigiCert KeyLocker, SSL.com eSigner, cloud KMS).
# Configure with JSIGN_STORETYPE, JSIGN_KEYSTORE, JSIGN_STOREPASS and JSIGN_ALIAS (see jsign's
# docs for your provider). Anything that is not a .exe, or no signing configured: nothing to do.
set -eu
bin="$1"
case "$bin" in
  *.exe) ;;
  *) exit 0 ;;
esac
if [ -z "${JSIGN_STORETYPE:-}" ]; then
  echo "sign-windows: signing not configured, leaving $bin unsigned"
  exit 0
fi
jsign --storetype "$JSIGN_STORETYPE" --keystore "${JSIGN_KEYSTORE:-}" --storepass "${JSIGN_STOREPASS:-}" \
  --alias "${JSIGN_ALIAS:-}" --tsaurl "${JSIGN_TSAURL:-http://timestamp.digicert.com}" \
  --name "Straiker Ascend tunnel agent" --url "https://github.com/straiker-ai/ascend-tunnel" \
  "$bin"
echo "sign-windows: signed $bin"
