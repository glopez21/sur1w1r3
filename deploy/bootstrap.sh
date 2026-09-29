#!/usr/bin/env bash
# One-command remote entry point: fetch a pinned project ref, then onboard.
set -euo pipefail

REPOSITORY="${SURICATA_SHIPPER_REPOSITORY:-https://github.com/glopez21/suricata-shipper}"
REF="${SURICATA_SHIPPER_REF:-main}"
REF_KIND="${SURICATA_SHIPPER_REF_KIND:-heads}"
MODE="check"

for arg in "$@"; do
    case "$arg" in
        --check) MODE="check" ;;
        --install) MODE="install" ;;
        --help|-h) MODE="help" ;;
        *) printf '[bootstrap] ERROR: unknown argument: %s\n' "$arg" >&2; exit 2 ;;
    esac
done

if [[ "$MODE" == help ]]; then
    printf 'Usage: bootstrap.sh [--check | --install | --help]\n'
    exit 0
fi
if [[ "$MODE" == install && $EUID -ne 0 ]]; then
    printf '[bootstrap] ERROR: --install must run as root (use sudo)\n' >&2
    exit 1
fi

[[ "$REPOSITORY" == https://* ]] || {
    printf '[bootstrap] ERROR: project repository URL must use HTTPS\n' >&2
    exit 2
}
command -v curl >/dev/null 2>&1 || { printf '[bootstrap] ERROR: curl is required\n' >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { printf '[bootstrap] ERROR: tar is required\n' >&2; exit 1; }
[[ "$REF_KIND" == heads || "$REF_KIND" == tags ]] || {
    printf '[bootstrap] ERROR: SURICATA_SHIPPER_REF_KIND must be heads or tags\n' >&2
    exit 2
}

TMP_DIR="$(mktemp -d -t suricata-shipper.XXXXXX)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

ARCHIVE_URL="${REPOSITORY%/}/archive/refs/${REF_KIND}/${REF}.tar.gz"
printf '[bootstrap] Fetching project ref: %s\n' "$REF"
curl --fail --location --silent --show-error "$ARCHIVE_URL" \
    | tar -xz --strip-components=1 -C "$TMP_DIR"

[[ -x "$TMP_DIR/deploy/onboard.sh" ]] || {
    printf '[bootstrap] ERROR: downloaded archive does not contain deploy/onboard.sh\n' >&2
    exit 1
}

"$TMP_DIR/deploy/onboard.sh" "$@"
