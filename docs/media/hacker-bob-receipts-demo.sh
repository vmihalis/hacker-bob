#!/usr/bin/env bash
set -euo pipefail

RED=$'\033[1;31m'
AMBER=$'\033[1;33m'
MUTED=$'\033[2;37m'
RESET=$'\033[0m'

receipt() {
  printf "${AMBER}%-22s${RESET} %s\n" "$1" "$2"
  sleep 0.35
}

printf "${AMBER}HACKER BOB / RECEIPT PORTFOLIO${RESET}\n"
printf "${RED}17 CVE IDs / 9 PROJECTS${RESET} ${MUTED}— public records + assigned IDs, not a live scan${RESET}\n\n"
sleep 0.6

receipt "stable-diffusion.cpp" "CVE-2026-47747  CVE-2026-47748  CVE-2026-47749  CVE-2026-47750"
receipt "netatalk" "CVE-2026-49387  CVE-2026-49388  CVE-2026-49389  CVE-2026-49390"
receipt "libcupsfilters" "CVE-2026-64611  CVE-2026-64612"
receipt "libtirpc" "CVE-2026-66714  CVE-2026-66715  [assigned / public record pending]"
receipt "OpenSSH" "CVE-2026-35388"
receipt "libheif" "CVE-2026-49271"
receipt "Samba" "CVE-2026-3012"
receipt "rpcbind" "CVE-2026-16277"
receipt "OpenEXR" "CVE-2026-65979  [assigned / public record pending]"

printf "\n${RED}17 CVE IDs${RESET} ${MUTED}/ nine open-source projects${RESET}\n"
