#!/usr/bin/env bash
# =============================================================================
# LIVE end-to-end security tests for the remediation set (S6, I1, I19/S14).
# Drives the REAL running stack: real login cookie, real ws-ticket, real
# WebSocket handshake + hijack attempt, real cross-tenant read, real :8015 auth,
# and the settings->DB tunnel activation gate.
#
# Skips cleanly (exit 0) when the stack is down, so it is safe in the aggregate
# suite. Creates and DELETES its own throwaway users.
#
#   bash tests/test_e2e_security_live.sh
# =============================================================================
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! curl -sf http://localhost:8090/health >/dev/null 2>&1 || ! curl -sf http://localhost:3000/api/health >/dev/null 2>&1; then
  echo "[skip] stack not up (agent :8090 / webapp :3000 unreachable) — skipping live E2E"
  exit 0
fi

FAIL=0

echo "#### S6 (WS ticket auth + hijack) + I1 (cross-tenant read) — inside agent container ####"
if ! docker compose exec -T agent python - < tests/e2e_s6_i1.py; then
  FAIL=1
fi

echo
echo "#### I19/S14 (:8015 bearer auth, boot force-down, settings activation gate) ####"
TOKEN=$(docker compose exec -T webapp printenv TUNNEL_AUTH_TOKEN | tr -d '\r\n')
IKEY=$(docker compose exec -T webapp printenv INTERNAL_API_KEY | tr -d '\r\n')
pass=0; total=0
chk(){ total=$((total+1)); if [ "$1" = "$2" ]; then echo "PASS  $3  ($1)"; pass=$((pass+1)); else echo "FAIL  $3  (got '$1' want '$2')"; FAIL=1; fi; }

c=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8015/tunnel/configure -H 'Content-Type: application/json' -H "Authorization: Bearer WRONGTOKEN" -d '{}'); chk "$c" 401 ":8015 wrong token -> 401"
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8015/tunnel/configure -H 'Content-Type: application/json' -d '{}'); chk "$c" 401 ":8015 no token -> 401"
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8015/tunnel/configure -H 'Content-Type: application/json' -H "Authorization: Bearer $TOKEN" -d '{}'); chk "$c" 200 ":8015 correct token -> 200"
c=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8015/health); chk "$c" 200 ":8015 /health open -> 200"
c=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8015/tunnel/status); chk "$c" 401 ":8015 /tunnel/status no token -> 401"

body=$(curl -s -X POST http://localhost:3000/api/global/tunnel-config/sync)
if echo "$body" | grep -q '"configured":false'; then chk 1 1 "boot sync forces tunnels down"; else chk 0 1 "boot sync forces down [$body]"; fi

EMAIL="e2e_i19_$(openssl rand -hex 4)@redamon.local"
curl -s -X POST http://localhost:3000/api/users -H 'Content-Type: application/json' -H "x-internal-key: $IKEY" \
  -d "{\"name\":\"i19\",\"email\":\"$EMAIL\",\"password\":\"Test1234!\",\"role\":\"standard\"}" >/dev/null
JAR=$(mktemp)
LOGIN=$(curl -s -c "$JAR" -X POST http://localhost:3000/api/auth/login -H 'Content-Type: application/json' -d "{\"email\":\"$EMAIL\",\"password\":\"Test1234!\"}")
USERID=$(echo "$LOGIN" | python3 -c "import sys,json;print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
curl -s -b "$JAR" -X PUT "http://localhost:3000/api/users/$USERID/settings" -H 'Content-Type: application/json' -d '{"tunnelsEnabled":true}' >/dev/null
en=$(docker compose exec -T postgres psql -U redamon -d redamon -tA -c "SELECT tunnels_enabled FROM user_settings WHERE user_id='$USERID';" 2>/dev/null | tr -d '[:space:]')
chk "$en" "t" "settings enable -> DB tunnels_enabled=true"
curl -s -b "$JAR" -X PUT "http://localhost:3000/api/users/$USERID/settings" -H 'Content-Type: application/json' -d '{"tunnelsEnabled":false}' >/dev/null
dis=$(docker compose exec -T postgres psql -U redamon -d redamon -tA -c "SELECT tunnels_enabled FROM user_settings WHERE user_id='$USERID';" 2>/dev/null | tr -d '[:space:]')
chk "$dis" "f" "settings disable -> DB tunnels_enabled=false"
curl -s -X DELETE "http://localhost:3000/api/users/$USERID" -H "x-internal-key: $IKEY" >/dev/null
rm -f "$JAR"

echo
echo "I19 live: $pass/$total"
echo
if [ "$FAIL" -eq 0 ]; then echo ">> LIVE E2E ALL GREEN"; else echo ">> LIVE E2E FAILURES ABOVE"; fi
exit $FAIL
