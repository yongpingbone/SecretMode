#!/usr/bin/env bash
set -euo pipefail

DB_NAME="secretmode_pairing_ci"
SCHEMA="backend-spike/pairing_invites.sql"

psql_scalar() {
  sudo -u postgres psql -X -qAt -v ON_ERROR_STOP=1 -d "$DB_NAME" -c "$1"
}

assert_eq() {
  local expected="$1"
  local actual="$2"
  local label="$3"
  if [[ "$actual" != "$expected" ]]; then
    echo "ASSERTION FAILED: $label: expected=$expected actual=$actual" >&2
    exit 1
  fi
}

sudo systemctl start postgresql
sudo -u postgres dropdb --if-exists "$DB_NAME"
sudo -u postgres createdb "$DB_NAME"
sudo -u postgres psql -X -q -v ON_ERROR_STOP=1 -d "$DB_NAME" -f "$SCHEMA"

DIGEST_A="decode(repeat('aa', 32), 'hex')"
DIGEST_B="decode(repeat('bb', 32), 'hex')"
KEY_INVITER="decode(repeat('01', 32), 'hex')"
KEY_A="decode(repeat('02', 32), 'hex')"
KEY_B="decode(repeat('03', 32), 'hex')"

insert_valid_invite() {
  local pairing_id="$1"
  local digest_expr="$2"
  psql_scalar "INSERT INTO pairing_invites (pairing_id, transcript_digest, inviter_device_id, inviter_key_fingerprint, issued_at, expires_at) VALUES ('$pairing_id', $digest_expr, 'device-inviter', $KEY_INVITER, clock_timestamp() - interval '1 minute', clock_timestamp() + interval '10 minutes'); SELECT 1;" >/dev/null
}

consume() {
  local pairing_id="$1"
  local digest_expr="$2"
  local device_id="$3"
  local key_expr="$4"
  psql_scalar "SELECT consume_pairing_invite('$pairing_id', $digest_expr, '$device_id', $key_expr);"
}

# First consumer wins, serial replay loses.
PAIRING_SERIAL="11111111111111111111111111111111"
insert_valid_invite "$PAIRING_SERIAL" "$DIGEST_A"
assert_eq "1" "$(consume "$PAIRING_SERIAL" "$DIGEST_A" 'device-a' "$KEY_A")" "first consume must succeed"
assert_eq "0" "$(consume "$PAIRING_SERIAL" "$DIGEST_A" 'device-b' "$KEY_B")" "second consume must fail"
assert_eq "device-a" "$(psql_scalar "SELECT consumed_by_device_id FROM pairing_invites WHERE pairing_id='$PAIRING_SERIAL';")" "first consumer must remain authoritative"

# Wrong transcript must fail without burning the invite.
PAIRING_WRONG_DIGEST="22222222222222222222222222222222"
insert_valid_invite "$PAIRING_WRONG_DIGEST" "$DIGEST_A"
assert_eq "0" "$(consume "$PAIRING_WRONG_DIGEST" "$DIGEST_B" 'device-a' "$KEY_A")" "wrong digest must not consume"
assert_eq "ISSUED" "$(psql_scalar "SELECT status FROM pairing_invites WHERE pairing_id='$PAIRING_WRONG_DIGEST';")" "wrong digest must leave invite issued"
assert_eq "1" "$(consume "$PAIRING_WRONG_DIGEST" "$DIGEST_A" 'device-a' "$KEY_A")" "correct digest must still consume after wrong attempt"

# Expired invite cannot be revived by a client-supplied time because the function
# has no caller-controlled time argument. Server clock is authoritative.
PAIRING_EXPIRED="33333333333333333333333333333333"
psql_scalar "INSERT INTO pairing_invites (pairing_id, transcript_digest, inviter_device_id, inviter_key_fingerprint, issued_at, expires_at) VALUES ('$PAIRING_EXPIRED', $DIGEST_A, 'device-inviter', $KEY_INVITER, clock_timestamp() - interval '2 minutes', clock_timestamp()); SELECT 1;" >/dev/null
assert_eq "0" "$(consume "$PAIRING_EXPIRED" "$DIGEST_A" 'device-a' "$KEY_A")" "expired invite must not consume"
assert_eq "ISSUED" "$(psql_scalar "SELECT status FROM pairing_invites WHERE pairing_id='$PAIRING_EXPIRED';")" "expired attempt must not mutate row"

# Future/not-yet-valid invite is also blocked by server time.
PAIRING_FUTURE="44444444444444444444444444444444"
psql_scalar "INSERT INTO pairing_invites (pairing_id, transcript_digest, inviter_device_id, inviter_key_fingerprint, issued_at, expires_at) VALUES ('$PAIRING_FUTURE', $DIGEST_A, 'device-inviter', $KEY_INVITER, clock_timestamp() + interval '5 minutes', clock_timestamp() + interval '10 minutes'); SELECT 1;" >/dev/null
assert_eq "0" "$(consume "$PAIRING_FUTURE" "$DIGEST_A" 'device-a' "$KEY_A")" "future invite must not consume"

# Cancelled invite is terminal for consumption.
PAIRING_CANCELLED="55555555555555555555555555555555"
insert_valid_invite "$PAIRING_CANCELLED" "$DIGEST_A"
psql_scalar "UPDATE pairing_invites SET status='CANCELLED' WHERE pairing_id='$PAIRING_CANCELLED'; SELECT 1;" >/dev/null
assert_eq "0" "$(consume "$PAIRING_CANCELLED" "$DIGEST_A" 'device-a' "$KEY_A")" "cancelled invite must not consume"

# Real race: A obtains the row lock, signals the test, then sleeps before commit.
# B starts only after A has the lock. PostgreSQL must re-check the UPDATE predicate
# after A commits and B must observe that the invite is no longer ISSUED.
PAIRING_RACE="66666666666666666666666666666666"
insert_valid_invite "$PAIRING_RACE" "$DIGEST_A"
rm -f /tmp/secretmode-pairing-a-locked /tmp/secretmode-pairing-a.out /tmp/secretmode-pairing-b.out

sudo -u postgres psql -X -qAt -v ON_ERROR_STOP=1 -d "$DB_NAME" > /tmp/secretmode-pairing-a.out <<SQL &
BEGIN;
SELECT consume_pairing_invite('$PAIRING_RACE', $DIGEST_A, 'device-a', $KEY_A);
\! touch /tmp/secretmode-pairing-a-locked
SELECT pg_sleep(2);
COMMIT;
SQL
A_PID=$!

for _ in $(seq 1 100); do
  [[ -f /tmp/secretmode-pairing-a-locked ]] && break
  sleep 0.05
done
if [[ ! -f /tmp/secretmode-pairing-a-locked ]]; then
  echo "consumer A never acquired the invite row lock" >&2
  kill "$A_PID" 2>/dev/null || true
  exit 1
fi

sudo -u postgres psql -X -qAt -v ON_ERROR_STOP=1 -d "$DB_NAME" > /tmp/secretmode-pairing-b.out <<SQL &
SELECT consume_pairing_invite('$PAIRING_RACE', $DIGEST_A, 'device-b', $KEY_B);
SQL
B_PID=$!

wait "$A_PID"
wait "$B_PID"

A_RESULT="$(grep -E '^[01]$' /tmp/secretmode-pairing-a.out | head -n 1)"
B_RESULT="$(grep -E '^[01]$' /tmp/secretmode-pairing-b.out | head -n 1)"
assert_eq "1" "$A_RESULT" "lock holder A must consume"
assert_eq "0" "$B_RESULT" "blocked racer B must lose after predicate re-check"
assert_eq "CONSUMED|device-a" "$(psql_scalar "SELECT status || '|' || consumed_by_device_id FROM pairing_invites WHERE pairing_id='$PAIRING_RACE';")" "race must leave exactly one authoritative consumer"
assert_eq "1" "$(psql_scalar "SELECT count(*) FROM pairing_invites WHERE pairing_id='$PAIRING_RACE' AND status='CONSUMED';")" "race must produce exactly one consumed row"

# Lock-wait expiry: holder locks but does NOT consume. Waiting consumer starts while
# invite is valid, but the lock is released only after expiry. A fresh server clock
# re-check must reject the waiting consume after the rollback.
PAIRING_LOCK_EXPIRY="77777777777777777777777777777777"
psql_scalar "INSERT INTO pairing_invites (pairing_id, transcript_digest, inviter_device_id, inviter_key_fingerprint, issued_at, expires_at) VALUES ('$PAIRING_LOCK_EXPIRY', $DIGEST_A, 'device-inviter', $KEY_INVITER, clock_timestamp() - interval '1 minute', clock_timestamp() + interval '1 second'); SELECT 1;" >/dev/null
rm -f /tmp/secretmode-pairing-expiry-locked /tmp/secretmode-pairing-expiry-waiter.out

sudo -u postgres psql -X -qAt -v ON_ERROR_STOP=1 -d "$DB_NAME" >/tmp/secretmode-pairing-expiry-holder.out <<SQL &
BEGIN;
SELECT pairing_id FROM pairing_invites WHERE pairing_id='$PAIRING_LOCK_EXPIRY' FOR UPDATE;
\! touch /tmp/secretmode-pairing-expiry-locked
SELECT pg_sleep(2);
ROLLBACK;
SQL
HOLDER_PID=$!

for _ in $(seq 1 100); do
  [[ -f /tmp/secretmode-pairing-expiry-locked ]] && break
  sleep 0.05
done
if [[ ! -f /tmp/secretmode-pairing-expiry-locked ]]; then
  echo "expiry holder never acquired the invite row lock" >&2
  kill "$HOLDER_PID" 2>/dev/null || true
  exit 1
fi

sudo -u postgres psql -X -qAt -v ON_ERROR_STOP=1 -d "$DB_NAME" > /tmp/secretmode-pairing-expiry-waiter.out <<SQL &
SELECT consume_pairing_invite('$PAIRING_LOCK_EXPIRY', $DIGEST_A, 'device-b', $KEY_B);
SQL
WAITER_PID=$!

wait "$HOLDER_PID"
wait "$WAITER_PID"

EXPIRY_RESULT="$(grep -E '^[01]$' /tmp/secretmode-pairing-expiry-waiter.out | head -n 1)"
assert_eq "0" "$EXPIRY_RESULT" "consumer waiting past expiry must be rejected"
assert_eq "ISSUED" "$(psql_scalar "SELECT status FROM pairing_invites WHERE pairing_id='$PAIRING_LOCK_EXPIRY';")" "expired lock waiter must not mutate invite"

echo "pairing_invite_storage_result=ok"
