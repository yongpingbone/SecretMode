BEGIN;

CREATE TABLE pairing_invites (
    pairing_id text PRIMARY KEY,
    transcript_digest bytea NOT NULL,
    inviter_device_id text NOT NULL,
    inviter_key_fingerprint bytea NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    status text NOT NULL DEFAULT 'ISSUED',
    consumed_by_device_id text,
    consumed_by_key_fingerprint bytea,
    consumed_at timestamptz,
    CONSTRAINT pairing_id_is_128_bit_hex
        CHECK (pairing_id ~ '^[0-9a-f]{32}$'),
    CONSTRAINT transcript_digest_is_sha256_sized
        CHECK (octet_length(transcript_digest) = 32),
    CONSTRAINT inviter_key_fingerprint_is_sha256_sized
        CHECK (octet_length(inviter_key_fingerprint) = 32),
    CONSTRAINT invite_lifetime_is_positive
        CHECK (expires_at > issued_at),
    CONSTRAINT pairing_invite_status_is_known
        CHECK (status IN ('ISSUED', 'CONSUMED', 'CANCELLED')),
    CONSTRAINT consumed_fields_are_atomic
        CHECK (
            (status = 'CONSUMED'
                AND consumed_by_device_id IS NOT NULL
                AND consumed_by_key_fingerprint IS NOT NULL
                AND consumed_at IS NOT NULL
                AND octet_length(consumed_by_key_fingerprint) = 32)
            OR
            (status <> 'CONSUMED'
                AND consumed_by_device_id IS NULL
                AND consumed_by_key_fingerprint IS NULL
                AND consumed_at IS NULL)
        )
);

CREATE OR REPLACE FUNCTION consume_pairing_invite(
    p_pairing_id text,
    p_transcript_digest bytea,
    p_consumer_device_id text,
    p_consumer_key_fingerprint bytea
) RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
    invite pairing_invites%ROWTYPE;
    server_now timestamptz;
BEGIN
    IF p_pairing_id !~ '^[0-9a-f]{32}$' THEN
        RAISE EXCEPTION 'invalid pairing_id';
    END IF;
    IF octet_length(p_transcript_digest) <> 32 THEN
        RAISE EXCEPTION 'invalid transcript digest';
    END IF;
    IF length(p_consumer_device_id) = 0 THEN
        RAISE EXCEPTION 'consumer device id must not be empty';
    END IF;
    IF octet_length(p_consumer_key_fingerprint) <> 32 THEN
        RAISE EXCEPTION 'invalid consumer key fingerprint';
    END IF;

    -- The lock is acquired before reading authoritative time or deciding whether
    -- the invite is consumable. A waiter therefore re-reads the committed row and
    -- fresh server time after any earlier consumer releases the row.
    SELECT *
      INTO invite
      FROM pairing_invites
     WHERE pairing_id = p_pairing_id
     FOR UPDATE;

    IF NOT FOUND THEN
        RETURN 0;
    END IF;

    server_now := clock_timestamp();

    IF invite.transcript_digest <> p_transcript_digest
       OR invite.status <> 'ISSUED'
       OR server_now < invite.issued_at
       OR server_now >= invite.expires_at THEN
        RETURN 0;
    END IF;

    UPDATE pairing_invites
       SET status = 'CONSUMED',
           consumed_by_device_id = p_consumer_device_id,
           consumed_by_key_fingerprint = p_consumer_key_fingerprint,
           consumed_at = server_now
     WHERE pairing_id = p_pairing_id;

    RETURN 1;
END;
$$;

COMMIT;
