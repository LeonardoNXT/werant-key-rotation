CREATE TABLE signing_keys (
    id UUID PRIMARY KEY,
    kid UUID NOT NULL UNIQUE,
    algorithm TEXT NOT NULL,
    status TEXT NOT NULL,
    version TEXT NOT NULL,

    public_jwk BYTEA NOT NULL,
    encrypted_private_key BYTEA NOT NULL,
    encrypted_dek BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    kms_key_id TEXT NOT NULL,

    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    activated_at TIMESTAMPTZ,
    deactivated_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,

    CONSTRAINT signing_keys_algorithm_check
        CHECK (algorithm = 'RS256'),
    CONSTRAINT signing_keys_status_check
        CHECK (status IN ('pending', 'active', 'deactivated', 'retired')),
    CONSTRAINT signing_keys_lifecycle_timestamps_check
        CHECK (
            (status = 'pending'
                AND activated_at IS NULL
                AND deactivated_at IS NULL
                AND retired_at IS NULL)
            OR
            (status = 'active'
                AND activated_at IS NOT NULL
                AND deactivated_at IS NULL
                AND retired_at IS NULL)
            OR
            (status = 'deactivated'
                AND activated_at IS NOT NULL
                AND deactivated_at IS NOT NULL
                AND retired_at IS NULL)
            OR
            (status = 'retired'
                AND activated_at IS NOT NULL
                AND deactivated_at IS NOT NULL
                AND retired_at IS NOT NULL)
        )
);

CREATE UNIQUE INDEX signing_keys_one_active_idx
    ON signing_keys (status)
    WHERE status = 'active';

CREATE UNIQUE INDEX signing_keys_one_deactivated_idx
    ON signing_keys (status)
    WHERE status = 'deactivated';

CREATE INDEX signing_keys_pending_order_idx
    ON signing_keys (created_at, id)
    WHERE status = 'pending';
