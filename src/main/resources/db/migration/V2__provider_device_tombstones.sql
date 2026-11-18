-- A tombstone prevents an old delayed REGISTER from re-activating a revoked key.
CREATE TABLE mcs_diag_device_tombstone (
    device_id varchar(36) NOT NULL,
    key_id varchar(64) NOT NULL,
    revoked_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor_id varchar(200) NOT NULL,
    CONSTRAINT mcs_diag_device_tombstone_pk PRIMARY KEY (device_id,key_id)
);
CREATE INDEX mcs_diag_device_tombstone_time_idx
    ON mcs_diag_device_tombstone (revoked_at);

-- Respect previously revoked V1 devices; never accidentally re-enable historical keys.
INSERT INTO mcs_diag_device_tombstone (device_id,key_id,revoked_at,actor_id)
SELECT device_id,key_id,COALESCE(revoked_at,CURRENT_TIMESTAMP),'FLYWAY_V2_BACKFILL'
FROM mcs_diag_device
WHERE active=false OR revoked_at IS NOT NULL
ON CONFLICT (device_id,key_id) DO NOTHING;
