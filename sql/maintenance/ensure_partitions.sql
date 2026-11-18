-- DBA/maintenance job; run monthly before the precreated horizon expires.
SET search_path TO wallet_diagnostics;
DO $block$
DECLARE
    month_start date := (date_trunc('month', CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date - INTERVAL '1 month')::date;
    partition_start date;
BEGIN
    FOR i IN 0..7 LOOP
        partition_start := (month_start + make_interval(months => i))::date;
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF mcs_diag_event FOR VALUES FROM (%L) TO (%L)',
            'mcs_diag_event_' || to_char(partition_start, 'YYYY_MM'),
            to_char(partition_start, 'YYYY-MM-DD') || ' 00:00:00+00',
            to_char((partition_start + interval '1 month')::date, 'YYYY-MM-DD') || ' 00:00:00+00'
        );
    END LOOP;
END
$block$;
