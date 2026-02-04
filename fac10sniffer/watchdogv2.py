BRUTE_FORCE_TOTAL = 5
SCAN_NEUTRAL_TOTAL = 12
WINDOW_MINUTES = 10


def watchdog():
    conn = connectdb()
    cur = conn.cursor()

    cur.execute(f"""
        SELECT
            src_ip,
            SUM(failure_count) AS total_failures,
            COUNT(*) AS sessions,
            MIN(start_time),
            MAX(end_time)
        FROM auth_logs
        WHERE src_ip IS NOT NULL
        AND start_time > now() - interval '{WINDOW_MINUTES} minutes'
        GROUP BY src_ip
        HAVING SUM(failure_count) >= {BRUTE_FORCE_TOTAL}
    """)
    brute_rows = cur.fetchall()

    for r in brute_rows:
        print(
            f"[ALERT][BRUTE_FORCE] "
            f"src_ip={r[0]} "
            f"failures={r[1]} "
            f"sessions={r[2]} "
            f"window={r[3]}→{r[4]}"
        )

    cur.execute(f"""
        SELECT
            src_ip,
            SUM(neutral_count) AS total_neutral,
            COUNT(*) AS sessions
        FROM auth_logs
        WHERE src_ip IS NOT NULL
        AND start_time > now() - interval '{WINDOW_MINUTES} minutes'
        GROUP BY src_ip
        HAVING SUM(neutral_count) >= {SCAN_NEUTRAL_TOTAL}
        AND SUM(success_count) = 0
    """)
    scan_rows = cur.fetchall()

    for r in scan_rows:
        print(
            f"[ALERT][SCAN] "
            f"src_ip={r[0]} "
            f"neutrals={r[1]} "
            f"sessions={r[2]}"
        )

    cur.execute(f"""
        SELECT
            src_ip,
            username,
            SUM(failure_count) AS failures,
            SUM(success_count) AS success,
            MIN(start_time)
        FROM auth_logs
        WHERE src_ip IS NOT NULL
        AND start_time > now() - interval '{WINDOW_MINUTES} minutes'
        GROUP BY src_ip, username
        HAVING SUM(failure_count) > 0
        AND SUM(success_count) > 0
    """)
    saf_rows = cur.fetchall()

    for r in saf_rows:
        print(
            f"[ALERT][SUCCESS_AFTER_FAILURE] "
            f"src_ip={r[0]} "
            f"user={r[1]} "
            f"failures={r[2]} "
            f"success={r[3]} "
            f"time={r[4]}"
        )

    cur.close()
    closedbconn()


watchdog()

