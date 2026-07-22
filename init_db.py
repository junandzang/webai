"""최초 1회 실행: AI 데이터베이스와 테이블을 만들고 초기 데이터를 시드한다.

실행:  python init_db.py

여러 번 실행해도 안전하다 (CREATE TABLE IF NOT EXISTS / INSERT IGNORE).
"""

import sys

import pymysql

import config
from db import create_operator

# (그룹, 서버명, IP, OS, 용도, 상태)
SAMPLE_SERVERS = [
    ("WEB", "WEB-01", "10.0.1.11", "Ubuntu 22.04", "웹 서버", "ok"),
    ("WEB", "WEB-02", "10.0.1.12", "Ubuntu 22.04", "웹 서버", "ok"),
    ("WEB", "WEB-03", "10.0.1.13", "Ubuntu 22.04", "웹 서버 (예비)", "check"),
    ("WAS", "WAS-01", "10.0.2.11", "Rocky Linux 9", "애플리케이션 서버", "ok"),
    ("WAS", "WAS-02", "10.0.2.12", "Rocky Linux 9", "애플리케이션 서버", "ok"),
    ("DB", "DB-01", "10.0.3.11", "Rocky Linux 9", "MariaDB 마스터", "ok"),
    ("DB", "DB-02", "10.0.3.12", "Rocky Linux 9", "MariaDB 슬레이브", "down"),
    ("API", "API-01", "10.0.4.11", "Ubuntu 22.04", "API 게이트웨이", "ok"),
    ("API", "API-02", "10.0.4.12", "Ubuntu 22.04", "API 게이트웨이", "ok"),
]


def main():
    # 1) database 없이 서버에 접속 (AI DB가 아직 없을 수 있으므로)
    try:
        server_conn = pymysql.connect(
            host=config.DB["host"],
            port=config.DB["port"],
            user=config.DB["user"],
            password=config.DB["password"],
            charset=config.DB["charset"],
            autocommit=True,
        )
    except pymysql.err.OperationalError as e:
        print("[오류] MariaDB에 접속하지 못했습니다. 서비스 실행 여부와 접속정보를 확인하세요.")
        print("      상세:", e)
        sys.exit(1)

    with server_conn:
        with server_conn.cursor() as cur:
            # 2) AI 데이터베이스 생성
            cur.execute(
                f"CREATE DATABASE IF NOT EXISTS `{config.DB_NAME}` "
                "DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci"
            )
            cur.execute(f"USE `{config.DB_NAME}`")

            # 3) operators 테이블 생성
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS operators (
                    id            INT AUTO_INCREMENT PRIMARY KEY,
                    username      VARCHAR(50)  NOT NULL UNIQUE,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )

            # 4) servers 테이블 생성
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS servers (
                    id         INT AUTO_INCREMENT PRIMARY KEY,
                    group_name VARCHAR(50)  NOT NULL,
                    name       VARCHAR(100) NOT NULL UNIQUE,
                    ip         VARCHAR(45)  NOT NULL DEFAULT '',
                    os         VARCHAR(100) NOT NULL DEFAULT '',
                    role       VARCHAR(100) NOT NULL DEFAULT '',
                    status     VARCHAR(20)  NOT NULL DEFAULT 'ok',
                    sort_order INT          NOT NULL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_group (group_name)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )

            # 5) server_groups 테이블 생성 (서버 0대인 그룹도 유지하기 위한 레지스트리)
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS server_groups (
                    id         INT AUTO_INCREMENT PRIMARY KEY,
                    name       VARCHAR(50) NOT NULL UNIQUE,
                    sort_order INT NOT NULL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )

            # 6) 샘플 서버 시드 — servers가 완전히 비어 있을 때(최초 설치)만 넣는다.
            #    이후 재실행(스키마 추가 등)에서 사용자가 지운 샘플이 되살아나지 않도록.
            cur.execute("SELECT COUNT(*) AS c FROM servers")
            seeded = 0
            if cur.fetchone()[0] == 0:
                cur.executemany(
                    "INSERT IGNORE INTO servers "
                    "(group_name, name, ip, os, role, status) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    SAMPLE_SERVERS,
                )
                seeded = cur.rowcount

            # 7) 서버가 쓰고 있는 그룹명을 레지스트리에 채운다.
            #    신규 설치(위 시드분)와 기존 설치(이미 있던 그룹) 모두 여기서 처리된다.
            cur.execute(
                "INSERT IGNORE INTO server_groups (name) "
                "SELECT DISTINCT group_name FROM servers"
            )
            backfilled = cur.rowcount

            # 8) 보안검사(스캔) 테이블
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id          INT AUTO_INCREMENT PRIMARY KEY,
                    server_id   INT NOT NULL,
                    target_ip   VARCHAR(45) NOT NULL,
                    status      VARCHAR(20) NOT NULL DEFAULT 'queued',
                    os_detected VARCHAR(120) DEFAULT '',
                    scan_source VARCHAR(20)  DEFAULT '',
                    crit INT DEFAULT 0, high INT DEFAULT 0, med INT DEFAULT 0,
                    low  INT DEFAULT 0, info INT DEFAULT 0,
                    error_message VARCHAR(255) DEFAULT '',
                    started_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    finished_at TIMESTAMP NULL DEFAULT NULL,
                    INDEX idx_server (server_id, id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_checks (
                    id          INT AUTO_INCREMENT PRIMARY KEY,
                    scan_id     INT NOT NULL,
                    category    VARCHAR(20) NOT NULL,
                    title       VARCHAR(200) NOT NULL,
                    severity    VARCHAR(12) NOT NULL,
                    result      VARCHAR(8)  NOT NULL,
                    port        INT NULL,
                    detail      TEXT,
                    evidence    TEXT,
                    remediation TEXT,
                    cve_ids     VARCHAR(255) DEFAULT '',
                    ref_url     VARCHAR(255) DEFAULT '',
                    INDEX idx_scan (scan_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
            # 기존 설치 대응: ref_url 컬럼이 없으면 추가한다.
            cur.execute(
                "ALTER TABLE scan_checks "
                "ADD COLUMN IF NOT EXISTS ref_url VARCHAR(255) DEFAULT ''"
            )
            # 점수(0~100) 컬럼. 자산 점수 표시에 사용한다.
            cur.execute(
                "ALTER TABLE scans "
                "ADD COLUMN IF NOT EXISTS score FLOAT DEFAULT NULL"
            )
            # 계정 기반 심층 점검 포함 여부. 자격증명 자체는 저장하지 않는다.
            cur.execute(
                "ALTER TABLE scans "
                "ADD COLUMN IF NOT EXISTS authed TINYINT(1) NOT NULL DEFAULT 0"
            )

    print(
        f"[완료] 데이터베이스 '{config.DB_NAME}'에 "
        "'operators', 'servers', 'server_groups', 'scans', 'scan_checks' "
        "테이블을 준비했습니다."
    )
    if backfilled:
        print(f"[완료] 서버 그룹 {backfilled}개를 그룹 목록에 등록했습니다.")
    if seeded:
        print(f"[완료] 샘플 서버 {seeded}대를 등록했습니다.")
    else:
        print("[안내] 샘플 서버가 이미 등록되어 있어 건너뜁니다.")

    # 6) 초기 admin 계정 시드
    created = create_operator(
        config.INITIAL_ADMIN_USERNAME, config.INITIAL_ADMIN_PASSWORD
    )
    if created:
        print(
            f"[완료] 초기 운영자 계정 생성: "
            f"{config.INITIAL_ADMIN_USERNAME} / {config.INITIAL_ADMIN_PASSWORD}"
        )
    else:
        print(
            f"[안내] 운영자 계정 '{config.INITIAL_ADMIN_USERNAME}'이(가) 이미 존재하여 건너뜁니다."
        )


if __name__ == "__main__":
    main()
