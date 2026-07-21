"""최초 1회 실행: AI 데이터베이스와 operators 테이블을 만들고 admin 계정을 시드한다.

실행:  python init_db.py
"""

import sys

import pymysql

import config
from db import create_operator


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
    print(f"[완료] 데이터베이스 '{config.DB_NAME}'와 'operators' 테이블을 준비했습니다.")

    # 4) 초기 admin 계정 시드
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
