# 운영자 로그인 웹사이트

로컬 MariaDB를 사용하는 운영자 전용 로그인 사이트입니다. (FastAPI + PyMySQL)

## 요구 사항
- Python 3.x
- 로컬 MariaDB 실행 중 (`localhost:3306`)

## 설치
```bash
python -m pip install -r requirements.txt
```

## 0) 환경변수 설정 (최초 1회)
`.env.example`를 `.env`로 복사한 뒤 실제 값(DB 비밀번호, 세션 시크릿 등)을 채웁니다.
```bash
copy .env.example .env    # Windows
cp .env.example .env      # macOS/Linux
```
`.env`는 `.gitignore`에 등록되어 있어 저장소에 올라가지 않습니다.

## 1) DB 초기화 (최초 1회)
`AI` 데이터베이스와 `operators` 테이블을 만들고 초기 관리자 계정을 시드합니다.
```bash
python init_db.py
```
- 초기 계정: **admin / admin1234**

## 2) 서버 실행
```bash
python -m uvicorn app:app --reload --port 8000
```
브라우저에서 http://localhost:8000 접속

## 화면
- `/login` : 아이디/비밀번호 로그인
  - 빈 입력 시: "아이디와 비밀번호를 모두 입력해주세요."
  - 계정/비번 오류 시: "아이디 또는 비밀번호가 올바르지 않습니다."
- `/dashboard` : 서버 관리 대시보드 (세션 필요)
  - 왼쪽 사이드바에 **서버 그룹** 목록, 클릭하면 `/dashboard?group=WEB` 으로 이동
  - 오른쪽에 해당 그룹의 서버가 **랙 서버 아이콘 카드**로 표시됨
  - 상단 통계 카드 (전체/정상/점검/중지), 검색창으로 서버명·IP·용도 필터
  - 카드에 마우스를 올리면 수정·삭제 버튼 노출
  - 비밀번호 변경 팝업 (`POST /change-password`, JSON 응답)
- `/logout` : 로그아웃

## 서버 관리 API
모두 세션이 필요하며 `{"ok": bool, "message": str}` JSON을 반환합니다.

| 메서드 | 경로 | 설명 |
|---|---|---|
| POST | `/api/servers` | 서버 등록 (없는 그룹명을 쓰면 그룹이 새로 생김) |
| POST | `/api/servers/{id}` | 서버 수정 |
| POST | `/api/servers/{id}/delete` | 서버 삭제 |

입력 필드: `group_name`, `name`, `ip`, `os_name`, `role`, `status`(`ok`/`check`/`down`).
서버명은 UNIQUE라 중복 시 400과 함께 "이미 존재하는 서버명입니다."를 반환합니다.

## 구성
| 파일 | 설명 |
|---|---|
| `.env.example` | 환경변수 템플릿 (`.env`로 복사해 사용) |
| `config.py` | `.env`에서 DB 접속정보·세션 시크릿·초기 계정을 읽어옴 |
| `db.py` | DB 커넥션, 비밀번호 해시(bcrypt)/검증, 계정·서버 조회 및 CRUD |
| `init_db.py` | DB/테이블 생성, admin 및 샘플 서버 시드 (재실행 안전) |
| `app.py` | FastAPI 라우트 (로그인/대시보드/서버 API/로그아웃) |
| `templates/` | base.html(사이드바·상단바 셸), login.html, dashboard.html |
| `static/style.css` | 스타일 (로그인 + 앱 셸 + 서버 카드) |

## DB 테이블
- `operators` : 운영자 계정 (`username`, `password_hash`)
- `servers` : 서버 목록 (`group_name`, `name`, `ip`, `os`, `role`, `status`, `sort_order`)
  - 그룹은 별도 테이블 없이 `group_name` 컬럼으로 관리합니다.

## 보안 참고
- 비밀번호는 bcrypt 해시로 저장됩니다.
- DB 비밀번호·세션 시크릿 등 자격증명은 모두 `.env`에만 두고, 절대 커밋하지 마세요.
- 운영 배포 시 `.env`의 `SESSION_SECRET`을 임의의 긴 무작위 문자열로 반드시 변경하세요.
- 초기 계정 `admin / admin1234`는 최초 로그인 후 즉시 변경하세요.
