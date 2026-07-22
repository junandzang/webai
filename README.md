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
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```
브라우저에서 http://localhost:8000 접속 (개발 중 자동 리로드는 `--reload` 추가)

**간편 실행**: `run_8000.bat` 더블클릭 (8100은 `run_8100.bat`). 창을 닫으면 서버도 종료됩니다.

**자동 시작(로그온 시)**: 작업 스케줄러에 `operator-site` 작업으로 등록되어 있습니다.
`start_servers.vbs`가 8000·8100을 창 없이 백그라운드로 띄웁니다.
```powershell
Start-ScheduledTask -TaskName 'operator-site'      # 지금 바로 시작
Get-ScheduledTaskInfo -TaskName 'operator-site'    # 마지막 실행 결과 확인
Unregister-ScheduledTask -TaskName 'operator-site' # 자동 시작 해제
```
> 관리자 권한이 없어 진짜 Windows 서비스(sc/NSSM) 대신 작업 스케줄러를 사용합니다.
> 서버를 내리려면 `Get-Process python | Stop-Process` 또는 해당 PID를 종료하세요.

### (선택) SolidStep 스타일 UI — 포트 8100
같은 DB·스캔 엔진을 공유하는 별도 디자인의 콘솔입니다. 8000과 동시에 띄울 수 있습니다.
```bash
python -m uvicorn app_cce:app --port 8100
```
브라우저에서 http://localhost:8100 접속 (로그인 계정은 8000과 동일).
- 빨간 테마 로그인 + 좌측 아이콘 레일 + 자산 그룹/대상 패널 + 상단 탭
- **자산 정보**: 자산별 점수 카드, 평균 점수, 진단 실행(톱니)
- **진단 결과**: 자산별 최신 진단 요약 + 보고서 상세보기
- **보고서 상세보기**: 취약/수동 점검/양호 분류, 위험도(최상~최하), 진단기준·현황·조치방법
- 나머지 탭(조치/결재/작업내역/로그/통계/대시보드/다운로드)은 "준비 중"

## 화면
- `/login` : 아이디/비밀번호 로그인
  - 빈 입력 시: "아이디와 비밀번호를 모두 입력해주세요."
  - 계정/비번 오류 시: "아이디 또는 비밀번호가 올바르지 않습니다."
- `/dashboard` : 서버 관리 대시보드 (세션 필요)
  - 왼쪽 사이드바에 **서버 그룹** 목록, 클릭하면 `/dashboard?group=WEB` 으로 이동
  - `서버 그룹` 라벨의 **+ 버튼으로 빈 그룹을 추가** (서버 0대인 그룹도 유지됨)
  - 그룹에 마우스를 올리면 **연필(이름 수정) · 휴지통(삭제)** 버튼이 나타남
  - 그룹 삭제는 **서버가 0대일 때만** 가능 (서버가 남아 있으면 버튼이 비활성화됨)
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
| POST | `/api/groups` | 빈 그룹 생성 (`name`) |
| POST | `/api/groups/rename` | 그룹명 변경 (`old_name`, `new_name`) |
| POST | `/api/groups/delete` | 그룹 삭제 (`name`) — 서버가 남아 있으면 400 |
| POST | `/api/servers/{id}/scan` | 보안검사 시작 (백그라운드) → `{ok, scan_id}` |
| GET  | `/api/servers/{id}/scan/status` | 최신 스캔 상태·심각도 카운트(폴링) |
| GET  | `/servers/{id}` | 서버 상세 + 보안검사 리포트 페이지(HTML) |

입력 필드: `group_name`, `name`, `ip`, `os_name`, `role`, `status`(`ok`/`check`/`down`).
서버명은 UNIQUE라 중복 시 400과 함께 "이미 존재하는 서버명입니다."를 반환합니다.

그룹명 변경은 해당 그룹 서버들의 `group_name`을 일괄 UPDATE 합니다.
이미 있는 그룹명으로 바꾸면 **두 그룹이 합쳐집니다**.

## 보안검사 (취약점 스캔)
서버 카드의 **보안검사** 버튼 → 백그라운드로 nmap 스캔 → 리포트 페이지에 체크리스트로 표시.

- **엔진**: nmap `-sT -sV -Pn --top-ports 200 + NSE`(관리자 권한 불필요). `scanner.py`가 XML을 파싱
- **OS 파악**: 서비스 지문·배너로 OS를 추정해 `servers.os`를 자동 갱신
- **점검 항목**(`rules.py`, 오프라인): 평문 인증(telnet/FTP/메일), 원격 관리 노출(SSH/RDP/VNC),
  DB 노출(MySQL/PG/MSSQL/Mongo/Redis 등), 무인증 접근(익명 FTP·Redis/Mongo → 계정 탈취),
  웹(HTTPS 미적용·약한 TLS·보안 헤더 누락), 지원종료(EOL) OS
- **CVE**(`nvd.py`): NVD 실시간 조회를 시도하고, 사내 프록시로 막히면 오프라인 규칙 결과만으로 진행
  (리포트에 `CVE 출처: 실시간 NVD | 내장 규칙(오프라인)` 표시)
- **경계**: 노출 평가와 비파괴적 확인만 수행. **실제 비밀번호 시도·브루트포스·익스플로잇 없음.**
  스캔 대상은 인벤토리에 등록된 서버 IP로 한정

> **선행조건**: nmap이 설치돼 있어야 합니다. `.env`의 `NMAP_PATH`로 경로를 지정하거나 PATH에 두세요.

## 계정 기반 심층 점검 (credentialed audit)
`서버 검사` 화면의 자산별 **계정 점검** 버튼 → SSH·DB 접속 정보를 입력하면 서버 내부까지 점검합니다.

- **입력**: SSH(포트/ID/비밀번호), DB(포트/ID/비밀번호) — 필요한 쪽만 입력해도 됩니다
- **자격증명은 저장하지 않습니다.** DB·파일·로그 어디에도 남기지 않고 해당 검사에서 메모리로만 사용합니다.
  재검사 시 다시 입력해야 합니다
- **읽기 전용**으로만 조회합니다 (설정 변경·쓰기 없음)
- **DB 점검**(`credaudit.audit_mysql`): 빈 비밀번호·익명 계정, root 원격 접속, 모든 IP 허용(%),
  과도한 권한(SUPER/GRANT/FILE), `secure_file_priv`·`local_infile`·TLS 설정, test DB, 정확한 버전
  (역할·잠긴 계정은 오탐 방지를 위해 제외)
- **SSH 점검**(`credaudit.audit_ssh`): 정확한 배포판·커널 버전, UID 0 계정, 빈 비밀번호 계정,
  비밀번호 정책, `PermitRootLogin`·`PasswordAuthentication`, `/etc/passwd`·`/etc/shadow` 권한
- 접속 실패(포트 차단·자격증명 오류)는 오류가 아니라 **정보 항목**으로 남고 나머지 점검은 계속됩니다
- 결과는 기존 네트워크 스캔과 **한 리포트로 합쳐지며**, `scans.authed=1`로 표시됩니다

## 구성
| 파일 | 설명 |
|---|---|
| `.env.example` | 환경변수 템플릿 (`.env`로 복사해 사용) |
| `config.py` | `.env`에서 DB 접속정보·세션 시크릿·초기 계정·스캔 설정을 읽어옴 |
| `db.py` | DB 커넥션, 비밀번호 해시(bcrypt)/검증, 계정·서버 CRUD, 스캔 저장 |
| `init_db.py` | DB/테이블 생성, admin 및 샘플 서버 시드 (재실행 안전) |
| `app.py` | 기존 UI(8000) FastAPI 라우트 |
| `app_cce.py` | SolidStep 스타일 UI(8100) FastAPI 라우트 — db/scanner 공유 |
| `templates_cce/`, `static_cce/` | 8100 전용 템플릿·스타일 |
| `scanner.py` | nmap 실행·XML 파싱·NVD 병합 오케스트레이터 (점수 계산 포함) |
| `rules.py` | 오프라인 보안 점검 규칙 엔진 |
| `nvd.py` | NVD CVE 실시간 조회(+오프라인 폴백) |
| `templates/` | base.html(셸), login.html, dashboard.html, scan.html(리포트) |
| `static/style.css` | 스타일 (로그인 + 앱 셸 + 서버 카드 + 스캔 리포트) |

## DB 테이블
- `operators` : 운영자 계정 (`username`, `password_hash`)
- `servers` : 서버 목록 (`group_name`, `name`, `ip`, `os`, `role`, `status`, `sort_order`)
- `scans` : 보안검사 실행 이력 (`server_id`, `target_ip`, `status`, `os_detected`, 심각도 카운트)
- `scan_checks` : 스캔별 체크리스트 항목 (`category`, `title`, `severity`, `result`, `detail`, `remediation`, `cve_ids`)
- `server_groups` : 그룹 목록 (`name`, `sort_order`)
  - 사이드바 메뉴는 이 테이블 기준이라 **서버가 0대인 그룹도 유지**됩니다.
  - `servers.group_name`은 FK가 아닌 문자열이며, 서버 등록·수정 시 새 그룹명이 들어오면
    자동으로 `server_groups`에 등록됩니다.
  - `init_db.py`는 기존 설치에서도 쓰이던 그룹명을 자동으로 백필합니다.

## 보안 참고
- 비밀번호는 bcrypt 해시로 저장됩니다.
- DB 비밀번호·세션 시크릿 등 자격증명은 모두 `.env`에만 두고, 절대 커밋하지 마세요.
- 운영 배포 시 `.env`의 `SESSION_SECRET`을 임의의 긴 무작위 문자열로 반드시 변경하세요.
- 초기 계정 `admin / admin1234`는 최초 로그인 후 즉시 변경하세요.
