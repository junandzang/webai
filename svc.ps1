# operator-site 서비스 제어 스크립트
#
#   .\svc.ps1 start     서버 시작 (이미 떠 있으면 그대로 둠)
#   .\svc.ps1 stop      서버 중지
#   .\svc.ps1 restart   재시작
#   .\svc.ps1 status    상태 확인
#
# 관리자 권한이 없어 진짜 Windows 서비스로는 등록할 수 없으므로,
# 이 스크립트 + 작업 스케줄러(감시자)로 서비스처럼 동작하게 한다.

param(
    [ValidateSet('start', 'stop', 'restart', 'status')]
    [string]$Action = 'status',
    [int]$Port = 8000,
    [string]$App = 'app:app'
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

function Get-Listener {
    Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
        Select-Object -First 1
}

function Get-ServerProcess {
    # 이 앱의 uvicorn 프로세스만 골라낸다 (다른 python 프로세스는 건드리지 않는다)
    Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine -match [regex]::Escape("uvicorn $App") }
}

function Show-Status {
    $l = Get-Listener
    if ($l) {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$($l.OwningProcess)" -ErrorAction SilentlyContinue
        Write-Host "[실행 중] 포트 $Port  (PID $($l.OwningProcess))" -ForegroundColor Green
        try {
            $r = Invoke-WebRequest "http://localhost:$Port/login" -UseBasicParsing -TimeoutSec 5
            Write-Host "         HTTP 응답 $($r.StatusCode) - 정상" -ForegroundColor Green
        } catch {
            Write-Host "         HTTP 응답 없음 - 프로세스는 살아있으나 응답 불가" -ForegroundColor Yellow
        }
        Write-Host "         http://localhost:$Port"
        return $true
    }
    Write-Host "[중지됨] 포트 $Port 에서 실행 중인 서버가 없습니다." -ForegroundColor Yellow
    return $false
}

function Start-Server {
    if (Get-Listener) {
        Write-Host "[안내] 이미 실행 중입니다. 그대로 둡니다." -ForegroundColor Cyan
        Show-Status | Out-Null
        return
    }
    Write-Host "서버를 시작합니다..." -ForegroundColor Cyan
    # 창 없이 백그라운드로 띄우고 로그를 파일로 남긴다.
    # 리다이렉션은 cmd 에게 맡긴다 — Start-Process -RedirectStandardOutput 을 쓰면
    # 부모 셸이 파이프를 붙들어 스크립트(및 이를 호출한 bat)가 반환되지 않는다.
    $line = "python -m uvicorn $App --host 127.0.0.1 --port $Port >> server.log 2>&1"
    $opts = @{
        FilePath         = 'cmd.exe'
        ArgumentList     = @('/c', $line)
        WorkingDirectory = $Root
        WindowStyle      = 'Hidden'
    }
    Start-Process @opts | Out-Null

    for ($i = 0; $i -lt 15; $i++) {
        if (Get-Listener) { break }
        Start-Sleep -Seconds 1
    }
    if (-not (Show-Status)) {
        Write-Host "[오류] 시작에 실패했습니다. server.log 를 확인하세요." -ForegroundColor Red
    }
}

function Stop-Server {
    $procs = @(Get-ServerProcess)
    if ($procs.Count -eq 0) {
        Write-Host "[안내] 실행 중인 서버가 없습니다." -ForegroundColor Yellow
        return
    }
    foreach ($p in $procs) {
        Write-Host "중지: PID $($p.ProcessId)" -ForegroundColor Cyan
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 2
    if (Get-Listener) {
        Write-Host "[경고] 아직 포트가 열려 있습니다." -ForegroundColor Yellow
    } else {
        Write-Host "[완료] 중지되었습니다." -ForegroundColor Green
    }
}

switch ($Action) {
    'start'   { Start-Server }
    'stop'    { Stop-Server }
    'restart' { Stop-Server; Start-Sleep -Seconds 2; Start-Server }
    'status'  { Show-Status | Out-Null }
}
