' operator-site 서버 2개(8000, 8100)를 창 없이 백그라운드로 실행한다.
' 작업 스케줄러(로그온 시)에서 wscript.exe 로 호출된다.
'   실행:  wscript.exe "C:\...\operator-site\start_servers.vbs"
Option Explicit

Dim sh, fso, baseDir
Set sh  = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

' 이 스크립트가 있는 폴더를 작업 디렉터리로 사용
baseDir = fso.GetParentFolderName(WScript.ScriptFullName)
sh.CurrentDirectory = baseDir

' 0 = 창 숨김, False = 종료를 기다리지 않음
sh.Run "cmd /c python -m uvicorn app:app --host 127.0.0.1 --port 8000 >> server.log 2>&1", 0, False
sh.Run "cmd /c python -m uvicorn app_cce:app --host 127.0.0.1 --port 8100 >> cce.log 2>&1", 0, False
