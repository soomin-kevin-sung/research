# Windows Subsystem for Linux 2 (WSL2)

## 실행 경계

WSL2는 관리형 경량 VM에서 Linux 커널을 실행합니다. 배포판별 파일시스템·프로세스 환경이 있으며 Windows 드라이브 자동 마운트, Windows 프로그램 호출(interop), 네트워크 연결은 WSL 설정을 따릅니다. `wsl.conf`는 배포판별 설정을, `.wslconfig`는 WSL2 VM의 전역 설정을 제어합니다. 배포판을 다시 시작해도 디스크에 저장된 파일은 유지됩니다. [Microsoft WSL2 아키텍처](https://learn.microsoft.com/en-us/windows/wsl/wsl2-about) · [WSL 설정 레퍼런스](https://learn.microsoft.com/en-us/windows/wsl/wsl-config)

## 에이전트 적용

- [Codex](../agents/codex.md)와 [Claude Code](../agents/claude-code.md)는 배포판 안에서 Linux용 [Bubblewrap](bubblewrap.md)을 사용합니다. [QwenPaw](../agents/qwenpaw.md) Linux판은 탐지 결과에 따라 Bubblewrap 또는 [Landlock](landlock.md) 등을 선택합니다.
- [OpenClaw](../agents/openclaw.md)의 Windows Hub 관리형 설치는 WSL 배포판에 Gateway를 둘 수 있습니다. Gateway가 개별 도구에 적용하는 Docker·MXC 등의 선택과는 별도의 배치 정보입니다.
- [Hermes Agent](../agents/hermes.md)는 WSL2에 직접 설치하거나 Windows의 터미널 플러그인에서 기존 배포판으로 실행을 전달할 수 있습니다. [OpenCode](../agents/opencode.md)의 WSL 배포는 엔진 실행 위치를 바꾸는 배포 옵션입니다.

## 실측 시 확인

배포판, WSL 커널, 작업 디렉터리의 파일시스템, DrvFs 접근, interop 및 네트워크 모드를 기록합니다. 배포판 내부의 셸 격리와 Windows 호스트의 시험 리소스 접근을 구분하고, 초기 VM 시작과 준비된 배포판에서의 작업 비용을 따로 측정합니다.
