# Claude Code의 Windows 실행 격리

2026-11-23 확인 · 안정 릴리스 `2.1.330` · 대상은 Windows에서 실행하는 Claude Code CLI와 WSL2입니다. [Claude Code v2.1.330 릴리스](https://github.com/anthropics/claude-code/releases/tag/v2.1.330)

[조사 목록](../README.md)

관련 기술은 [도구 승인과 호스트 셸](../../../research/solutions/tool-approval.md) · [Bubblewrap](../solutions/bubblewrap.md) · [WSL2](../solutions/wsl2.md) · [Docker](../solutions/docker.md) · [Dev Containers](../solutions/dev-containers.md) · [외부 VM](../solutions/virtual-machines.md) · [Claude Code 관리형 클라우드](../solutions/claude-code-cloud.md)에서 설명합니다.

## Windows 네이티브와 WSL2

Claude Code 네이티브 Windows에서 에이전트가 실행하는 셸 명령에는 내장 Bash 샌드박스가 적용되지 않습니다. 명령 실행 여부는 Claude Code 권한 모드와 사전 승인 규칙이 결정하고, 실행된 프로세스는 Windows 실행 계정의 권한을 사용합니다. 내장 OS 수준 셸 격리를 사용하려면 WSL2 배포판 안에서 Linux용 Claude Code를 실행하고 샌드박스를 활성화해야 합니다. [Claude Code 샌드박싱](https://code.claude.com/docs/en/sandboxing) · [Claude Code 설치](https://code.claude.com/docs/en/setup)

## WSL2에서의 파일과 네트워크 경계

- **파일 접근.** Bubblewrap이 파일시스템 경계를 적용합니다. 기본 쓰기 범위는 작업 디렉터리, 추가로 지정한 작업 디렉터리, 사용자 임시 디렉터리입니다. 기본 읽기는 일부 차단 경로를 제외하고 넓게 허용되므로 `sandbox.filesystem.denyRead`와 `permissions.blockReadsOutsideWorkingDirectories`의 유효 설정이 중요합니다. Git worktree의 공용 Git 디렉터리와 보호 경로는 별도 규칙을 따릅니다. [파일시스템 격리](https://code.claude.com/docs/en/sandboxing#filesystem-isolation)
- **네트워크.** 별도 네트워크 네임스페이스에서 셸을 실행하고, 외부 샌드박스 프록시로 연결을 중계합니다. `socat`이 릴레이에 사용됩니다. 프록시 사용 클라이언트는 도메인과 포트 규칙을 적용받고, 직접 연결과 비 TCP 프로토콜은 기본 경로에서 차단됩니다. 선택적 seccomp 필터는 Unix 도메인 소켓 격리를 보완합니다. [WSL2 의존성](https://code.claude.com/docs/en/sandboxing#set-up-linux-and-wsl2) · [네트워크 격리](https://code.claude.com/docs/en/sandboxing#network-isolation)
- **환경 변수와 자격 증명.** 기본 읽기 정책이 일부 자격 증명 파일을 열어 둡니다. 정책에서 보호할 파일과 변수 이름을 지정할 수 있으므로, 가짜 파일과 가짜 변수로 각각 확인합니다. `/mnt/c` 접근과 Windows 프로그램 호출 가능성은 WSL 배포판의 자동 마운트 및 interop 설정과 함께 기록합니다. [Claude Code 자격 증명 보호](https://code.claude.com/docs/en/sandboxing) · [WSL 설정](https://learn.microsoft.com/en-us/windows/wsl/wsl-config)

## 활성화와 적용 범위

`/sandbox`에서 활성화 상태와 의존성을 확인합니다. `sandbox.enabled`로 활성화하고 `sandbox.failIfUnavailable`로 백엔드 미지원·시작 실패 시 동작을 통제합니다. 정책상 비격리 재시도를 금지하려면 `sandbox.allowUnsandboxedCommands: false`를 별도로 적용합니다. `excludedCommands`와 사용자가 직접 입력하는 `!` 셸 명령은 적용 조건이 다르므로 결과에서 구분합니다. [샌드박스 구성과 관리 정책](https://code.claude.com/docs/en/sandboxing#enforce-sandboxing-with-managed-settings)

샌드박스는 에이전트 셸 명령과 그 하위 프로세스에 적용됩니다. Read, Edit, Write, WebFetch는 Claude Code 자체 권한 규칙을 따르고, MCP 서버와 훅도 셸 샌드박스 밖에서 실행됩니다. 전체 프로세스를 함께 격리하는 Dev Container, VM, 원격 Claude Code 환경은 각기 다른 배포 단위입니다. [샌드박스 적용 범위](https://code.claude.com/docs/en/sandboxing#what-runs-outside-the-sandbox) · [격리 환경 선택](https://code.claude.com/docs/en/sandbox-environments)

## 실측에서 확인할 항목

- 네이티브 Windows와 WSL2에서 각각 에이전트가 생성한 셸 명령을 측정합니다. WSL2는 샌드박스 활성화 상태, `bwrap`·`socat` 버전, 배포판과 프로젝트가 있는 파일시스템을 기록합니다.
- WSL2에서 셸 Read·Write와 내장 Read·Write 도구를 구분합니다. 프록시를 사용하는 연결과 직접 연결도 구분하고, 허용 목적지와 차단 목적지는 관리 가능한 시험 서버를 사용합니다.
- 기본 읽기 범위, 명시한 읽기 거부, 가짜 환경 변수 상속을 별도로 확인합니다. 의존성 미충족 조건은 시작 거부 또는 비격리 실행으로 기록합니다.
