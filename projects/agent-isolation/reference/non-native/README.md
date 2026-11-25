# 기존 교차 플랫폼 조사 기록

Windows 네이티브 비교 범위를 확정하기 전의 자료입니다. 에이전트 문서는 당시 실행 경로를 보존합니다. 현재 비교는 [Windows 네이티브 격리 조사](../../research/README.md)에서 진행합니다.

[프로젝트 비교표](../../README.md#windows-서비스별-조사) · [실측 프로토콜](../../protocol.md) · [결과 및 판단](../../findings.md)

`agents/`에는 조사 버전에서 명령과 파일 도구가 실제로 거치는 경로를, `solutions/`에는 그 경로를 구성하는 기술의 동작과 정책 적용 범위를 기록합니다. 아래 표의 **제품 실행 경로**는 네이티브 또는 제품이 지원하는 백엔드입니다. **배포·호스팅 경로**는 에이전트나 엔진을 어디에 두는지 설명합니다. 한 실행에 여러 계층이 적용될 수 있습니다.

제품 적용은 서비스 문서의 고정 버전을 기준으로 하며, 배포·호스팅 경로에는 별도로 확인한 공식 온라인 문서도 사용합니다. 공급자 기능의 적용 범위는 각 에이전트의 연동 코드와 설정에 따라 달라집니다. 현재는 문서·소스 조사 단계이며 ISO-01~06과 비용 측정값은 아직 없습니다.

## 에이전트별 사용 경로

| 에이전트 | 제품 실행 경로 | 배포·호스팅 경로 |
| --- | --- | --- |
| [Codex](agents/codex.md) | 네이티브 [MXC](../../research/solutions/mxc.md), 레거시 [전용 계정·Restricted Token](../../research/solutions/windows-accounts-tokens.md), Linux [Bubblewrap](solutions/bubblewrap.md)과 제한적인 레거시 [Landlock](solutions/landlock.md) | [WSL2](solutions/wsl2.md), [Dev Containers](solutions/dev-containers.md), [Codex Cloud](solutions/codex-cloud.md) |
| [Claude Code](agents/claude-code.md) | Windows [도구 승인과 호스트 셸](../../research/solutions/tool-approval.md), WSL2 [Bubblewrap과 네트워크 프록시](solutions/bubblewrap.md) | [WSL2](solutions/wsl2.md), [Docker](solutions/docker.md), [Dev Containers](solutions/dev-containers.md), [VM](solutions/virtual-machines.md), [관리형 클라우드](solutions/claude-code-cloud.md) |
| [QwenPaw](agents/qwenpaw.md) | 거버넌스 판정 후 [AppContainer](../../research/solutions/appcontainer.md) 또는 [Restricted Token·WFP](../../research/solutions/windows-accounts-tokens.md). Linux는 [Bubblewrap](solutions/bubblewrap.md) 또는 [Landlock](solutions/landlock.md) 탐지 | Linux판을 [WSL2](solutions/wsl2.md)에 설치하는 경우 |
| [OpenClaw](agents/openclaw.md) | Gateway [호스트 실행](../../research/solutions/tool-approval.md), [Docker](solutions/docker.md), [Podman](solutions/podman.md), [MXC 플러그인](../../research/solutions/mxc.md), [SSH](solutions/ssh.md), [OpenShell](solutions/openshell.md), [Crabbox](solutions/crabbox.md)를 통한 [Daytona](solutions/daytona.md). Windows Hub 노드는 별도 [MXC](../../research/solutions/mxc.md) | 관리형 Gateway의 [WSL2](solutions/wsl2.md) 또는 Store 네이티브 [MXC IsolationSession](../../research/solutions/mxc-isolation-session.md) |
| [Hermes Agent](agents/hermes.md) | 기본 [호스트 셸](../../research/solutions/tool-approval.md), [Docker](solutions/docker.md) 또는 호환 [Podman](solutions/podman.md), [SSH](solutions/ssh.md), [Modal](solutions/modal.md), [Daytona](solutions/daytona.md), [Vercel Sandbox](solutions/vercel-sandbox.md) | [WSL2](solutions/wsl2.md) 직접 설치 또는 WSL 터미널 연결 |
| [OpenCode](agents/opencode.md) | [도구 승인과 호스트 셸](../../research/solutions/tool-approval.md) | [WSL2](solutions/wsl2.md), 외부 [컨테이너](solutions/docker.md), [VM](solutions/virtual-machines.md) 또는 별도 원격 서버에 엔진 배치 |
| [OpenHuman](agents/openhuman.md) | [TinyBox](../../research/solutions/tinybox.md) 기반 선택. 안정판 Windows에서는 [호스트 셸](../../research/solutions/tool-approval.md)로 실행되며 [AppContainer](../../research/solutions/appcontainer.md)는 자동 탐지에서 제외. [Docker](solutions/docker.md)는 명령 단위로 선택 가능 | Docker 엔진이 실행되는 환경에 의존 |

## 기술별 문서

| 기술 | 경계를 적용하는 곳 |
| --- | --- |
| [MXC](../../research/solutions/mxc.md) | Windows ProcessContainer에서 실행한 프로세스에 SDK 정책 적용 |
| [MXC IsolationSession](../../research/solutions/mxc-isolation-session.md) | 전용 Windows 계정과 OS 관리 세션에 Gateway 서비스 배치 |
| [Windows 전용 계정·Restricted Token·ACL·WFP](../../research/solutions/windows-accounts-tokens.md) | Windows 보안 주체와 객체 접근 권한, 네트워크 필터 |
| [AppContainer](../../research/solutions/appcontainer.md) | Windows AppContainer SID, capability, 객체 ACL |
| [Bubblewrap](solutions/bubblewrap.md) | Linux 네임스페이스와 호출자가 조립한 마운트·네트워크 정책 |
| [Landlock](solutions/landlock.md) | Linux 커널의 접근 제어 규칙 |
| [WSL2](solutions/wsl2.md) | Windows 호스트와 Linux 배포판 사이의 VM 및 통합 설정 |
| [Docker](solutions/docker.md) | Linux 컨테이너 엔진의 파일·프로세스·네트워크 경계 |
| [Podman](solutions/podman.md) | Linux 컨테이너와 Windows Podman Machine 설정 |
| [TinyBox](../../research/solutions/tinybox.md) | 라이브러리가 선택한 로컬 jail 또는 Docker 경로 |
| [SSH](solutions/ssh.md) | 원격 계정 및 대상 서버가 적용한 정책 |
| [OpenShell](solutions/openshell.md) | 컴퓨트 드라이버, Linux 접근 규칙 및 네트워크 감독 계층 |
| [Crabbox](solutions/crabbox.md) | 임대한 원격 머신과 그 제공자의 실행 정책 |
| [Modal](solutions/modal.md) | 관리형 원격 런타임과 샌드박스 정책 |
| [Daytona](solutions/daytona.md) | 관리형 샌드박스의 커널·네트워크·스토리지 |
| [Vercel Sandbox](solutions/vercel-sandbox.md) | Firecracker microVM과 제공자 네트워크 정책 |
| [Dev Containers](solutions/dev-containers.md) | 개발 컨테이너의 엔진, 마운트, 도구 실행 위치 |
| [외부 VM](solutions/virtual-machines.md) | 하이퍼바이저와 운영자가 구성한 공유 범위 |
| [Codex Cloud](solutions/codex-cloud.md) | 작업별 원격 VM과 환경 정책 |
| [Claude Code 관리형 클라우드](solutions/claude-code-cloud.md) | 원격 세션 VM과 프록시 정책 |
| [도구 승인과 호스트 셸](../../research/solutions/tool-approval.md) | 호출 전 애플리케이션 판정과 호스트 실행 계정 |
