# OpenClaw의 Windows 실행 격리

2026-11-23 확인 · Gateway 안정 릴리스 `2026.11.6`, Windows Hub 안정 릴리스 `2026.11.3` · Hub와 Gateway는 독립적으로 배포됩니다. [Gateway 릴리스](https://github.com/openclaw/openclaw/releases/tag/v2026.11.6) · [Windows Hub 릴리스](https://github.com/openclaw/openclaw-windows-node/releases/tag/v2026.11.3)

[조사 목록](../README.md)

관련 기술은 [도구 승인과 호스트 셸](../../../research/solutions/tool-approval.md) · [MXC](../../../research/solutions/mxc.md) · [Docker](../solutions/docker.md) · [Podman](../solutions/podman.md) · [SSH](../solutions/ssh.md) · [OpenShell](../solutions/openshell.md) · [Crabbox](../solutions/crabbox.md) · [Daytona](../solutions/daytona.md) · [WSL2](../solutions/wsl2.md) · [MXC IsolationSession](../../../research/solutions/mxc-isolation-session.md)에서 설명합니다.

## Windows에서 구분해야 할 실행 경로

| 경로 | 실행 위치 | 문서와 코드에서 확인한 경계 |
| --- | --- | --- |
| Gateway 또는 CLI 직접 실행 | Windows 호스트, WSL2 배포판 또는 원격 호스트 | Gateway의 실행 계정과 배포 환경을 따름. 일반 에이전트 도구 샌드박스는 기본 `off` |
| Gateway 에이전트 샌드박스 | Docker·Podman, SSH, OpenShell, Crabbox 또는 설치한 백엔드 | 활성화한 경우 대상 도구를 해당 백엔드로 보냄. Windows에서 공식 MXC 플러그인 선택 가능 |
| Windows Hub 노드의 `system.run` | Windows 노드가 연결된 PC | 지원 장치에서 노드 로컬 MXC. Gateway 쪽 샌드박스와 별개 |
| Windows Hub의 관리형 Gateway 설치 | 앱 소유 WSL 배포판 또는 라이브 문서의 Store 네이티브 설치 경로 | Gateway 프로세스를 배치하는 방식. 에이전트 도구의 백엔드 선택과 설정을 별도로 확인 |

Gateway 안정 태그의 Windows 설치 문서는 Hub의 일반 로컬 설치가 전용 `OpenClawGateway` WSL 배포판을 만든다고 설명합니다. 현재 온라인 가이드는 호환 PC의 Store 네이티브 Gateway를 별도 옵션으로 안내하고, 지원되지 않거나 프로브로 확인되지 않으면 WSL 설치를 권합니다. Hub의 설치 옵션과 실제 배치가 어느 쪽인지 릴리스 및 장치별로 확인하는 것이 필요합니다. 네이티브 CLI의 Windows 예약 작업과 S4U 계정 설정은 서비스 실행 방식입니다. [안정 태그 Windows 문서](https://github.com/openclaw/openclaw/blob/v2026.11.6/docs/platforms/windows.md) · [최신 Windows 설치 가이드](https://docs.openclaw.ai/platforms/windows)

## Gateway의 도구 샌드박스

`agents.defaults.sandbox.mode`는 `off`, `non-main`, `all`을 지원합니다. `scope`는 `session`, `agent`, `shared`로 런타임 공유 단위를 정하고, `workspaceAccess`는 `none`, `ro`, `rw`로 실제 작업 영역 노출을 정합니다. 활성화 시 기본 백엔드인 Docker는 기본 네트워크 `none`, 읽기 전용 루트, 전체 capability 제거를 사용합니다. 명시적 바인드 마운트와 별도 브라우저 컨테이너에는 각 설정이 적용됩니다. 도구 허용 정책과 `tools.elevated`는 실행 위치에 영향을 주므로 함께 읽어야 합니다. [격리 개요](https://github.com/openclaw/openclaw/blob/v2026.11.6/docs/gateway/sandboxing.md) · [모드와 백엔드](https://github.com/openclaw/openclaw/blob/v2026.11.6/docs/gateway/sandboxing/modes-scope-and-backend.md) · [Docker 기본값](https://github.com/openclaw/openclaw/blob/v2026.11.6/docs/gateway/sandboxing/docker-backend.md)

Gateway 본체는 호스트에 남으며 `exec`, `process`, `read`, `write`, `edit` 등의 도구가 샌드박스 정책을 적용받습니다. 브라우저 격리는 별도 옵션이고, 일반 세션과 생성자 역할이 격리를 강제하는 세션은 `tools.elevated` 처리에 차이가 있습니다. `non-main`은 에이전트의 메인 세션을 제외하므로 세션 키를 점검해야 합니다. [도구별 적용 범위](https://github.com/openclaw/openclaw/blob/v2026.11.6/docs/gateway/sandboxing/what-gets-sandboxed.md) · [세션 적용 조건](https://github.com/openclaw/openclaw/blob/v2026.11.6/docs/gateway/sandboxing/modes-scope-and-backend.md)

Windows Gateway용 공식 `@openclaw/mxc-sandbox` 플러그인은 설치 후 `sandbox.backend: "mxc"`를 지정해야 합니다. SDK의 Windows ProcessContainer로 툴을 실행하고 기본 네트워크는 `none`입니다. `network: "default"`는 아웃바운드 연결을 열며 플러그인에는 목적지 목록 필터가 없습니다. `workspaceAccess`에 따라 격리 작업 디렉터리와 실제 프로젝트의 마운트 범위가 달라집니다. 실행은 명령 단위이며 Docker 방식의 장수 컨테이너는 제공하지 않습니다. [v2026.11.6 MXC 플러그인 설명](https://github.com/openclaw/openclaw/blob/v2026.11.6/extensions/mxc/README.md)

## Windows Hub 노드의 명령 실행

Gateway가 노드로 전달한 `system.run`은 페어링, Gateway의 노드 명령 정책, Windows 로컬 V2 승인, MXC 정책을 거칩니다. 지원 장치에서는 Windows Hub가 파일·네트워크·클립보드·UI 정책을 MXC에 넘깁니다. 미지원으로 확정된 Windows는 차단 설정에 따라 경고와 함께 직접 실행할 수 있습니다. SDK 오류, 판정 불가, 런타임 실패는 이 호환 실행으로 전환하는 조건이 아닙니다. Hub의 로컬 MCP 모드도 같은 `system.run` 경로를 사용합니다. [Windows Hub 실행 FAQ](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/docs/OPENCLAW_GATEWAY_NODE_EXEC_FAQ.md) · [Hub 로컬 MCP 모드](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/docs/MCP_MODE.md)

## 실측에서 확인할 항목

- `openclaw sandbox explain`으로 세션의 유효 모드, 백엔드, 스코프, 마운트를 기록합니다. Gateway 직접 실행, Gateway Docker 또는 MXC, Windows 노드 실행을 별도 조건으로 측정합니다.
- Docker 네트워크, MXC 플러그인의 네트워크, 노드 MXC의 네트워크와 파일 정책을 각각 검증합니다. Gateway와 노드에 서로 다른 합성 파일을 두어 실제 실행 위치를 확인합니다.
- 노드 MXC 호환성, 자식 실행 가능 여부, 정책이 허용하는 호환 실행 여부를 구분합니다. Windows Hub 및 Gateway 버전과 설치 경로를 함께 남깁니다.
