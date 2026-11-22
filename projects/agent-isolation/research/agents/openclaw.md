# OpenClaw의 Windows 실행 격리

2026-11-23 확인 · Gateway 안정 릴리스 `2026.11.6`, Windows Hub 안정 릴리스 `2026.11.3` · Hub와 Gateway는 독립적으로 배포됩니다. [Gateway 릴리스](https://github.com/openclaw/openclaw/releases/tag/v2026.11.6) · [Windows Hub 릴리스](https://github.com/openclaw/openclaw-windows-node/releases/tag/v2026.11.3)

[조사 목록](../README.md)

관련 기술은 [도구 승인과 호스트 셸](../solutions/tool-approval.md) · [MXC](../solutions/mxc.md) · [MXC IsolationSession](../solutions/mxc-isolation-session.md)에서 설명합니다.

## Windows 네이티브 실행 경로

| 경로 | 격리 범위 |
| --- | --- |
| Windows Gateway 또는 CLI 직접 실행 | Gateway 실행 계정의 권한을 따릅니다. 일반 Gateway 도구 샌드박스는 기본 `off`입니다. |
| Windows Gateway의 MXC 플러그인 | 선택한 Gateway 도구의 명령을 MXC에 전달합니다. 실행기의 호스트 프로브에서 실제 지원 등급을 확인합니다. |
| Windows Hub 노드의 `system.run` | 지원 장치에서 노드 로컬 MXC가 명령을 제한합니다. |
| Store 네이티브 Gateway | 지원 장치에서 Gateway 서비스 자체를 별도 Windows 계정의 IsolationSession에 배치합니다. |

Store 네이티브 설치는 Windows의 세션 지원을 확인합니다. 실제 설치 경로와 제품별 버전을 기록합니다. CLI 예약 작업은 서비스 실행 방식입니다. [Gateway 실행 모드](https://github.com/openclaw/openclaw/blob/v2026.11.6/docs/gateway/sandboxing/modes-scope-and-backend.md) · [Windows 네이티브 설치 안내](https://docs.openclaw.ai/platforms/windows)

## Gateway의 도구 샌드박스

Gateway 본체는 호스트에 남으며 `exec`, `process`, `read`, `write`, `edit` 등의 도구가 샌드박스 정책을 적용받습니다. 브라우저 격리는 별도 옵션이고, 일반 세션과 생성자 역할이 격리를 강제하는 세션은 `tools.elevated` 처리에 차이가 있습니다. `non-main`은 에이전트의 메인 세션을 제외하므로 세션 키를 점검해야 합니다. [도구별 적용 범위](https://github.com/openclaw/openclaw/blob/v2026.11.6/docs/gateway/sandboxing/what-gets-sandboxed.md) · [세션 적용 조건](https://github.com/openclaw/openclaw/blob/v2026.11.6/docs/gateway/sandboxing/modes-scope-and-backend.md)

Windows Gateway용 공식 `@openclaw/mxc-sandbox` 플러그인은 설치 후 `sandbox.backend: "mxc"`를 지정해야 합니다. SDK의 Windows ProcessContainer로 툴을 실행하고 기본 네트워크는 `none`입니다. `network: "default"`는 아웃바운드 연결을 열며 플러그인에는 목적지 목록 필터가 없습니다. `workspaceAccess`에 따라 격리 작업 디렉터리와 실제 프로젝트의 마운트 범위가 달라집니다. 실행은 명령 단위이고 스코프는 작업 영역 공유 단위를 정합니다. [v2026.11.6 MXC 플러그인 설명](https://github.com/openclaw/openclaw/blob/v2026.11.6/extensions/mxc/README.md)

## Windows Hub 노드의 명령 실행

Gateway가 노드로 전달한 `system.run`은 페어링, Gateway의 노드 명령 정책, Windows 로컬 V2 승인, MXC 정책을 거칩니다. 지원 장치에서는 Windows Hub가 파일·네트워크·클립보드·UI 정책을 MXC에 넘깁니다. 미지원으로 확정된 Windows는 차단 설정에 따라 경고와 함께 직접 실행할 수 있습니다. SDK 오류, 판정 불가, 런타임 실패는 이 호환 실행으로 전환하는 조건이 아닙니다. Hub의 로컬 MCP 모드도 같은 `system.run` 경로를 사용합니다. [Windows Hub 실행 FAQ](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/docs/OPENCLAW_GATEWAY_NODE_EXEC_FAQ.md) · [Hub 로컬 MCP 모드](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/docs/MCP_MODE.md)

## 실측에서 확인할 항목

- `openclaw sandbox explain`으로 세션의 유효 모드, 백엔드, 스코프, 마운트를 기록합니다. Gateway 직접 실행, Gateway 도구 MXC, Windows 노드 MXC, Store 네이티브 Gateway 세션을 별도 조건으로 기록합니다.
- Gateway 플러그인과 노드 MXC의 네트워크·파일 정책을 각각 검증합니다. Gateway와 노드에 서로 다른 합성 파일을 두어 실제 실행 위치를 확인합니다.
- 노드 MXC 호환성, 자식 실행 가능 여부, 정책이 허용하는 호환 실행 여부를 구분합니다. Windows Hub 및 Gateway 버전과 설치 경로를 함께 남깁니다.
