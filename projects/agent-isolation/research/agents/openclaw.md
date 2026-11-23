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

메시지는 **폰·채팅 → Gateway → 에이전트**로 들어옵니다. 노드 실행 요청은 **에이전트 → Gateway → Windows Hub**로 전달됩니다. 노드는 Gateway에 연결해 해당 기기의 실행 기능을 제공하는 구성요소입니다. Gateway와 Hub는 같은 PC에 있을 수 있습니다. Gateway 자체에서 실행되는 명령에는 별도 실행 경로가 적용됩니다. [배치와 실행 경로](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/docs/OPENCLAW_GATEWAY_NODE_EXEC_FAQ.md#what-deployment-combinations-are-valid)

| 단계 | 검사와 결과 |
| --- | --- |
| Gateway 전달 | 에이전트의 `exec` 권한, `host=node` 라우팅, 노드 페어링·연결, `system.run` 지원, 파라미터와 노드 명령 정책을 확인합니다. 필요하면 Gateway 승인도 받습니다. 기본 `full/off` 경로에서는 일반적으로 Gateway 승인 질문을 생략합니다. |
| Hub 로컬 승인 V2 | Run system tools 설정과 로컬 정책을 평가합니다. 실행 파일 절대 경로와 정규화한 인수가 허용 목록과 일치하면 기본 정책에서 진행합니다. 미일치 시 Windows 사용자에게 한 번 허용, 항상 허용, 거부 중 하나를 묻습니다. UI를 표시할 수 없으면 기본적으로 거부합니다. |
| 실행 경로 판정과 MXC 요청 검증 | 지원 장치에서는 파일·네트워크·클립보드·UI 정책을 담은 SDK 요청을 BaseContainer에서 집행할 수 있는지 검사합니다. OS 미지원이 확인되면 호스트 호환 실행을 준비합니다. |
| 최종 승인 재검증 및 시작 | 두 경로 모두 시작 직전에 현재 정책과 승인의 유효성을 다시 확인합니다. 정책 변경이나 재검증 실패는 시작을 차단합니다. MXC로 시작한 프로세스에는 실행 중 격리 정책이 적용됩니다. |

V2는 Windows Hub의 **로컬 명령 승인 방식**을 가리킵니다. OpenClaw 2.0은 별도로 쓰이는 제품 업데이트 명칭입니다. Windows Hub의 호환 실행에서도 명령 승인 정책은 적용됩니다. Hub의 로컬 MCP 모드도 같은 `system.run` 처리 경로를 사용합니다. [승인 V1·V2와 명령 전달 순서](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/docs/OPENCLAW_GATEWAY_NODE_EXEC_FAQ.md) · [OpenClaw 2.0 소개](https://openclaw.ai/podcast/episode-9) · [Hub 로컬 MCP 모드](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/docs/MCP_MODE.md) · [MXC 지원 판정](../solutions/mxc.md#openclaw-windows-hub의-지원-판정)

## 실측에서 확인할 항목

- `openclaw sandbox explain`으로 세션의 유효 모드, 백엔드, 스코프, 마운트를 기록합니다. Gateway 직접 실행, Gateway 도구 MXC, Windows 노드 MXC, Store 네이티브 Gateway 세션을 별도 조건으로 기록합니다.
- Gateway 플러그인과 노드 MXC의 네트워크·파일 정책을 각각 검증합니다. Gateway와 노드에 서로 다른 합성 파일을 두어 실제 실행 위치를 확인합니다.
- 노드 MXC 호환성, 자식 실행 가능 여부, 정책이 허용하는 호환 실행 여부를 구분합니다. Windows Hub 및 Gateway 버전과 설치 경로를 함께 남깁니다.
