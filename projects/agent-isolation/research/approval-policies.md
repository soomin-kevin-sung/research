# 승인 정책과 Windows 샌드박스의 연결

## 핵심 결론

- **승인자가 결정하는 것은 명령을 시작해도 되는지, 또는 특정 예외를 허용할지입니다.** 실제 파일·네트워크 권한은 어느 Windows 계정과 샌드박스로 실행했는지에 따라 달라집니다. 관리자 권한으로 샌드박스를 설치하는 절차도 명령별 사용자 승인과 별개입니다. [Codex 승인과 보안](https://learn.chatgpt.com/docs/agent-approvals-security) · [OpenClaw 승인과 실행 경로](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/docs/OPENCLAW_GATEWAY_NODE_EXEC_FAQ.md)
- **샌드박스가 거부한 뒤의 동작이 가장 큰 차이입니다.** OpenClaw Hub는 승인 후에도 전체 MXC 정책을 집행할 수 있는지 확인합니다. Codex는 승인 유형과 정책에 따라 권한을 넓힐 수 있지만, 조사 버전의 소스는 명시적 파일 읽기 거부가 있으면 샌드박스를 유지합니다. QwenPaw에는 일반적인 샌드박스 차단 후 별도 인간 승인으로 격리 없이 재시도하는 경로가 있습니다. [OpenClaw Hub](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/docs/OPENCLAW_GATEWAY_NODE_EXEC_FAQ.md) · [Codex 권한 처리 소스](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/core/src/tools/sandboxing.rs) · [QwenPaw 도구 어댑터](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/governance/tool_adapter.py)
- **같은 “항상 허용”이라도 기억하는 단위가 다릅니다.** OpenClaw Hub V2가 새로 저장하는 규칙은 실행 파일과 인수에 묶입니다. Hermes는 명령 패턴을 기억하고, OpenHuman의 일반 승인은 도구 이름을 저장합니다. OpenCode는 조사 버전의 V1과 온라인 V2 문서에서 저장 방식이 다릅니다. [OpenClaw Hub V2](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/docs/OPENCLAW_GATEWAY_NODE_EXEC_FAQ.md) · [Hermes 승인](https://github.com/NousResearch/hermes-agent/blob/v0.23.3/website/docs/user-guide/security.md) · [OpenHuman 승인](https://github.com/tinyhumansai/openhuman/blob/v0.64.15/gitbooks/features/approval-gate.md) · [OpenCode V1](https://github.com/anomalyco/opencode/blob/v1.19.6/packages/opencode/src/permission/index.ts) · [OpenCode V2](https://opencode.ai/docs/permissions/)

## 에이전트별 비교

조사 기준 버전의 Windows 네이티브 셸과 로컬 실행 경로를 비교합니다. 공식 온라인 문서가 릴리스 소스와 다른 세대를 설명할 때는 따로 표시했습니다. 결과는 문서·소스 조사이며 실제 승인 UI나 Windows 프로세스에서 관찰한 결과는 아직 없습니다. [조사 버전](../README.md#windows-서비스별-조사)

| 제품 | 승인 정책은 어떻게 운용하나 | 승인 후 어디에서 실행하나 |
| --- | --- | --- |
| [Codex](agents/codex.md) | `approval_policy`로 승인 요청 시점을 정하고, 사용자가 답하거나 `auto_review`에서 심사합니다. `never`에서는 추가 승인 요청을 띄우지 않습니다. 명령 규칙과 추가 권한 요청도 각각 심사할 수 있습니다. | 일반 명령은 유효 권한 프로필을 Windows 백엔드에 전달합니다. 정책이 허용하는 권한 확대에는 샌드박스 밖 실행 경로도 있습니다. 조사 버전은 명시적 파일 읽기 거부를 보존해야 할 때 네이티브 샌드박스를 요구합니다. |
| [OpenClaw](agents/openclaw.md) | Gateway는 실행 위치와 위험 정책을 결정합니다. 노드 실행에는 Windows Hub 소유자의 V2 승인이 독립적으로 적용됩니다. Hub 기본은 허용 목록, 미일치 시 질문, 응답 UI를 제공할 수 없을 때 거부입니다. | Gateway 도구 MXC와 노드 MXC는 별개입니다. Hub는 승인한 실행 파일과 인수를 전달하고, 실행 직전 정책과 MXC 적용 가능성을 확인합니다. |
| [QwenPaw](agents/qwenpaw.md) | 거버넌스가 도구·인수와 위험 신호를 평가해 허용·거부·질문·샌드박스 실행 중 하나를 결정합니다. 일부 위험 판정에는 판단 모델이 관여하고, 인간 승인 요청은 승인 서비스가 처리합니다. | 샌드박스 실행 분기에서 생성한 구성을 Windows 백엔드에 전달합니다. 일반 위반 후 별도 승인 재시도와 모델이 샌드박스 실행만 승인한 경우의 동작이 다릅니다. |
| [Claude Code](agents/claude-code.md) | 도구별 `deny`, `ask`, `allow` 순서로 규칙을 평가합니다. 기본 대화형 모드는 주로 사용자에게 묻고, 사용 가능한 `auto` 모드에서는 분류기가 판단합니다. `dontAsk`에서는 평소 확인이 필요한 호출을 거부하는 것이 기본입니다. | Windows 네이티브 셸 승인 뒤에는 Windows 실행 계정 권한이 적용됩니다. Bash·PowerShell 규칙과 내장 파일 도구 규칙은 제품의 사전 검사입니다. |
| [Hermes Agent](agents/hermes.md) | `smart`는 위험 패턴에 걸린 요청을 보조 모델이 심사하고 불확실하면 사용자에게 묻습니다. `manual`은 위험 명령을 사용자에게 묻습니다. 승인 범위는 1회·세션·영구 패턴이며, 무인 실행은 호출 유형에 맞는 별도 기본 거부 설정을 사용합니다. | 사전 검사가 이미 선택된 터미널 백엔드를 고려합니다. 승인 결과가 백엔드를 바꾸지는 않으며, Windows 기본 `local`은 호스트 계정으로 실행합니다. |
| [OpenCode](agents/opencode.md) | 안정판 V1의 `permission`은 마지막 일치 규칙을 사용합니다. 셸을 분석해 외부 경로와 명령을 사전 심사합니다. `once`는 현재 요청, `always`는 실행 인스턴스의 승인 패턴 목록에 추가합니다. | 승인 뒤 Windows 셸을 호스트 권한으로 시작합니다. 온라인 V2는 `permissions`와 프로젝트 단위의 지속 승인 규칙을 설명하므로 V1의 승인 저장 방식과 구분합니다. |
| [OpenHuman](agents/openhuman.md) | 일반 자율성 정책은 기본 꺼짐입니다. 켜면 `readonly`는 쓰기를 차단하고, 기본 등급 `supervised`는 쓰기 등에서 질문하며, `full`도 네트워크·설치·파괴적 작업은 질문합니다. 일반 게이트의 항상 허용은 도구 이름 단위입니다. | 승인 게이트와 샌드박스 선택은 별개입니다. 런타임과 세션 출처가 실행 경로를 정하며, 조사 버전 Windows 로컬의 TinyBox는 OS 격리 백엔드를 선택하지 않습니다. |

## 연결 방식과 운영상 차이

### Codex와 OpenClaw에서 승인 후 남는 제한

Codex에서는 `approval_policy`가 질문 시점을, `approvals_reviewer`가 질문을 받을 주체를, 권한 프로필이 파일과 네트워크 범위를 정합니다. 고정 소스에는 실행 관리자가 일반·확대 실행을 구분한 후 Windows 백엔드를 선택하고, MXC 실행기에 권한 프로필과 명령을 함께 전달하는 경로가 있습니다. 특정 실행 규칙의 허용 판정은 정책이 허용하는 경우 샌드박스 밖 실행을 뜻할 수 있습니다. 읽기 거부가 설정되어 있을 때는 그 제한을 유지하는 경로를 사용하며, 이를 집행할 수 있는 샌드박스가 없으면 거부합니다. 명령 실패가 자동으로 다른 Windows 백엔드를 고른다는 의미는 아닙니다. [Codex 설정 레퍼런스](https://learn.chatgpt.com/docs/config-file/config-reference) · [0.171.0 실행 순서](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/core/src/tools/orchestrator.rs) · [권한 확대와 거부 보존](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/core/src/tools/sandboxing.rs) · [MXC 실행 계약](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/mxc-sandbox/README.md)

OpenClaw Gateway는 요청 정책과 실행 호스트 정책을 합칠 때 더 엄격한 값을 사용합니다. 노드로 전달된 명령은 Gateway의 통과 여부와 별개로 Hub에서 검사를 받습니다. Hub V2는 실행 파일의 절대 경로와 인수에 승인을 묶고, 직전에 정책을 다시 확인합니다. 승인 대기 중 정책이 변경되면 해당 승인은 무효입니다. SDK·정책·실행 오류는 차단하며, Windows 미지원이 확인된 경우의 승인된 호스트 호환 실행은 별도 경로입니다. Gateway의 권한 확대 기능도 별도 정책이며, 격리가 필수인 역할 세션에서는 Gateway 샌드박스 밖으로 나갈 수 없습니다. [Windows Hub의 실행·승인 순서](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/docs/OPENCLAW_GATEWAY_NODE_EXEC_FAQ.md) · [Gateway 권한 확대 정책](https://github.com/openclaw/openclaw/blob/v2026.11.6/docs/tools/elevated.md)

### QwenPaw에서 도구 규칙이 Windows 권한으로 바뀌는 지점

QwenPaw는 샌드박스 실행의 파일 범위를 만들 때 작업 영역과 사용자 파일 도구 규칙을 참조합니다. 고정 소스의 변환 루프는 규칙의 도구 종류와 경로를 바탕으로 읽기·쓰기 범위를 만들며, 해당 루프에서 규칙의 허용·거부 여부를 확인하지 않습니다. 민감 경로 거부는 별도 목록으로 전달합니다. 따라서 파일 도구에서 거부로 표시된 경로가 셸에서도 차단되는지는 유효 Windows 정책에서 확인해야 합니다. 또한 문서 주석에는 사용 불가 시 질문한다고 적힌 부분이 있지만, 고정 버전의 실행 분기는 일반 샌드박스 실행 판정을 `ALLOW`로 바꾸는 경로를 갖습니다. 적용 조건과 유효 실행 환경을 따로 확인할 항목입니다. [2.3.0.post1 판정 및 구성 생성 소스](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/governance/resource_governor.py)

일반 샌드박스 거부 결과를 받은 어댑터는 사용자에게 다시 질문할 수 있습니다. 그 승인이 나면 격리 구성을 전달하지 않고 호출을 재시도하는 분기가 있습니다. 판단 모델의 결정이 샌드박스 실행을 전제로 한 경우에는 이 재시도 분기로 넘어가지 않습니다. 일반 승인에서 정확한 대상 또는 유사 대상 규칙이 추가될 수 있고, 판단 모델에서 유래한 승인에는 해당 호출만 적용되는 분기가 있습니다. 거부나 승인 대기 만료는 호출을 차단합니다. [2.3.0.post1 승인·재시도 소스](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/governance/tool_adapter.py)

### 호스트 셸에서 승인 정책이 적용되는 범위

- **Claude Code.** `deny`와 `ask`가 `allow`보다 먼저 처리됩니다. 온라인 권한 문서는 PowerShell 복합 명령의 구성 요소를 각각 평가한다고 설명합니다. 승인된 프로그램이 실행 중 요청하는 OS 권한은 별개입니다. [권한 규칙과 PowerShell](https://code.claude.com/docs/en/permissions) · [샌드박스 지원 범위](https://code.claude.com/docs/en/sandboxing)
- **Hermes Agent.** 사람에게 질문하는 경우 CLI와 메시징 채널의 전달 방식이 다릅니다. 공유 채팅의 기본 `approvers`는 입장한 구성원이 응답할 수 있게 하며, 호출자·관리자·지정 사용자 조건으로 좁힐 수 있습니다. 터미널 코드는 명령 실행 전에 선택한 환경 정보를 승인 검사에 사용합니다. [0.23.3 승인 운영](https://github.com/NousResearch/hermes-agent/blob/v0.23.3/website/docs/user-guide/security.md) · [터미널 실행 소스](https://github.com/NousResearch/hermes-agent/blob/v0.23.3/tools/terminal_tool.py)
- **OpenCode.** 안정판 V1은 외부 경로 검사와 셸 명령 검사를 각각 호출합니다. 이 검사에서 계속 진행할 수 있게 되면 호스트의 Windows 자식 프로세스를 시작합니다. [1.19.6 승인 서비스](https://github.com/anomalyco/opencode/blob/v1.19.6/packages/opencode/src/permission/index.ts) · [1.19.6 셸 소스](https://github.com/anomalyco/opencode/blob/v1.19.6/packages/opencode/src/tool/shell.ts)
- **OpenHuman.** 일반 자율성 정책을 켜면 웹 채팅 등에서 승인 대기 항목을 보여 줍니다. 일반 요청의 대기 만료는 문서상 10분이며 거부로 끝납니다. CLI와 신뢰된 자동화 등 출처에 따라 일반 게이트에서 대기하지 않는 경로도 문서화돼 있습니다. 브라우저의 강제 1회 승인은 로컬 셸과 별개의 도구 정책입니다. [0.64.15 승인 게이트](https://github.com/tinyhumansai/openhuman/blob/v0.64.15/gitbooks/features/approval-gate.md) · [Windows 로컬 실행](solutions/tinybox.md)

## 실측에서 남길 값

프롬프트가 표시됐는지와 최종 실행 권한을 따로 적습니다. 최초 판정, 승인 주체와 저장 범위, 응답 없음이나 정책 변경의 처리, 프로세스 시작 여부, 실제 백엔드와 계정을 남깁니다. 일반 실행의 성공과 승인된 재시도의 성공은 구분합니다. [승인 확인 항목](../protocol.md#승인과-실행-권한)
