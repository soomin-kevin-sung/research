# Windows에서 코딩 에이전트는 어디까지 격리되나

## 핵심 결론

**작업 폴더를 보호할 수 있는지, 필요한 개발 작업이 돌아가는지, 셸 밖 도구에도 같은 제한이 적용되는지를 각각 확인해야 합니다.** Windows에서 직접 실행하는 에이전트 7종을 조사했습니다. 아래 결과는 공식 문서와 릴리스 소스에 근거하며, 실제 차단 동작과 작업 성공률·성능은 측정 전입니다. [서비스별 조사 범위와 버전](README.md#windows-서비스별-조사)

| 확인할 질문 | 조사에서 확인한 답 |
| --- | --- |
| 작업 폴더 안의 민감한 하위 폴더만 잠글 수 있나? | 실행 방식마다 다릅니다. Codex MXC는 지원되는 PC에서 하위 경로를 별도로 제한할 수 있습니다. OpenClaw Gateway의 MXC 플러그인은 사용자가 지정한 파일 거부 규칙을 제공하지 않습니다. QwenPaw 일부 경로는 초기 설정 때 존재하는 폴더에 거부 규칙을 적용합니다. |
| 파일을 읽고 쓸 수 있으면 빌드와 테스트도 되나? | 병렬 빌드, 디버거, 개발 서버는 프로세스 간 통신과 로컬 포트 또는 백그라운드 실행이 필요합니다. 파일 검사를 통과해도 각각 실패할 수 있습니다. |
| 셸의 인터넷을 막으면 에이전트의 모든 연결도 막히나? | Codex의 로컬 명령 프록시와 웹 검색·MCP·브라우저의 연결에는 별도 정책이 적용됩니다. 관리형 네트워크 설정에서는 같은 PC의 로컬 서비스 접근도 확인해야 합니다. |
| 격리를 적용할 수 없으면 명령은 어떻게 되나? | 경로에 따라 명령을 시작하지 않거나, 승인 후 Windows 사용자 권한으로 실행합니다. 어떤 방식으로 실행됐는지 남겨야 보안 결과를 해석할 수 있습니다. |

[실행 경로 비교](research/README.md) · [상세 근거와 제품별 제약](research/security-boundaries.md)

**승인 후에도 같은 권한으로 실행되는지는 제품마다 다릅니다.** OpenClaw Hub는 명령 승인 후에도 Windows 격리 정책을 확인합니다. Codex는 권한 확대를 승인할 수 있지만, 조사 버전의 소스상 명시적 파일 읽기 거부가 있으면 샌드박스를 유지합니다. QwenPaw에는 일반 샌드박스 차단 후 별도 인간 승인으로 격리 없이 다시 시도하는 경로가 있습니다. [에이전트 7종의 승인 정책 비교](research/approval-policies.md)

## 사례

### 작업 폴더 안의 특정 폴더만 잠근다

에이전트에 프로젝트 수정 권한은 주되 그 안의 자격 증명 폴더는 보호해야 하는 경우입니다. **읽기 전용이라면 내용은 여전히 읽을 수 있습니다.** 내용까지 보호하려면 접근 거부가 필요합니다. Windows에서는 부모 폴더 권한이 삭제·이름 변경에 관여할 수 있으므로, 내용 읽기·쓰기와 함께 이름 표시·삭제·이름 변경도 따로 확인합니다. [Windows 파일 권한](https://learn.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants) · [삭제 및 이름 변경 규칙](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-deletefilew#remarks)

| 실행 경로 | 하위 폴더 보호 |
| --- | --- |
| **Codex MXC** | 지원되는 PC에서는 더 구체적인 하위 경로 규칙을 적용합니다. PC가 요청한 거부 기능을 지원하지 않으면 실행 전에 실패합니다. 패턴으로 지정한 거부는 명령 시작 때 존재하는 일치 항목을 기준으로 하며, 하드 링크에는 파일 이름별 권한이 유지됩니다. |
| **OpenClaw Gateway MXC** | 사용자 지정 파일 거부 규칙을 제공하지 않습니다. 쓰기 허용 범위가 제품이 보호하는 스킬 폴더와 겹치면 명령 시작을 거부합니다. Windows Hub의 노드 실행은 별도이며, 지정된 보호 경로에 Windows의 네이티브 거부를 요구합니다. |
| **QwenPaw AppContainer·관리자 제한 토큰** | 초기 설정 때 경로가 이미 있으면 거부 ACL을 설정합니다. 경로가 없으면 건너뛰고, 소스상 호출부에서 ACL 설정 성공 여부를 확인하지 않습니다. 비관리자 제한 토큰은 기본 실행 경로에서 읽기 거부를 집행하지 않습니다. |

[Codex MXC 소스](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/mxc-sandbox/README.md) · [OpenClaw Gateway](https://github.com/openclaw/openclaw/blob/v2026.11.6/extensions/mxc/README.md) · [Windows Hub](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/docs/OPENCLAW_GATEWAY_NODE_EXEC_FAQ.md) · [QwenPaw 경로별 근거](research/security-boundaries.md#상위-폴더-허용과-하위-폴더-보호)

### 파일은 열리지만 빌드나 개발 서버가 멈춘다

- **병렬 빌드와 디버깅.** 이전 Codex MXC 버전에서 단일 작업자 빌드는 성공했지만 병렬 MSBuild와 진단 연결이 실패했다는 공개 보고가 있습니다. 프로세스 간 통신에 쓰는 명명된 파이프가 관련된 것으로 보고됐으며, 원인과 조사 기준 버전인 `0.171.0`에서의 재현 여부는 확인되지 않았습니다. [MSBuild 병렬 실행 구조](https://learn.microsoft.com/en-us/visualstudio/msbuild/build-process-overview) · [공개 호환성 보고](https://github.com/openai/codex/issues/60794)
- **개발 서버와 파일 변경 감시.** Codex MXC는 전경 명령이 끝나면 남은 자식 프로세스도 종료합니다. 셸 명령이 반환된 뒤에도 서버나 워처가 계속 살아 있어야 하는 작업은 이 동작의 영향을 받습니다. [Codex Windows 샌드박스](https://learn.chatgpt.com/docs/windows/windows-sandbox#mxc-compatibility)
- **Windows 앱과 사용자별 설정.** 창 조작, 입력, 클립보드에는 각각 별도 권한이 필요합니다. AppContainer나 별도 계정에서 실행하면 기존 Windows 사용자 프로필의 레지스트리 설정이나 로그인 상태를 읽는 도구도 따로 확인해야 합니다. [MXC UI 정책](https://github.com/microsoft/mxc/blob/main/docs/backends/process-container/UIPolicy_Schema.md) · [Microsoft AppContainer 격리](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)

### 셸을 제한해도 별도 연결과 권한이 남는다

- **같은 PC의 서비스.** Codex MXC의 관리형 네트워크는 호스트 루프백을 허용합니다. 같은 PC의 로컬 DB나 개발 API를 보호해야 한다면 외부 인터넷 차단과 별개로 접근 결과를 확인해야 합니다. [Codex MXC 소스](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/mxc-sandbox/README.md)
- **MCP·웹 검색·브라우저.** Codex의 로컬 명령 프록시는 이러한 도구나 Computer Use에 공통 적용되지 않습니다. 도구별 실행 위치와 유효 정책을 따로 확인해야 합니다. [Codex 도구별 통신 범위](https://learn.chatgpt.com/docs/agent-approvals-security#traffic-outside-the-command-network-proxy)
- **환경 변수·자원 한도.** 조사한 QwenPaw Windows 버전은 환경 변수 허용 목록과 프로세스 수·메모리 한도를 집행하지 않습니다. 설정에 값이 있다는 사실만으로 민감한 변수가 숨겨지거나 자원 사용량이 제한된다고 판단할 수 없습니다. [QwenPaw 구현 제약](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/website/public/docs/security.en.md#current-limitations)

### 격리 환경을 시작할 수 없는 PC에서 명령을 실행한다

**시작 거부**는 작업이 멈췄다는 뜻입니다. **비격리 실행**은 작업이 호스트 계정 권한으로 진행됐다는 뜻입니다. OpenClaw Windows Hub는 일반적인 정책·SDK·실행 오류에서는 시작을 차단하며, Windows 자체가 미지원으로 확정된 경우 승인된 비격리 실행 경로가 있습니다. OpenHuman 안정판의 Windows 로컬 셸은 TinyBox가 Windows 격리 백엔드를 선택하지 않아 호스트에서 실행됩니다. [Windows Hub 실패 처리](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/docs/OPENCLAW_GATEWAY_NODE_EXEC_FAQ.md) · [OpenHuman의 TinyBox 경로](research/solutions/tinybox.md)

### 같은 “항상 허용”을 눌러도 저장되는 범위가 다르다

OpenClaw Hub V2가 새 승인에 저장하는 단위는 실행 파일과 인수입니다. Hermes는 명령 패턴을, OpenHuman의 일반 승인은 도구 이름을 기억합니다. 공유 채팅에서 누구에게 승인 권한이 있는지도 별도 설정입니다. 실측에서는 승인 주체, 이번 요청에만 적용되는지, 다음 실행에도 재사용되는지를 기록합니다. [제품별 승인 및 저장 범위](research/approval-policies.md#핵심-결론)

## 배경지식

**명령 승인**은 에이전트가 명령을 시작해도 되는지 결정하는 단계입니다. **OS 샌드박스**는 시작된 명령이 실제로 어디에 접근할 수 있는지 Windows가 제한하는 방식입니다. 예를 들어 사용자가 빌드를 승인해도 샌드박스는 빌드 도구의 프로젝트 밖 파일 쓰기를 차단할 수 있습니다. [도구 승인과 호스트 셸](research/solutions/tool-approval.md)

| 용어 | 쉽게 말하면 |
| --- | --- |
| **MXC ProcessContainer** | 명령과 그 자식 프로세스가 파일·네트워크에 접근하는 범위를 Windows에서 제한합니다. |
| **MXC IsolationSession** | 서비스나 작업을 별도 Windows 계정과 세션에서 실행합니다. 예를 들어 OpenClaw 서비스가 이 세션에서 실행되더라도 그 서비스가 시작하는 개별 도구의 정책은 별도로 확인합니다. |
| **AppContainer** | Windows가 앱에 전용 보안 식별자와 허용 기능을 부여해 파일·레지스트리·네트워크 접근을 제한합니다. |
| **제한 토큰·ACL·WFP** | 토큰은 프로그램이 어떤 권한으로 실행되는지, ACL은 파일이나 레지스트리를 누가 사용할 수 있는지, WFP는 어떤 네트워크 연결을 차단할 수 있는지를 정합니다. |
| **루프백·명명된 파이프·MCP** | 루프백은 같은 PC의 서비스에 연결하는 네트워크 경로입니다. 명명된 파이프는 프로그램끼리 통신하는 Windows 기능입니다. MCP는 에이전트가 별도 도구나 서비스에 연결할 때 사용하는 방식입니다. |

[격리 기술 문서](research/README.md#격리-기술과-기준-동작) · [Windows 명명된 파이프](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)

## 실측에서 확인할 것

조사 범위는 Windows 호스트에서 직접 실행되는 명령과 파일 작업입니다. WSL2, Linux 컨테이너, 별도 VM과 원격 실행은 제외했습니다. Claude Code, Hermes Agent, OpenCode와 조사 버전의 OpenHuman 로컬 실행은 Windows 호스트 계정의 기준 동작에 포함했습니다. [서비스별 비교표](README.md#windows-서비스별-조사)

1. **보호 범위.** 허용한 작업은 성공하고 금지한 파일·포트·별도 도구 접근은 차단되는지 확인합니다.
2. **작업 호환성.** 필요한 자원이 막혀 빌드, 테스트, 개발 서버가 실패하는지 확인합니다.
3. **비용과 운영.** 시작·작업 시간, 메모리, 성공률, 설정에 필요한 권한을 같은 호스트에서 비교합니다.

측정에는 합성 파일과 통제된 서비스를 사용하고, Windows 빌드·실행 계정·실제 백엔드·권한 정책을 함께 남깁니다. [실측 프로토콜](protocol.md) · [실행 기록 양식](../../templates/run.md)
