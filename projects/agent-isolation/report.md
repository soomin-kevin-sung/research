# Windows 네이티브 에이전트 샌드박스 조사 보고서

## 핵심 결론

1. **같은 Windows PC에서도 실제 실행 경로에 따라 격리 범위가 달라집니다.** Codex의 MXC, OpenClaw Gateway의 MXC 플러그인, Windows Hub의 노드 실행, Store Gateway의 IsolationSession은 각각 다른 경계를 적용합니다. 환경 이름보다 실제 백엔드, 실행 계정, 권한 프로필을 확인해야 합니다. [Windows 실행 경로 비교](research/README.md)
2. **상위 폴더를 열어 두고 하위 폴더만 보호하려면 읽기·쓰기·삭제·이름 변경을 각각 확인해야 합니다.** Codex MXC는 지원 호스트에서 하위 경로 거부를 표현할 수 있습니다. OpenClaw Gateway 플러그인은 사용자 지정 파일 거부를 노출하지 않으며, 일부 보호 경로가 쓰기 허용과 충돌하면 시작을 거부합니다. QwenPaw는 경로와 ACL 설정 시점에 따라 거부 규칙이 실제로 적용되는지 확인해야 합니다. [제품별 하위 경로 검토](research/security-boundaries.md#상위-폴더-허용과-하위-폴더-보호)
3. **파일 보호가 작동해도 정상 작업을 막거나 다른 통신을 허용할 수 있습니다.** 병렬 빌드에는 프로세스 간 통신이 필요하고, 개발 서버에는 로컬 포트와 프로세스 수명이 중요합니다. 반대로 호스트 루프백, MCP, 브라우저, 사용자 프로필은 파일 정책이나 명령 프록시와 별도로 접근할 수 있는지 확인해야 합니다. [파일 외 자원 검토](research/security-boundaries.md#파일-외-자원과-작업-호환성)
4. **현재 근거는 문서·릴리스 소스·공개 호환성 보고입니다.** Windows 호스트에서의 접근 차단, 작업 성공률, 성능 비용은 아직 측정하지 않았습니다. 조사한 방식의 보안 순위나 안전성 보장은 실측 이후에도 검증한 구성과 정책에 한정됩니다. [실측 프로토콜](protocol.md) · [결과 및 판단](findings.md)

## 사례

### 작업 폴더를 열어 두면서 민감한 하위 폴더를 보호하려는 경우

에이전트가 프로젝트 파일을 읽고 수정해야 하지만, 같은 프로젝트 안의 설정이나 시험용 자격 증명 폴더에는 접근하면 안 되는 상황입니다. 이때 하위 폴더를 **읽기 전용**으로 지정하면 변경을 막을 수 있어도 내용은 여전히 읽을 수 있습니다. **접근 거부**가 필요한 데이터라면 파일 내용 접근과 함께 이름 노출, 삭제, 이름 변경을 따로 판정해야 합니다. Windows에서는 파일의 삭제·이름 변경에 부모 폴더의 자식 삭제 권한도 관여합니다. [Microsoft 파일 접근 권한](https://learn.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants) · [삭제 권한 규칙](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-deletefilew#remarks)

- **Codex MXC**는 지원되는 호스트에서 더 구체적인 하위 경로 정책을 적용합니다. 네이티브 파일 거부 기능이 필요한데 호스트가 이를 지원하지 않으면 명시적 거부 요청은 시작 전에 실패합니다. 거부 글롭은 시작 시점의 일치 항목에 적용되고, 하드 링크의 경로별 권한에 관한 제약도 소스에 명시돼 있습니다. [Codex 0.171.0 MXC 구현](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/mxc-sandbox/README.md) · [Codex Windows 샌드박스](https://learn.chatgpt.com/docs/windows/windows-sandbox#mxc-compatibility)
- **OpenClaw Gateway MXC**는 조사 버전에서 사용자 지정 하위 경로 거부를 제공하지 않습니다. 쓰기 허용 경로가 제품이 보호하는 스킬 폴더와 겹치면 명령을 시작하지 않습니다. **Windows Hub의 노드 실행**은 별개이며 지정된 보호 경로의 네이티브 거부를 요구합니다. [Gateway 플러그인](https://github.com/openclaw/openclaw/blob/v2026.11.6/extensions/mxc/README.md) · [Windows Hub 실행 정책](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/docs/OPENCLAW_GATEWAY_NODE_EXEC_FAQ.md)
- **QwenPaw AppContainer와 관리자 제한 토큰**은 초기 설정 때 이미 존재하는 거부 경로에 Windows ACL을 적용합니다. 두 구현 모두 해당 경로가 없으면 건너뛰고, 거부 ACL 설정의 성공 반환값을 호출부에서 검사하지 않습니다. 비관리자 제한 토큰의 기본 실행 경로는 읽기 거부를 강제하지 않습니다. [AppContainer 소스](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_appcontainer_sandbox.py) · [관리자 경로](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_elevated_sandbox.py) · [비관리자 경로](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_unelevated_sandbox.py)

### 파일은 읽히지만 빌드나 개발 서버가 동작하지 않는 경우

병렬 빌드와 진단 도구는 다른 프로세스와 데이터를 주고받을 수 있어야 합니다. 이전 Codex MXC 버전에서 단일 작업자 빌드는 성공했지만 병렬 MSBuild와 진단 연결이 실패했다는 공개 보고가 있습니다. 명명된 파이프가 관련된 것으로 보고됐으며 조사 기준 버전에서의 재현 여부와 원인은 확인되지 않았습니다. Codex MXC가 전경 명령 종료 시 남은 자식 프로세스를 종료하는 동작은 공식 문서에 명시되어 있으므로, 셸 명령이 끝난 뒤에도 계속 실행돼야 하는 서버나 워처는 별도 호환성 조건입니다. [MSBuild 병렬 실행 구조](https://learn.microsoft.com/en-us/visualstudio/msbuild/build-process-overview) · [공개 호환성 보고](https://github.com/openai/codex/issues/60794) · [Codex Windows 샌드박스](https://learn.chatgpt.com/docs/windows/windows-sandbox#mxc-compatibility)

### 셸의 네트워크는 제한했지만 다른 연결이 열려 있는 경우

Codex MXC의 관리형 네트워크는 그 구성에서 호스트 루프백을 허용합니다. 로컬 DB나 서비스가 경계 안에 들어가는지는 따로 판단해야 합니다. 로컬 명령 프록시의 정책은 MCP, 웹 검색, 브라우저, Computer Use에 공통 적용되지 않습니다. QwenPaw Windows에서는 환경 변수 허용 목록과 프로세스 수·메모리 한도가 집행되지 않으므로, 해당 설정이 있다는 이유만으로 노출과 과점유가 차단된다고 판단할 수 없습니다. [Codex 도구별 통신 범위](https://learn.chatgpt.com/docs/agent-approvals-security#traffic-outside-the-command-network-proxy) · [Codex MXC 구현](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/mxc-sandbox/README.md) · [QwenPaw 구현 제약](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/website/public/docs/security.en.md#current-limitations)

### Windows가 샌드박스를 시작할 수 없는 경우

실행 전에 정책 적용을 거절하면 해당 작업이 중단됩니다. 호환 실행을 선택하면 명령이 시작되지만 기존 격리 요구는 충족되지 않을 수 있습니다. 예를 들어 OpenClaw Windows Hub는 정책·SDK·실행 오류를 차단하며, Windows 자체가 미지원으로 확정된 경우에는 승인된 비격리 호환 경로를 문서화합니다. OpenHuman 안정판의 Windows 로컬 경로는 TinyBox가 Windows jail을 선택하지 않아 비격리 백엔드에서 실행됩니다. 이 경우 실행 성공 여부와 실제 백엔드를 함께 기록해야 합니다. [Windows Hub 실패 처리](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/docs/OPENCLAW_GATEWAY_NODE_EXEC_FAQ.md) · [OpenHuman의 TinyBox 실행 경로](research/solutions/tinybox.md)

## 배경지식

**에이전트의 명령 승인**은 애플리케이션이 명령을 시작할지 결정하는 단계입니다. **OS 샌드박스**는 시작된 프로세스가 어떤 파일이나 포트에 접근할 수 있는지 Windows에서 제한합니다. 예를 들어 사용자가 셸 명령을 승인해도 OS 정책은 파일 쓰기를 차단할 수 있습니다. Windows 네이티브에서 파일 도구, 셸, MCP, 브라우저가 서로 다른 프로세스나 계정으로 동작하면 승인과 격리도 실행 경로마다 확인해야 합니다. [도구 승인과 호스트 셸](research/solutions/tool-approval.md)

| 용어 | 이 조사에서의 의미 |
| --- | --- |
| MXC ProcessContainer | Microsoft SDK가 Windows의 프로세스 격리 기능으로 명령과 자식 프로세스에 파일·네트워크 등의 정책을 적용하는 방식입니다. 제품이 사용하는 SDK와 Windows 기능에 따라 실제 정책이 달라집니다. |
| MXC IsolationSession | 별도 Windows 계정과 세션에 서비스나 작업을 배치하는 방식입니다. OpenClaw Store Gateway의 배치 경계가 이에 해당하며, 개별 도구 실행 경계는 별도로 확인합니다. |
| AppContainer | Windows가 앱에 전용 보안 식별자와 허용 기능을 부여해 파일, 레지스트리, 네트워크 등에 대한 접근을 통제하는 방식입니다. |
| 제한 토큰·ACL·WFP | 토큰은 프로세스의 실행 권한을 정합니다. ACL은 파일이나 레지스트리 같은 객체의 접근 규칙이고, WFP는 Windows의 네트워크 필터링 계층입니다. 세 기능이 어떤 조합으로 적용되는지에 따라 결과가 달라집니다. |
| 루프백·명명된 파이프 | 루프백은 같은 PC의 서비스에 네트워크로 연결하는 경로입니다. 명명된 파이프는 프로그램끼리 데이터를 주고받는 Windows 통신 수단이며, 병렬 빌드와 진단 도구도 사용할 수 있습니다. |

[Windows 기술 목록](research/README.md#격리-기술과-기준-동작) · [Microsoft 명명된 파이프 권한](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)

## 조사 범위와 실측 계획

Windows 호스트에서 직접 실행되는 명령과 파일 작업을 중심으로 7개 에이전트를 조사했습니다. Codex, OpenClaw, QwenPaw는 Windows 격리 백엔드별로 기록했습니다. Claude Code, Hermes Agent, OpenCode 및 조사 버전의 OpenHuman Windows 로컬 실행은 호스트 계정에서 어떤 일이 가능한지 관찰할 기준에 포함했습니다. WSL2, Linux 컨테이너, 외부 VM과 원격 실행은 이번 비교 범위에서 제외했습니다. [서비스별 조사 버전과 범위](README.md#windows-서비스별-조사)

같은 Windows 호스트에서 합성 파일과 통제된 서비스로 일반 작업의 성공과 보호 정책의 적용을 각각 확인합니다. 측정값은 실제 백엔드, Windows 빌드, 실행 계정, 권한 정책과 함께 기록합니다. 호환성 시험에서 정상 작업이 막힌 결과와 접근 시험에서 금지된 자원이 허용된 결과를 구분합니다. 시작·작업 시간, 최대 메모리, 성공률과 운영 부담은 실제 실행 기록이 생긴 뒤 비교합니다. [실측 프로토콜](protocol.md) · [실행 기록 양식](../../templates/run.md)
