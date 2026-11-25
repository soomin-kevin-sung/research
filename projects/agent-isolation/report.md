# Windows에서 코딩 에이전트는 어디까지 격리되나

Windows에서 직접 실행하는 에이전트 7종을 공식 문서와 릴리스 소스로 조사했습니다. 그중 Restricted Token을 쓰는 네 구성과 QwenPaw의 AppContainer를 실제 PC에서 측정했습니다. MXC BaseContainer는 측정하지 않았습니다. 프로젝트는 2026-11-25에 종료했습니다. [서비스별 조사 범위와 버전](README.md#windows-서비스별-조사) · [질문별 결과와 근거](findings.md)

## 핵심 결론

**실측한 Restricted Token 네 구성은 쓰기를 막고, 읽기는 토큰의 계정이 읽을 수 있는 만큼 허용합니다.** 신뢰하는 에이전트가 실수로 작업 폴더 밖에 쓰는 일은 줄입니다. 신뢰하지 않는 코드를 가두는 보안 경계로는 네 구성 모두 부족합니다.

측정한 구성은 QwenPaw `2.3.0.post1`의 비관리자·관리자와 Codex CLI `0.172.0`의 `unelevated`·`elevated`입니다. 대부분의 항목을 5회 측정했고, 횟수가 다른 항목은 결과 표에 적었습니다. [사례 19개로 보는 결과](report-token-backends/index.html) · [결과 표와 판단](findings.md#restricted-token-네-구성-실측-2026-11-25)

### 막힌 것

네 구성 모두 다음을 거부했습니다.

- 사용자만 쓰기를 허용한 파일·폴더와 다른 작업 폴더에 쓰기.
- 사용자 레지스트리(`HKCU`)와 `HKLM\SOFTWARE`에 쓰기.
- 사용자 프로세스를 메모리 쓰기·스레드 생성 권한으로 열기.
- 호스트가 만든 명명된 파이프에 쓰기.

### 뚫린 것

- **Everyone에 쓰기를 준 위치.** 폴더와 레지스트리 키 모두 네 구성이 썼습니다.
- **읽기.** 현재 사용자 토큰을 쓰는 두 구성(QwenPaw 비관리자, Codex `unelevated`)은 사용자가 읽는 것을 모두 읽기 권한으로 열었습니다. `.ssh`, 에이전트 인증 파일, 사용자 레지스트리가 포함됩니다. 시험용 사용자 범위 DPAPI 값도 복호화했습니다.
- **다른 프로세스.** 같은 두 구성은 사용자 프로세스 거의 전부를 메모리 읽기·종료·토큰 복제 권한으로 열었습니다. Codex `elevated`도 로그온 SID ACE가 있는 사용자 프로세스 106개 중 96개를 같은 권한으로 열었습니다. explorer가 포함됩니다.
- **별도 계정이어도 읽힌 것.** `Users`·`Everyone` 읽기가 상속되는 프로필 아래 파일은 네 구성 모두 읽기 권한으로 열었습니다. 시험용 컴퓨터 범위 DPAPI 값도 네 구성 모두 복호화했습니다. Codex `elevated`는 `~/.codex`의 인증·설정 파일도 열었습니다.
- **환경 변수.** 네 구성 모두 `API_KEY`가 들어간 이름의 변수를 그대로 전달했습니다.
- **작업 폴더 안 보호.** QwenPaw 두 구성은 `.git`과 읽기 전용 폴더의 변경을 허용했습니다. Codex 두 구성은 시작 전에 있던 `.git`·`.codex`·`.agents`는 보호했지만, 시작 시점에 없던 같은 이름의 폴더는 만들 수 있었습니다.
- **작업 폴더 사이.** QwenPaw 비관리자와 Codex 두 구성은 동시에 실행 중인 다른 작업 폴더의 샌드박스 프로세스를 모든 권한으로 열었습니다. Codex 두 구성은 임시 폴더를 작업 폴더끼리 같이 씁니다. Codex `elevated`는 샌드박스 계정 프로필도 같이 씁니다.
- **남는 프로세스.** Codex 두 구성에서는 Job 밖으로 띄운 프로세스가 제품을 강제 종료한 뒤에도 실행됐습니다.

QwenPaw 관리자만 사용자 프로세스와 다른 작업 폴더의 샌드박스를 열지 못했고, 사용자 로그온 SID에 쓰기를 준 위치에도 쓰지 못했습니다.

### 왜 그런가

- **`WRITE_RESTRICTED`의 두 단계 검사.** 네 구성 모두 `WRITE_RESTRICTED` 플래그로 만든 Restricted Token을 씁니다. Windows는 모든 요청을 토큰의 사용자·그룹 SID로 검사합니다(첫 번째 검사). 쓰기 권한 요청만 제한 SID 목록으로 한 번 더 검사합니다(두 번째 검사).
- **읽기는 제한되지 않습니다.** 파일 읽기, 프로세스 메모리 읽기·종료 권한, 토큰 열기는 두 번째 검사를 받지 않습니다. 토큰의 계정이 할 수 있으면 샌드박스 명령도 합니다.
- **제한 SID 목록에 Everyone과 로그온 SID가 있습니다.** DACL이 이 SID에 쓰기를 준 위치는 두 번째 검사도 통과합니다. 작업 폴더 쓰기는 제품이 작업 폴더 DACL에 추가한 capability SID의 쓰기 허용 ACE로 통과합니다.
- **별도 계정은 첫 번째 검사에서 갈립니다.** Codex `elevated`와 QwenPaw 관리자는 별도 계정의 토큰을 제한합니다. 사용자만 허용한 파일은 첫 번째 검사에서 거부됩니다. 다른 계정에도 읽기를 준 파일은 읽힙니다.
- **로그온 SID를 공유하는지가 프로세스 접근을 가릅니다.** Codex `elevated`는 `CreateProcessWithLogonW`로 실행기를 시작해 사용자의 로그온 SID를 함께 가집니다. 그래서 DACL이 로그온 SID에 권한을 주는 사용자 프로세스가 열렸습니다. QwenPaw 관리자는 `LogonUserW`로 새 로그온 세션을 열어 로그온 SID가 다릅니다.

[토큰 구성과 소스 비교](research/restricted-token-backends.md) · [실행 기록 2026-11-25-01](runs/2026-11-25-01.md) · [02](runs/2026-11-25-02.md) · [03](runs/2026-11-25-03.md) · [04](runs/2026-11-25-04.md)

### 구성별 판단

| 구성 | 판단 |
| --- | --- |
| QwenPaw 비관리자 | 작업 폴더 밖 쓰기를 경로 권한에 따라 막는 수준입니다. 읽기 제한, 작업 폴더 안 보호, 다른 프로세스 읽기 차단이 없습니다. |
| Codex `unelevated` | 같은 경계에 작업 폴더 안 보호 경로, 작업 폴더별 capability SID, 별도 데스크톱이 더해집니다. 읽기와 다른 프로세스 읽기는 막지 않습니다. |
| Codex `elevated` | 별도 계정이라 사용자만 허용한 파일, `.ssh`, 사용자 레지스트리, 사용자 범위 DPAPI를 막습니다. 사용자의 로그온 SID를 공유해 사용자 데스크톱 프로세스가 열립니다. 모든 작업 폴더가 같은 계정과 프로필을 씁니다. |
| QwenPaw 관리자 | 네 구성 중 사용자 파일·프로세스 분리가 가장 넓습니다. 대신 앱 전체를 관리자 권한으로 실행해야 하고, 사용자 데스크톱을 공유하며, 계정을 만들 때마다 PC에 항목이 남습니다. |

- **QwenPaw AppContainer.** 작업 폴더 밖 읽기·쓰기, 외부 네트워크, 호스트의 명명된 파이프를 Windows가 거부했습니다. 그러나 작업 폴더 안 하위 폴더 보호가 실패했고, 개발 도구 호환성이 낮으며, 에이전트 경로에서는 선택되지 않습니다. [QwenPaw 실측 보고서](report-qwenpaw-backends.md)
- **QwenPaw의 승인 경로.** 기본 설정은 셸에 샌드박스를 적용하지 않습니다. 샌드박스가 막은 명령을 사용자가 승인하면 같은 명령이 격리 없이 다시 실행됐습니다(5/5). [승인 흐름 실측](runs/2026-11-24-07.md#1-iso-1518-승인-흐름-통합-시나리오마다-5회)

### 측정하지 않은 것

- MXC BaseContainer. 아래 MXC 관련 내용은 모두 문서와 소스 기준입니다.
- 네 구성의 네트워크 차단과 클립보드.
- Codex와 OpenClaw의 승인 흐름.
- 열린 핸들로 하는 실제 조작(메모리 읽기, 가장, 종료).

전체 목록은 [측정하지 않은 항목과 후속 과제](findings.md#측정하지-않은-항목과-후속-과제)에 있습니다.

## 문헌·소스 조사에서 확인한 것

**작업 폴더를 보호할 수 있는지, 필요한 개발 작업이 돌아가는지, 셸 밖 도구에도 같은 제한이 적용되는지를 각각 확인해야 합니다.** 이 절부터는 공식 문서와 릴리스 소스에 근거한 내용입니다. 실측으로 확인한 곳은 그 자리에 적었습니다.

| 확인할 질문 | 조사에서 확인한 답 |
| --- | --- |
| 작업 폴더 안의 민감한 하위 폴더만 잠글 수 있나? | 실행 방식마다 다릅니다. Codex MXC는 지원되는 PC에서 하위 경로를 별도로 제한할 수 있습니다. OpenClaw Gateway의 MXC 플러그인은 사용자가 지정한 파일 거부 규칙을 제공하지 않습니다. QwenPaw 일부 경로는 초기 설정 때 존재하는 폴더에 거부 규칙을 적용합니다. |
| 파일을 읽고 쓸 수 있으면 빌드와 테스트도 되나? | 병렬 빌드, 디버거, 개발 서버는 프로세스 간 통신과 로컬 포트 또는 백그라운드 실행이 필요합니다. 파일 검사를 통과해도 각각 실패할 수 있습니다. |
| 셸의 인터넷을 막으면 에이전트의 모든 연결도 막히나? | Codex의 로컬 명령 프록시와 웹 검색·MCP·브라우저의 연결에는 별도 정책이 적용됩니다. 관리형 네트워크 설정에서는 같은 PC의 로컬 서비스 접근도 확인해야 합니다. |
| 격리를 적용할 수 없으면 명령은 어떻게 되나? | 경로에 따라 명령을 시작하지 않거나, 승인 후 Windows 사용자 권한으로 실행합니다. 어떤 방식으로 실행됐는지 남겨야 보안 결과를 해석할 수 있습니다. |

[실행 경로 비교](research/README.md) · [상세 근거와 제품별 제약](research/security-boundaries.md)

**승인 후에도 같은 권한으로 실행되는지는 제품마다 다릅니다.** OpenClaw Hub는 명령 승인 후에도 Windows 격리 정책을 확인합니다. Codex는 권한 확대를 승인할 수 있지만, 조사 버전의 소스상 명시적 파일 읽기 거부가 있으면 샌드박스를 유지합니다. QwenPaw에는 일반 샌드박스 차단 후 별도 인간 승인으로 격리 없이 다시 시도하는 경로가 있습니다. 이 가운데 QwenPaw의 경로만 실측으로 확인했습니다. [에이전트 7종의 승인 정책 비교](research/approval-policies.md)

## 사례

[Windows 셸의 파일 권한과 읽기 거부 비교](research/filesystem-isolation-comparison.md)에서 MXC BaseContainer, AppContainer, Restricted Token, Codex `elevated`의 하위 경로·신규 파일·이름 변경과 AppContainer의 IPC 제약을 비교합니다.

### 승인과 실행 권한을 연결하는 네 가지 방식

| 방식 | 할 수 있는 것 | 적용할 때 확인할 조건 | 조사 사례 |
| --- | --- | --- | --- |
| 호출 전 승인 · OS 격리 없음 | 도구나 명령을 시작하기 전에 허용·거부합니다. | 시작된 프로세스와 자식 프로세스는 호스트 계정 권한을 따릅니다. | Claude Code, Hermes Agent 기본 `local`, OpenCode, OpenHuman의 Windows 로컬 셸 |
| 승인 후 격리 정책 검증 | 승인된 실행에도 파일·네트워크 등 OS 제한을 집행합니다. | 필수 정책을 적용할 수 있는지 실행 전에 확인합니다. 미지원 OS의 호환 실행 조건도 확인합니다. | OpenClaw Windows Hub의 `system.run` |
| 권한 확대 후 필수 제한 유지 | 예외를 승인하고도 명시적 파일 읽기 거부를 유지합니다. | 필요한 제한을 집행할 백엔드가 없으면 실행이 차단됩니다. | Codex의 명시적 읽기 거부가 있는 권한 확대 경로 |
| 격리 차단 후 별도 승인으로 호스트 재시도 | 일부 격리 차단을 사용자의 추가 승인으로 재시도할 수 있습니다. | 재시도에는 호스트 권한이 적용됩니다. 격리 실행만 허용한 모델 판정에는 이 분기가 적용되지 않습니다. | QwenPaw의 일반 샌드박스 차단 경로 |

[상세 흐름도](../../approval-patterns-detailed.html) · [제품별 승인 정책](research/approval-policies.md)

QwenPaw의 관리자 Restricted Token 경로와 Codex `elevated`는 별도 저권한 Windows 계정, Restricted Token, 파일 ACL을 사용합니다. 차단 이후의 동작은 제품의 승인 정책이 결정합니다. QwenPaw는 일반 샌드박스 실행의 결과를 격리 위반으로 분류하면 별도 인간 승인을 거쳐 호스트에서 비격리로 재시도할 수 있습니다. Codex는 별도 권한 확대 요청을 승인받더라도, 명시적 읽기 거부가 설정된 경로에서는 그 제한을 유지한 채 실행합니다. 차단만으로 확대 승인 요청이 자동으로 발생하지는 않습니다. [QwenPaw 재시도 코드](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/governance/tool_adapter.py#L476-L603) · [Codex 권한 확대 분기](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/core/src/tools/sandboxing.rs#L242-L256)

### OpenClaw Windows Hub에서 승인과 격리를 나누는 방식

폰이나 채팅의 메시지는 Gateway를 통해 에이전트에 도달합니다. 에이전트가 Windows 노드 실행을 선택하면 명령 요청은 Gateway를 거쳐 Windows Hub에 전달됩니다. Gateway와 Hub는 같은 PC에도 설치할 수 있습니다. Hub의 **명령 승인 V2**는 Windows 노드의 로컬 승인 방식 세대입니다.

1. **Gateway 전달 판단.** 에이전트의 `exec` 사용 권한, 대상 노드의 페어링·연결과 `system.run` 지원, Gateway의 전달 정책을 확인합니다. Gateway 승인 질문은 정책에 따라 생략될 수 있습니다.
2. **Hub 로컬 승인.** Hub가 실행 파일 경로와 인수를 허용 목록과 비교합니다. 기본값은 미일치 시 사용자에게 질문하고, 승인 화면을 표시할 수 없으면 거부하는 것입니다.
3. **실행 경로 판정과 MXC 요청 검증.** 지원 장치에서는 전체 격리 정책을 BaseContainer에서 집행할 수 있는지 검사합니다. OS 미지원이 확인되면 호스트 호환 실행을 준비합니다.
4. **최종 승인 재검증과 실행.** 두 경로 모두 프로세스 시작 직전에 승인이 여전히 유효한지 확인합니다. 지원 경로의 프로세스는 MXC가 실행 중 파일·네트워크 접근을 제한합니다.

BaseContainer **미지원이 확정된 경우**에는 유효한 Hub 명령 승인을 거쳐 호스트 호환 경로에서 격리 없이 실행할 수 있습니다. SDK 로딩 실패, 판정 불가, 정책 검증 실패는 시작을 차단합니다. 시작 후 오류는 실행 실패로 처리하며 호스트에서 재시도하지 않습니다. [OpenClaw 단계별 동작](research/agents/openclaw.md#windows-hub-노드의-명령-실행) · [MXC 지원 판정](research/solutions/mxc.md#openclaw-windows-hub의-지원-판정)

### 권한 확대 승인 후에도 필수 제한을 유지한다

Codex `0.171.0`의 해당 경로는 **① 권한 확대 요청 심사 → ② 이번 명령의 실행 권한 계산 → ③ Windows 샌드박스에서 집행**으로 나뉩니다. 명시적 읽기 거부가 있는 경우, 명령 허용 규칙에 일치했다는 사실만으로는 파일 권한이 확대되지 않습니다. 확대 요청이 승인되면 기존 읽기 거부를 유지한 실행 프로필을 계산합니다. 실제 확대 범위는 이 프로필로 판단합니다. [권한 확대와 승인 분기](research/approval-policies.md#codex와-openclaw에서-승인-후-남는-제한)

이번 방식의 도입 비교 범위는 **셸과 자식 프로세스**입니다. 후보는 **MXC BaseContainer**와 **레거시 `elevated`**입니다. MXC는 지원되는 Windows에서 프로세스 정책으로 제한을 집행하고, `elevated`는 관리자 초기 설정으로 준비한 저권한 계정과 ACL·방화벽을 사용합니다. MXC를 선호하도록 설정하면 환경과 정책에 따라 처음부터 레거시를 선택할 수 있습니다. MXC 명시 지정이나 선택 후 시작 실패는 백엔드 자동 재시도를 일으키지 않습니다. [Codex Windows 백엔드](research/agents/codex.md)

방식 선정 전에는 **승인으로 쓰기 범위가 어디까지 넓어지는지**, **필수 읽기 거부가 남는지**, **선택한 백엔드가 거부를 집행할 수 없을 때 명령을 시작하지 않는지**를 확인합니다. 보호 경로의 이름 변경과 실행 중 새로 생긴 패턴 일치 파일은 별도 관찰 항목입니다. [권한 확대 실측](protocol.md#codex-권한-확대와-읽기-거부-보존) · [MXC 보호 폴더 이름 변경](protocol.md#mxc-보호-폴더-이름-변경)

### 작업 폴더 안의 특정 폴더만 잠근다

에이전트에 프로젝트 수정 권한은 주되 그 안의 자격 증명 폴더는 보호해야 하는 경우입니다. **읽기 전용이라면 내용은 여전히 읽을 수 있습니다.** 내용까지 보호하려면 접근 거부가 필요합니다. Windows에서는 부모 폴더 권한이 삭제·이름 변경에 관여할 수 있으므로, 내용 읽기·쓰기와 함께 이름 표시·삭제·이름 변경도 따로 확인합니다. [Windows 파일 권한](https://learn.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants) · [삭제 및 이름 변경 규칙](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-deletefilew#remarks)

| 실행 경로 | 하위 폴더 보호 |
| --- | --- |
| **Codex MXC** | 지원되는 PC에서는 더 구체적인 하위 경로 규칙을 적용합니다. PC가 요청한 거부 기능을 지원하지 않으면 실행 전에 실패합니다. 패턴으로 지정한 거부는 명령 시작 때 존재하는 일치 항목을 기준으로 하며, 하드 링크에는 파일 이름별 권한이 유지됩니다. |
| **OpenClaw Gateway MXC** | 사용자 지정 파일 거부 규칙을 제공하지 않습니다. 쓰기 허용 범위가 제품이 보호하는 스킬 폴더와 겹치면 명령 시작을 거부합니다. Windows Hub의 노드 실행은 별도이며, 지정된 보호 경로에 Windows의 네이티브 거부를 요구합니다. |
| **QwenPaw AppContainer (`allow_read_all=False`)·관리자 Restricted Token (`allow_read_all=True`, 기본값)** | 초기 설정 때 경로가 이미 있으면 거부 ACL을 설정합니다. 경로가 없으면 건너뛰고, 소스상 호출부에서 ACL 설정 성공 여부를 확인하지 않습니다. 비관리자 Restricted Token은 기본 실행 경로에서 읽기 거부를 집행하지 않습니다. **실측:** AppContainer는 거부 ACE가 걸렸지만 효과가 없었고 모든 권한이 열렸습니다. 관리자 Restricted Token은 작업 폴더 안 거부 폴더의 읽기·목록·쓰기·삭제를 모두 거부했습니다(5/5). 비관리자 Restricted Token은 경고만 남기고 모두 허용했습니다(5/5). |
| **Codex `elevated`·`unelevated`(실측)** | `elevated`는 작업 폴더 안 거부 폴더의 읽기·목록·쓰기·삭제를 모두 거부했습니다(5/5). 설정에서 경로를 지워도 거부 ACE가 남았습니다. `unelevated`는 읽기 거부가 있는 설정이면 명령을 실행하지 않았습니다(5/5). |

[Codex MXC 소스](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/mxc-sandbox/README.md) · [OpenClaw Gateway](https://github.com/openclaw/openclaw/blob/v2026.11.6/extensions/mxc/README.md) · [Windows Hub](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/docs/OPENCLAW_GATEWAY_NODE_EXEC_FAQ.md) · [QwenPaw 경로별 근거](research/security-boundaries.md#상위-폴더-허용과-하위-폴더-보호) · [AppContainer 실측](runs/2026-11-24-07.md#iso-0709-appcontainer의-하위-폴더-보호가-실패한-원인) · [네 구성 실측](runs/2026-11-25-04.md)

### 파일은 열리지만 빌드나 개발 서버가 멈춘다

- **병렬 빌드와 디버깅.** 이전 Codex MXC 버전에서 단일 작업자 빌드는 성공했지만 병렬 MSBuild와 진단 연결이 실패했다는 공개 보고가 있습니다. 프로세스 간 통신에 쓰는 명명된 파이프가 관련된 것으로 보고됐으며, 원인과 조사 기준 버전인 `0.171.0`에서의 재현 여부는 확인되지 않았습니다. [MSBuild 병렬 실행 구조](https://learn.microsoft.com/en-us/visualstudio/msbuild/build-process-overview) · [공개 호환성 보고](https://github.com/openai/codex/issues/60794)
- **실측한 병렬 작업.** Python 다중 프로세스 병렬 작업은 QwenPaw 비관리자 Restricted Token, QwenPaw AppContainer, Codex `unelevated`에서 `WinError 5`로 실패했습니다. Codex `elevated`와 QwenPaw 관리자에서는 성공했습니다(각 5/5). [실행 기록](runs/2026-11-25-01.md#9-환경-변수-데스크톱-병렬-빌드-e-f-g4)
- **개발 서버와 파일 변경 감시.** Codex MXC는 전경 명령이 끝나면 남은 자식 프로세스도 종료합니다. 셸 명령이 반환된 뒤에도 서버나 워처가 계속 살아 있어야 하는 작업은 이 동작의 영향을 받습니다. [Codex Windows 샌드박스](https://learn.chatgpt.com/docs/windows/windows-sandbox#mxc-compatibility)
- **Windows 앱과 사용자별 설정.** 창 조작, 입력, 클립보드에는 각각 별도 권한이 필요합니다. AppContainer나 별도 계정에서 실행하면 기존 Windows 사용자 프로필의 레지스트리 설정이나 로그인 상태를 읽는 도구도 따로 확인해야 합니다. [MXC UI 정책](https://github.com/microsoft/mxc/blob/main/docs/backends/process-container/UIPolicy_Schema.md) · [Microsoft AppContainer 격리](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)

### 셸을 제한해도 별도 연결과 권한이 남는다

- **같은 PC의 서비스.** Codex MXC의 관리형 네트워크는 호스트 루프백을 허용합니다. 같은 PC의 로컬 DB나 개발 API를 보호해야 한다면 외부 인터넷 차단과 별개로 접근 결과를 확인해야 합니다. [Codex MXC 소스](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/mxc-sandbox/README.md)
- **MCP·웹 검색·브라우저.** Codex의 로컬 명령 프록시는 이러한 도구나 Computer Use에 공통 적용되지 않습니다. 도구별 실행 위치와 유효 정책을 따로 확인해야 합니다. [Codex 도구별 통신 범위](https://learn.chatgpt.com/docs/agent-approvals-security#traffic-outside-the-command-network-proxy)
- **환경 변수·자원 한도.** 조사한 QwenPaw Windows 버전은 환경 변수 허용 목록과 프로세스 수·메모리 한도를 집행하지 않습니다. 설정에 값이 있다는 사실만으로 민감한 변수가 숨겨지거나 자원 사용량이 제한된다고 판단할 수 없습니다. 실측에서 Restricted Token 네 구성과 QwenPaw AppContainer 모두 호스트의 시험용 환경 변수를 그대로 전달했습니다. [QwenPaw 구현 제약](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/website/public/docs/security.en.md#current-limitations)

### 격리 환경을 시작할 수 없는 PC에서 명령을 실행한다

**시작 거부**는 작업이 멈췄다는 뜻입니다. **비격리 실행**은 작업이 호스트 계정 권한으로 진행됐다는 뜻입니다. OpenClaw Windows Hub는 SDK·정책 검증에 실패하면 시작을 차단합니다. 시작 후 오류는 실행 실패로 처리하며 호스트에서 재시도하지 않습니다. OS 미지원이 확정되면 유효한 Hub 승인으로 비격리 호스트에서 실행할 수 있습니다. OpenHuman 안정판의 Windows 로컬 셸은 TinyBox가 Windows 격리 백엔드를 선택하지 않아 호스트에서 실행됩니다. [Windows Hub 실패 처리](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/docs/OPENCLAW_GATEWAY_NODE_EXEC_FAQ.md) · [OpenHuman의 TinyBox 경로](research/solutions/tinybox.md)

### 같은 “항상 허용”을 눌러도 저장되는 범위가 다르다

OpenClaw Hub V2가 새 승인에 저장하는 단위는 실행 파일과 인수입니다. Hermes는 명령 패턴을, OpenHuman의 일반 승인은 도구 이름을 기억합니다. 공유 채팅에서 누구에게 승인 권한이 있는지도 별도 설정입니다. 실측에서는 승인 주체, 이번 요청에만 적용되는지, 다음 실행에도 재사용되는지를 기록합니다. [제품별 승인 및 저장 범위](research/approval-policies.md#핵심-결론)

## 배경지식

**명령 승인**은 에이전트가 명령을 시작해도 되는지 결정하는 단계입니다. **OS 샌드박스**는 시작된 명령이 실제로 어디에 접근할 수 있는지 Windows가 제한하는 방식입니다. 예를 들어 사용자가 빌드를 승인해도 샌드박스는 빌드 도구의 프로젝트 밖 파일 쓰기를 차단할 수 있습니다. [도구 승인과 호스트 셸](research/solutions/tool-approval.md)

| 용어 | 쉽게 말하면 |
| --- | --- |
| **MXC ProcessContainer** | 명령과 그 자식 프로세스가 파일·네트워크에 접근하는 범위를 Windows에서 제한합니다. |
| **MXC IsolationSession** | 서비스나 작업을 별도 Windows 계정과 세션에서 실행합니다. 예를 들어 OpenClaw 서비스가 이 세션에서 실행되더라도 그 서비스가 시작하는 개별 도구의 정책은 별도로 확인합니다. |
| **AppContainer** | Windows가 앱에 전용 보안 식별자와 허용 기능을 부여해 파일·레지스트리·네트워크 접근을 제한합니다. |
| **Restricted Token·ACL·WFP** | 토큰은 프로그램이 어떤 권한으로 실행되는지, ACL은 파일이나 레지스트리를 누가 사용할 수 있는지, WFP는 어떤 네트워크 연결을 차단할 수 있는지를 정합니다. |
| **루프백·명명된 파이프·MCP** | 루프백은 같은 PC의 서비스에 연결하는 네트워크 경로입니다. 명명된 파이프는 프로그램끼리 통신하는 Windows 기능입니다. MCP는 에이전트가 별도 도구나 서비스에 연결할 때 사용하는 방식입니다. |

[격리 기술 문서](research/README.md#격리-기술과-기준-동작) · [Windows 명명된 파이프](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)

## 실측 범위와 남은 항목

조사 범위는 Windows 호스트에서 직접 실행되는 명령과 파일 작업입니다. WSL2, Linux 컨테이너, 별도 VM과 원격 실행은 제외했습니다. Claude Code, Hermes Agent, OpenCode와 조사 버전의 OpenHuman 로컬 실행은 Windows 호스트 계정의 기준 동작에 포함했습니다. [서비스별 비교표](README.md#windows-서비스별-조사)

| 대상 | 실측 여부 | 결과 |
| --- | --- | --- |
| Windows 호스트 기준 | 공통 워크로드 5회 | [실행 기록](runs/2026-11-23-01.md) |
| QwenPaw 비관리자 Restricted Token, AppContainer | ISO-01~18 | [QwenPaw 실측 보고서](report-qwenpaw-backends.md) |
| Restricted Token 네 구성(QwenPaw 비관리자·관리자, Codex `unelevated`·`elevated`) | 파일, 레지스트리, 다른 프로세스, 환경 변수, 데스크톱, 프로세스 수명, 시간, 남는 항목 | [사례별 보고서](report-token-backends/index.html) · [결과 및 판단](findings.md#restricted-token-네-구성-실측-2026-11-25) |
| MXC BaseContainer, OpenClaw, Codex 승인 흐름 | 미측정 | [후속 과제](findings.md#후속-과제) |

측정에는 합성 파일과 통제된 서비스를 사용했습니다. Windows 빌드·실행 계정·실제 백엔드·권한 설정은 실행 기록마다 남겼습니다. [실측 프로토콜](protocol.md) · [측정하지 않은 항목](findings.md#측정하지-않은-항목과-후속-과제)
