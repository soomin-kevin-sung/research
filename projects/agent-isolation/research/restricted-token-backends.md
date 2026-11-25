# Restricted Token 계열 백엔드 비교: QwenPaw와 Codex `unelevated`·`elevated`

QwenPaw와 Codex는 Windows에서 Restricted Token을 쓰는 샌드박스 백엔드를 두 가지씩 갖고 있습니다. 관리자 권한 없이 현재 사용자로 실행하는 방식과, 관리자 승인으로 만든 별도 계정으로 실행하는 방식입니다. 이 문서는 네 구성이 같은 Windows 기능을 어떻게 다르게 구성했는지 소스 기준으로 비교합니다.

| 구성 | 버전 | 근거 |
| --- | --- | --- |
| QwenPaw 비관리자 백엔드 (`WindowsUnelevatedSandbox`) | `2.3.0.post1` | 소스 + [실측](../report-qwenpaw-backends.md) |
| QwenPaw 관리자 백엔드 (`WindowsElevatedSandbox`) | `2.3.0.post1` | 소스 + [실측](../runs/2026-11-25-02.md) |
| Codex `unelevated` | CLI `0.171.0`(실측은 `0.172.0`, 샌드박스 코드 동일) | 소스 + [실측](../runs/2026-11-25-01.md) |
| Codex `elevated` | CLI `0.171.0`(실측은 `0.172.0`, 샌드박스 코드 동일) | 소스 + [실측](../runs/2026-11-25-01.md) |

네 구성 모두 2026-11-25에 같은 항목으로 실측했습니다. 1~9장은 소스 기준 설명이고, 실측과 다른 곳은 그 자리에 표시했습니다. 실측 결과는 10장 끝에 모았습니다.

## 용어

- **액세스 토큰(이하 토큰).** 프로세스에 붙는 보안 정보입니다. 사용자 SID, 그룹 SID, 특권, 무결성 수준이 들어 있습니다. 프로세스가 파일을 열 때 Windows는 이 토큰과 파일의 DACL을 비교합니다.
- **SID.** Security Identifier. 사용자, 그룹, 로그온 세션 등을 식별하는 값입니다. 앞부분 숫자로 종류가 나뉩니다. 예: 로컬·도메인 계정과 그룹 `S-1-5-21-…`, Everyone `S-1-1-0`, 로그온 SID `S-1-5-5-…`, AppContainer SID `S-1-15-2-…`, AppContainer capability SID `S-1-15-3-…`, 무결성 수준 `S-1-16-…`.
- **DACL과 ACE.** DACL은 파일·폴더·레지스트리 키에 붙은 접근 허용·거부 목록이고, ACE는 그 항목 하나("이 SID에게 이 권한을 허용 또는 거부")입니다. 폴더의 ACE는 하위 파일·폴더로 상속되게 설정할 수 있습니다.
- **`WRITE_RESTRICTED` 토큰.** 읽기는 원래 토큰의 사용자·그룹 SID로 DACL을 검사합니다. 쓰기는 이 검사에 더해, **제한 SID 목록**(restricting SID)에 있는 SID 중 하나가 DACL에서 쓰기 허용을 받았는지 한 번 더 검사합니다. [제한용 SID와 WRITE_RESTRICTED](solutions/windows-accounts-tokens.md#제한용-sid와-write_restricted)
- **capability SID(이 문서에서의 뜻).** QwenPaw와 Codex가 `S-1-5-21-a-b-c-d` 형식으로 무작위 생성하는 SID입니다. 어떤 계정에도 연결되지 않습니다. 제품은 이 SID를 토큰의 제한 SID 목록에 넣고, 쓰기를 허용할 폴더의 DACL에 이 SID의 쓰기 허용 ACE를 추가합니다. AppContainer의 capability SID(`S-1-15-3-…`)와 이름만 같고 다른 것입니다.
- **방화벽 규칙과 Windows 필터링 플랫폼(WFP).** 특정 계정의 네트워크 연결을 운영체제 수준에서 차단하는 기능입니다.
- **Windows 데이터 보호 API(DPAPI).** 비밀번호 같은 값을 암호화해 저장하는 Windows 기능입니다. 사용자 범위(그 사용자만 복호화)와 컴퓨터 범위(이 PC의 모든 계정이 복호화) 두 가지가 있습니다.

## 요약

**네 구성의 공통 구조.**
- `CreateRestrictedToken`에 `WRITE_RESTRICTED`를 지정해 토큰을 만듭니다. `DISABLE_MAX_PRIVILEGE`로 `SeChangeNotifyPrivilege`(경로 탐색 특권) 외의 특권을 모두 제거합니다.
- 제한 SID 목록에 무작위 capability SID, 로그온 SID, Everyone을 넣습니다.
- 작업 폴더 DACL에 capability SID의 쓰기 허용 ACE를 추가합니다.

그래서 QwenPaw 실측에서 나온 "DACL에 Everyone 쓰기 허용 ACE가 있는 폴더에는 쓰기가 허용된다"는 결과는 네 구성 모두에서 반복될 가능성이 높습니다.

**구성 간 차이.**

| 항목 | QwenPaw 비관리자 | Codex `unelevated` | QwenPaw 관리자 | Codex `elevated` |
| --- | --- | --- | --- | --- |
| 토큰을 만드는 계정 | 현재 사용자 | 현재 사용자 | 설정별 전용 계정(첫 명령 때 생성, QwenPaw 종료 시 삭제) | 설치 때 만든 고정 계정 두 개(오프라인·온라인) |
| 관리자 필요 | 아니요 | 아니요 | 실행하는 프로세스가 관리자여야 함 | 최초 설치 때 한 번 |
| 쓰기 허용 ACE 대상 | 샌드박스마다 capability SID 1개 | 작업 폴더·쓰기 경로마다 capability SID | capability SID 1개 + 전용 계정 SID | 작업 폴더·쓰기 경로마다 capability SID + 샌드박스 그룹 SID |
| 작업 폴더 안 보호 경로 | 없음(읽기 전용 마운트는 무시) | `.git`·`.codex`·`.agents` 등에 쓰기 거부 ACE | 읽기 전용 마운트는 읽기 허용 ACE만 추가 | `.git`·`.codex`·`.agents` 등에 쓰기 거부 ACE |
| 작업 폴더 밖 읽기 | 사용자가 읽을 수 있는 것 전부 | 사용자가 읽을 수 있는 것 전부 | 전용 계정이 읽을 수 있는 것만 | 시스템 폴더와 사용자 프로필 하위 폴더에 읽기 허용 ACE 추가(민감 폴더 제외) |
| 읽기 거부 요청 | 경고만 하고 실행 | 실행을 거부 | 기존 경로에 전용 계정 SID 대상 거부 ACE | 샌드박스 그룹 SID 대상 거부 ACE |
| 네트워크 차단 | 프록시 환경 변수 | 프록시 환경 변수 + 오프라인 환경 변수 + `ssh`·`scp` 실패용 대체 파일 | 전용 계정 방화벽 규칙 | 오프라인 계정 방화벽 규칙 + WFP 필터 |
| 데스크톱 | 사용자 기본 데스크톱 | 별도 데스크톱 | 사용자 기본 데스크톱(전용 계정에 접근 권한 부여) | 별도 데스크톱 |
| 셸 종료 후 자식 프로세스 | 도구 호출이 반환되지 않음(실측) | 종료하지 않음(의도된 동작) | 비관리자와 같은 대기 방식(미측정) | 종료하지 않음(의도된 동작) |
| ACE 정리 | 정리 함수가 삭제 | 삭제하지 않음 | 정리 함수가 계정·방화벽 규칙·ACE 삭제 | 삭제하지 않음(계정·방화벽 규칙도 유지) |

정리하면 다음과 같습니다.
- **QwenPaw**는 실행 중 추가한 ACE·계정·방화벽 규칙을 실행이 끝나면 삭제합니다.
- **Codex**는 쓰기 경로마다 capability SID를 따로 만들고 보호 경로에 쓰기 거부 ACE를 추가합니다. 대신 계정과 ACE를 삭제하지 않고 다음 실행에 다시 사용합니다.

## 1. 선택 조건과 준비

**QwenPaw.**
- `allow_read_all=True`(기본값)이면 Restricted Token 계열을 씁니다. 프로세스가 관리자면 관리자 백엔드, 아니면 비관리자 백엔드입니다.
- 에이전트 경로는 이 값을 따로 지정하지 않으므로, 일반 사용자 PC에서는 항상 비관리자 백엔드가 쓰입니다.
- 관리자 백엔드는 QwenPaw 자체를 관리자 권한으로 실행해야 선택됩니다.
- [백엔드 선택](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/config.py#L862-L877)

**Codex.**
- `[windows] sandbox = "unelevated" | "elevated" | "mxc"`로 고릅니다. 지정하지 않으면 샌드박스를 쓰지 않습니다.
- MXC를 우선하는 설정이 켜져 있고 PC가 지원하면 MXC가 먼저 선택됩니다.
- 관리 정책의 `allowed_sandbox_implementations`로 허용할 방식을 제한할 수 있고, 둘 다 허용되면 `elevated`가 기본입니다.
- `elevated`는 계정이 없거나 오래됐으면 설치 단계(setup)를 다시 실행합니다. 이때 패키지 서비스가 없으면 사용자 계정 컨트롤(UAC) 승인창이 뜹니다.
- `elevated`가 실패해도 `unelevated`로 자동 전환하지 않습니다. 화면에서 사용자가 고를 때만 바뀌고, 그 선택지에는 "프롬프트 주입 시 위험이 더 크다"는 경고가 붙습니다.
- [설정 매핑](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/core/src/config/windows_sandbox_config.rs#L86-L126) · [설치 필요 판단](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/identity.rs#L330-L449) · [비관리자 선택지 경고](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/tui/src/chatwidget/windows_sandbox_prompts.rs#L154-L166)

## 2. 토큰 구성

| 항목 | QwenPaw 비관리자 | Codex `unelevated` | QwenPaw 관리자 | Codex `elevated` |
| --- | --- | --- | --- | --- |
| 제한 전 토큰 | 현재 프로세스의 토큰 | 현재 프로세스의 토큰 | 전용 계정을 `LogonUser`(일괄 작업 로그온)로 로그온한 토큰 | 고정 계정으로 실행기(`codex-command-runner.exe`)를 시작한 뒤 그 실행기의 토큰 |
| 플래그 | `DISABLE_MAX_PRIVILEGE` + `WRITE_RESTRICTED` | `DISABLE_MAX_PRIVILEGE` + `LUA_TOKEN` + `WRITE_RESTRICTED` | `DISABLE_MAX_PRIVILEGE` + `LUA_TOKEN` + `WRITE_RESTRICTED` | `DISABLE_MAX_PRIVILEGE` + `LUA_TOKEN` + `WRITE_RESTRICTED` |
| 제한 SID 목록 | capability SID, 로그온 SID, Everyone | 쓰기 경로별 capability SID, 로그온 SID, Everyone | capability SID, 전용 계정 SID, 로그온 SID, Everyone | 쓰기 경로별 capability SID, 고정 계정 SID, (프록시용 SID), 로그온 SID, Everyone |
| 남는 특권 | `SeChangeNotifyPrivilege`(경로 탐색)만 | 같음 | 같음 | 같음 |
| 기본 DACL(샌드박스 프로세스가 새로 만드는 객체에 붙는 DACL) | capability SID, 로그온 SID, Everyone에게 모든 권한 | 로그온 SID에게 모든 권한, OWNER RIGHTS에게 `READ_CONTROL`만 | 로그온 SID와 capability SID에게 모든 권한 | 로그온 SID에게 모든 권한, OWNER RIGHTS에게 `READ_CONTROL`만 |

- **기본 DACL 차이.** 샌드박스 안에서 만든 프로세스·명명된 파이프 같은 객체에 어느 SID가 접근할 수 있는지를 정합니다.
  - QwenPaw 비관리자는 Everyone에게도 모든 권한을 줍니다.
  - Codex는 "같은 capability SID를 쓰는 다른 실행이 이 실행의 프로세스·파이프에 접근하지 못하게 한다"는 이유로 로그온 SID에만 줍니다.
  - 실측에서는 이 의도가 이루어지지 않았습니다. 로그온 SID는 모든 실행과 사용자 프로세스가 공유하므로, 다른 작업 폴더의 샌드박스가 이 실행의 프로세스를 모든 권한으로 열었습니다(2026-11-25 P6).
- **비관리자 두 구성의 제한 SID 목록.** 둘 다 사용자 SID를 넣지 않습니다. 그래서 사용자 레지스트리 키처럼 DACL이 사용자 SID에만 쓰기를 허용하는 곳에는 쓰지 못합니다. QwenPaw에서는 이것을 실측으로 확인했습니다.
- [QwenPaw 비관리자 토큰](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_unelevated_sandbox.py#L1630-L1700) · [QwenPaw 관리자 토큰](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_elevated_sandbox.py#L738-L800) · [Codex 토큰과 기본 DACL](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/token.rs#L54-L112) · [Codex 제한 SID 목록 순서](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/token.rs#L470-L523)

## 3. 쓰기 허용 ACE를 추가하는 방법

**capability SID**
- **QwenPaw:** 샌드박스 인스턴스마다 무작위 SID를 하나 만들고, 같은 설정이면 다시 씁니다. [생성](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_unelevated_sandbox.py#L634-L641)
- **Codex:** 작업 폴더(실행 위치)마다, 추가 쓰기 경로마다 무작위 SID를 따로 만들어 `CODEX_HOME\cap_sid`에 평문 JSON으로 저장합니다. 토큰에는 지금 실행에 해당하는 SID만 넣습니다. 따라서 설계상 작업 폴더 A에서 실행한 명령은, B의 DACL이 Everyone이나 로그온 SID에 쓰기를 허용하지 않는 한 작업 폴더 B에 쓰지 못합니다. [Codex capability SID](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/cap.rs#L15-L126)

**쓰기 허용 ACE**
- **공통점.** 네 구성 모두 읽기·쓰기·실행·삭제 허용 ACE를 하위 폴더와 파일에 상속되게 추가합니다.
- **차이: `FILE_DELETE_CHILD`(폴더 안의 파일·하위 폴더를 삭제하는 권한).**
  - QwenPaw 비관리자와 Codex 두 방식은 넣지 않습니다. Codex 소스는 이를 "하위 경로의 거부 ACE가 계속 효과를 갖게 하려는 것"이라고 설명합니다.
  - QwenPaw 관리자는 넣습니다. 폴더에 이 권한이 있으면, 파일 자체의 DACL이 삭제를 거부해도 그 파일을 삭제할 수 있습니다.
  - [QwenPaw 비관리자 마스크](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_unelevated_sandbox.py#L107-L111) · [QwenPaw 관리자 마스크](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_elevated_sandbox.py#L888-L898) · [Codex 마스크 설명](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/acl.rs#L513-L517)
- **QwenPaw 비관리자:** 작업 폴더와 쓰기 가능 마운트에만 추가합니다. 읽기 전용 마운트는 건너뜁니다. [마운트 처리](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_unelevated_sandbox.py#L2343-L2360)
- **QwenPaw 관리자:** capability SID와 전용 계정 SID 각각의 ACE를 추가합니다. 읽기 전용 마운트에는 읽기 허용 ACE만 추가합니다. 작업 폴더까지의 상위 폴더에는 경로 탐색 허용 ACE를 추가합니다. [관리자 ACE](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_elevated_sandbox.py#L1612-L1660)
- **Codex:** 가장 구체적인 쓰기 경로의 capability SID에 대한 ACE를 추가합니다. `elevated`는 샌드박스 그룹 SID에 대한 ACE도 추가합니다. `CODEX_HOME`과 사용자 프로필 루트, 프로필 아래 민감 폴더(`.ssh`, `.aws`, `.azure`, `.kube`, `.docker`, `.config`, `.gnupg` 등)는 쓰기 경로에서 뺍니다. [쓰기 경로 제외](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/setup.rs#L1356-L1477)

**ACE를 추가할 수 없는 쓰기 경로**
- ACE를 추가하려면 그 폴더의 DACL을 바꿀 권한(`WRITE_DAC`)이 필요합니다. 폴더 소유자는 이 권한을 가지지만, Administrators가 소유한 폴더에는 일반 사용자에게 이 권한이 대개 없습니다. UAC 승격 전 토큰에서는 Administrators 그룹이 거부 전용이라 사용자가 관리자 그룹 구성원이어도 같습니다.
- **Codex `elevated`:** 갱신 단계가 현재 사용자 권한으로 실행되므로, 추가 쓰기 경로(설정의 쓰기 경로나 승인된 추가 권한)가 이런 폴더이면 ACE 추가가 실패합니다. 갱신 도우미는 실패를 모아 오류로 끝내고, 명령은 시작하지 않습니다. 관리자 권한으로 실행하는 최초 설치 단계도 작업 폴더·쓰기 경로의 ACE는 추가하지 않습니다. [쓰기 ACE 실패 처리](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/setup_provisioning.rs#L1101-L1281)
- **QwenPaw 비관리자:** 작업 폴더나 쓰기 가능 마운트에 ACE를 추가하지 못하면 로그만 남기고 명령을 실행합니다. 그 폴더 쓰기는 두 번째 검사에서 거부될 것으로 예상합니다. [마운트 ACE 실패 처리](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_unelevated_sandbox.py#L2323-L2360)
- **QwenPaw 관리자:** QwenPaw가 관리자로 실행되므로, Administrators가 DACL 변경 권한을 가진 폴더라면 ACE 추가가 성공합니다. 관리자 소유 폴더의 DACL이 실행 중 바뀌고, 정리 함수가 다시 삭제합니다.
- **Codex `unelevated`:** ACE 추가 실패를 무시하고 명령을 실행합니다. 그 폴더 쓰기는 두 번째 검사에서 거부될 것으로 예상합니다. [ACE 실패 무시](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/spawn_prep.rs#L289-L305)

**작업 폴더 안 보호 경로**
- **Codex:** `.git`(gitdir 포인터가 가리키는 실제 위치 포함), `.agents`, `.codex`와 사용자가 지정한 읽기 전용 경로에 **쓰기 거부 ACE**를 상속되게 추가합니다. 해당 쓰기 경로의 capability SID들이 대상입니다. `.git`과 `.agents`는 명령 시작 시점에 있을 때만 보호 대상이 되고, `.codex`는 없어도 보호 대상입니다. 따라서 `.git`이 없는 작업 폴더에서는 샌드박스 명령이 `.git`을 새로 만들 수 있을 것으로 예상합니다. 실측에서는 시작 시점에 없던 `.codex`도 두 Codex 구성 모두 만들 수 있었습니다. `elevated`에서 이렇게 만든 폴더는 소유자가 샌드박스 계정이라, 다음 명령의 갱신 단계가 거부 ACE를 붙이지 못하고 그 작업 폴더의 명령이 모두 실패했습니다. [실측](../runs/2026-11-25-01.md#4-파일-쓰기-b) 사용자가 지정한 읽기 전용 경로는 없으면 미리 폴더로 만들어 둡니다. [보호 경로 기본값](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/protocol/src/permissions.rs#L2395-L2438) · [쓰기 거부 ACE](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/acl.rs#L852-L989)
- **QwenPaw:** 쓰기 거부 ACE를 추가하지 않습니다. QwenPaw 실측에서 읽기 전용 하위 폴더 보호가 실패한 원인은 상속된 쓰기 허용 ACE만 있고 거부 ACE가 없었기 때문입니다. Codex는 이 경우를 쓰기 거부 ACE로 처리합니다.

**임시 폴더**
- **QwenPaw 비관리자:** 호스트의 `TEMP` 값을 그대로 전달하고, 그 폴더에 쓰기 허용 ACE를 추가하지 않습니다. 실측에서 임시 폴더 쓰기가 5/5 거부됐습니다.
- **QwenPaw 관리자:** `USERPROFILE`, `TEMP`, `TMP`를 전용 계정의 프로필로 바꿉니다. [환경 설정](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_elevated_sandbox.py#L2408-L2414)
- **Codex:** 두 방식 모두 `TEMP`·`TMP` 값을 바꾸지 않습니다. 대신 정책에 임시 폴더가 포함되면 그 폴더를 쓰기 경로로 지정해 capability SID의 쓰기 허용 ACE를 추가합니다. 결과적으로 사용자의 실제 임시 폴더에 쓰기가 허용됩니다. [임시 폴더 해석](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/resolved_permissions.rs#L175-L208)

## 4. 읽기 범위와 읽기 거부

| 항목 | QwenPaw 비관리자 | Codex `unelevated` | QwenPaw 관리자 | Codex `elevated` |
| --- | --- | --- | --- | --- |
| 기본 읽기 범위 | 현재 사용자가 읽는 것 전부 | 현재 사용자가 읽는 것 전부(전체 읽기 정책만 지원) | 전용 계정 SID에 대한 DACL에 따름. 사용자 프로필 DACL에는 전용 계정이 없어 대개 읽기 거부 | 전체 읽기 정책 필수(작업 폴더가 있는 드라이브 루트를 읽을 수 있어야 하고, 일부 경로는 읽기 거부로만 제외). 명령마다 Windows 폴더, Program Files, ProgramData, 작업 폴더, **사용자 프로필 바로 아래의 각 항목**에 읽기 허용 ACE 추가(민감 폴더 제외) |
| 읽기 거부 요청 시 | 미지원 경고 후 그대로 실행 | 실행을 거부("샌드박스 없이 실행하지 않음") | 이미 있는 경로에 전용 계정 SID 대상 거부 ACE | 샌드박스 그룹 SID 대상 읽기 거부 ACE. 시작 전에 동기 적용, 글롭은 시작 시점에 존재하는 경로로 확장 |
| 거부 ACE 정리 | 해당 없음 | 해당 없음 | 정리 함수가 삭제 | 남겨 두고, 다음 동기화 때 필요 없어진 것만 삭제 |

- **적용할 수 없을 때의 동작이 반대입니다.** QwenPaw 비관리자는 읽기 거부를 적용할 수 없어도 경고만 남기고 실행합니다. Codex `unelevated`는 적용할 수 없는 정책이면 명령을 시작하지 않습니다.
- **`elevated` 계열의 읽기 범위.**
  - QwenPaw 관리자는 별도 계정을 쓰므로, 사용자 프로필 폴더 DACL에 전용 계정 SID가 없어 기본적으로 읽기가 거부됩니다. 실측(2026-11-25)에서 결과가 갈렸습니다.
    - 거부: 사용자만 허용한 파일, `.ssh`, `~/.codex`, `.gitconfig`, 사용자 하이브.
    - 허용: `Users`·`Everyone` 읽기가 프로필 루트에서 상속되는 위치(`AppData`, 프로필 아래 새 폴더). 이 PC의 프로필 루트에는 그 상속 ACE가 있었습니다. [실측](../runs/2026-11-25-02.md#6-파일-읽기-c)
  - Codex `elevated`도 작업 폴더가 있는 드라이브 루트를 읽을 수 있는 정책이어야 실행합니다. 일부 경로를 빼려면 읽기 거부 경로를 지정합니다. [드라이브 루트 읽기 확인](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/resolved_permissions.rs#L105-L117)
  - Codex `elevated`는 명령을 실행할 때마다 현재 사용자 권한으로 설치 도우미(`codex-windows-sandbox-setup.exe`)를 갱신 모드로 실행합니다. 갱신 모드는 그 명령의 작업 폴더를 기준으로 읽기·쓰기 경로 목록을 다시 만들고 ACE를 추가하며, UAC 승인을 요청하지 않습니다. 관리자 권한으로 실행하는 최초 설치 단계는 이 ACE를 추가하지 않습니다. 이전 작업 폴더에 추가한 ACE는 삭제하지 않습니다. [명령마다 갱신](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/identity.rs#L267-L311) · [갱신은 승격 없이 실행](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/setup.rs#L377-L426)
  - 읽기 경로 목록에는 사용자 프로필 바로 아래의 항목(폴더와 파일)이 들어가고, 각 항목에 샌드박스 그룹(`CodexSandboxUsers`)의 읽기·실행 허용 ACE를 하위로 상속되게(`OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE`) 추가합니다. 프로필 폴더 자체에는 추가하지 않습니다. 해당 경로의 DACL이 이미 Users, Authenticated Users, Everyone 중 하나에 읽기를 허용하면 추가하지 않습니다. [읽기 경로 수집](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/setup.rs#L555-L621) · [읽기 ACE 추가](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/setup_provisioning.rs#L241-L295)
  - 다른 계정을 써도 읽기가 넓은 이유는 두 가지입니다. 첫째, 위의 읽기 허용 ACE가 사용자 프로필의 기본 DACL(SYSTEM, Administrators, 사용자 본인만 허용)을 넓힙니다. 둘째, 프로필 밖의 폴더는 Windows 기본 DACL이 Users나 Authenticated Users에 읽기를 허용하는 경우가 많아, 어느 로컬 계정이든 읽을 수 있습니다.
  - 제외되는 것은 `.ssh`, `.tsh`, `.brev`, `.gnupg`, `.aws`, `.azure`, `.kube`, `.docker`, `.config`, `.npm`, `.pki`, `.terraform.d`와 `~/.ssh/config`의 `IdentityFile`·`Include`가 가리키는 경로입니다. 제외는 읽기 허용 ACE를 추가하지 않는다는 뜻이며, 거부 ACE를 추가하지는 않습니다.
  - `AppData`, `.codex`는 제외 목록에 없습니다. Codex 시험 코드도 `AppData`가 제외 대상이 아님을 확인합니다. 프로필 바로 아래의 `.gitconfig`, `.npmrc` 같은 파일도 이름이 목록에 없으면 읽기 허용 ACE를 받습니다. [제외 목록](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/setup.rs#L59-L78) · [`AppData` 시험](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/setup.rs#L2263-L2298)
  - 따라서 `~/.codex` 아래의 인증·설정 파일을 샌드박스 계정이 읽을 수 있는지가 실측에서 먼저 확인할 항목입니다. 비밀번호 폴더(`.sandbox-secrets`)에만 거부 ACE가 있습니다.
- [Codex 비관리자 읽기 제약](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/lib.rs#L746-L755) · [Codex 실행 거부 조건](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/sandboxing/src/windows.rs#L115-L162) · [Codex 읽기 허용 경로](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/setup.rs#L591-L621) · [Codex 읽기 거부 적용](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/setup_provisioning.rs#L998-L1015)

## 5. 네트워크

**Restricted Token에서 인터넷을 허용·거부하는 방법**

Restricted Token 자체에는 네트워크 연결을 제한하는 기능이 없습니다. 그래서 제품은 토큰 밖의 방법을 씁니다.
- **프록시 환경 변수(관리자 권한 불필요).** 아무것도 수신하지 않는 주소를 프록시 환경 변수로 설정합니다. 그 변수를 사용하는 프로그램만 연결에 실패하고, 사용하지 않는 프로그램과 DNS 조회는 막지 못합니다. QwenPaw 비관리자와 Codex `unelevated`가 이 방법을 씁니다.
- **별도 계정과 방화벽 규칙(관리자 권한 필요).** 샌드박스를 별도 계정으로 실행하고, 그 계정의 연결을 차단하는 Windows 방화벽 규칙을 추가합니다. Windows가 모든 연결에 적용합니다. QwenPaw 관리자와 Codex `elevated`가 이 방법을 쓰고, Codex는 WFP 필터를 더합니다.
- **허용.** 위 설정을 하지 않습니다. 프록시 환경 변수를 넣지 않거나, 방화벽 규칙이 없는 계정으로 실행합니다.
- **특정 도메인만 허용.** 모든 연결을 프록시로 거치게 강제하고, 그 프록시가 도메인을 걸러야 합니다.

이 비교에서는 네트워크 차단을 측정하지 않습니다.

**QwenPaw 비관리자**
- 차단하면 프록시 환경 변수를 아무것도 수신하지 않는 주소(`127.0.0.1:9`)로 지정하고, `NO_PROXY`는 비웁니다.
- 프록시 환경 변수를 사용하는 프로그램은 로컬 연결까지 실패하지만, 사용하지 않는 프로그램은 직접 연결됩니다(실측 5/5).
- [소스](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_unelevated_sandbox.py#L2376-L2384)

**Codex `unelevated`**
- 같은 방식의 프록시 환경 변수에 더해 다음을 설정합니다.
  - `NO_PROXY=localhost,127.0.0.1,::1`(로컬 연결은 허용)
  - `PIP_NO_INDEX`, `NPM_CONFIG_OFFLINE`, `CARGO_NET_OFFLINE`
  - 실패하는 `GIT_SSH_COMMAND`
  - `ssh`·`scp`를 대신하는 실패용 파일을 PATH 앞에 둠
- 모두 **값이 없을 때만** 넣으므로, 사용자가 원래 프록시를 지정해 두었다면 그 값이 남습니다.
- 방화벽이나 WFP는 쓰지 않습니다. 프록시 환경 변수를 사용하지 않는 프로그램은 QwenPaw와 마찬가지로 직접 연결될 것으로 예상합니다.
- [Codex 오프라인 환경 변수](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/env.rs#L105-L177)

**QwenPaw 관리자**
- 네트워크를 전부 허용하지 않으면 전용 계정 SID에 대해 들어오고 나가는 연결을 모두 막는 Windows 방화벽 규칙을 만듭니다.
- 로컬 연결 전용 규칙은 따로 없습니다.
- [방화벽 규칙](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_elevated_sandbox.py#L1672-L1700)

**Codex `elevated`**
- 네트워크를 막거나 프록시를 강제할 때는 오프라인 계정, 아니면 온라인 계정으로 실행합니다. 온라인 계정에는 아무 규칙도 없습니다.
- 오프라인 계정의 방화벽 규칙은 다음과 같습니다.
  - 로컬이 아닌 주소로 나가고 들어오는 연결을 막습니다.
  - 로컬 UDP를 막고, 로컬 TCP는 프록시 포트만 남기고 막습니다.
  - `allow_local_binding`이면 로컬 규칙을 지웁니다.
- 영구 WFP 필터로 ICMP와 포트 53·853·445·139도 막습니다. 다만 WFP는 소스에 "최선 노력"으로 적혀 있습니다.
- 관리형 네트워크 프록시는 `elevated`에서만 지원합니다.
- [Codex 방화벽 규칙](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/setup_provisioning/firewall.rs#L117-L237) · [Codex WFP 필터](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/wfp/filter_specs.rs#L25-L124) · [계정 선택](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/setup.rs#L755-L764)

## 6. 환경 변수, 데스크톱, 클립보드

**환경 변수.** 네 구성 모두 호스트의 환경 변수를 거의 그대로 넘기고 허용 목록 필터가 없습니다. QwenPaw 실측에서 시험용 환경 변수가 노출된 결과는 Codex에서도 반복될 것으로 예상합니다. [Codex 환경 블록](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/process.rs#L53-L80)

**데스크톱**
- **QwenPaw 비관리자:** 사용자 기본 데스크톱(`WinSta0\Default`)에서 실행합니다. [소스](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_unelevated_sandbox.py#L1909)
- **QwenPaw 관리자:** 전용 계정에 사용자의 창 스테이션과 데스크톱 접근 권한을 줘서 같은 데스크톱을 씁니다. [소스](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_elevated_sandbox.py#L1713-L1730)
- **Codex:** 두 방식 모두 같은 창 스테이션 안에 별도 데스크톱(`CodexSandboxDesktop-<번호>`)을 만들어 실행합니다. 샌드박스 프로세스의 창이 사용자 데스크톱에 표시되지 않고, 사용자 데스크톱의 창에 입력을 보내는 것도 제한됩니다. [Codex 데스크톱](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/desktop.rs#L263-L458)

**클립보드.**
- Windows 클립보드는 창 스테이션 단위로 공유됩니다. Codex도 별도 창 스테이션은 만들지 않고, 클립보드를 다루는 코드도 없습니다.
- 그래서 QwenPaw 실측의 "클립보드가 열린다"는 결과는 Codex에서도 반복될 것으로 예상합니다. 이 비교에서는 측정하지 않습니다.
- 두 제품의 샌드박스 소스와 QwenPaw 보안 문서에는 클립보드를 다루는 코드나 설명이 없습니다. Job 객체의 UI 제한(`JOB_OBJECT_UILIMIT_READCLIPBOARD`·`WRITECLIPBOARD`)도 설정하지 않습니다.
- Codex 자체 시험 목록에도 클립보드 항목은 없습니다. 화면 쪽 문제로는, 샌드박스 안에서 `Start-Process`로 URL을 여는 명령이 차단되지 않는 것이 "GUI 탈출이 고쳐질 때까지 알려진 실패(KNOWN FAIL until GUI escape fixed)"로 표시돼 있습니다. 시험은 명령의 종료 코드만 보며, 열린 브라우저가 어느 계정·데스크톱에서 실행되는지는 확인하지 않았습니다. [Codex 시험 목록](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/sandbox_smoketests.py#L914-L930)

## 7. 프로세스 수명과 자원

| 항목 | QwenPaw 비관리자 | Codex `unelevated`·`elevated` |
| --- | --- | --- |
| Job 객체 | `KILL_ON_JOB_CLOSE`(Job 핸들이 닫히면 모든 프로세스 종료)만 설정 | `KILL_ON_JOB_CLOSE` + `BREAKAWAY_OK`(`CREATE_BREAKAWAY_FROM_JOB`으로 만든 자식은 Job 밖에서 실행). 프로세스를 만들 때 바로 Job에 넣고, 넣지 못하면 실행하지 않음 |
| 시간 초과 | Job 전체 종료(실측: 5초 안에 자식 종료 5/5) | 에이전트 경로에서는 시간 초과 때만 Job 전체 종료. `codex sandbox` 명령에는 시간 제한이 없음(`timeout_ms: None`) |
| 셸이 정상 종료한 뒤 남은 자식 | 시간 제한이 적용되지 않고 도구 호출이 반환되지 않음(실측 5/5) | `KILL_ON_JOB_CLOSE`를 해제해 자식 프로세스를 종료하지 않음(의도된 동작). 도구 호출 반환 여부는 실측으로 확인 |
| 프로세스 수·메모리 한도 | 없음(실측) | 없음 |

- **다른 프로세스 접근(2026-11-25 실측).**
  - **QwenPaw 관리자.** 별도 계정이고 `LogonUserW`로 만든 별도 로그온 SID를 가집니다. 그래서 다음을 모두 열지 못했습니다.
    - 사용자 프로세스. 로그온 SID ACE가 있는 explorer 등도 포함하며, `QUERY_LIMITED`로 22개만 열렸습니다.
    - 다른 작업 폴더의 샌드박스
    - 승격된 QwenPaw 작업자
    - [실측](../runs/2026-11-25-02.md#8-다른-프로세스-접근-p-g5)
  - **비관리자 두 구성.** 사용자 프로세스를 `VM_READ`·`TERMINATE`·`QUERY_LIMITED`로 열고, 그 토큰을 `DUPLICATE`·`IMPERSONATE`·`ASSIGN_PRIMARY`로 열었습니다. `VM_WRITE`·`VM_OPERATION`·`CREATE_THREAD`·`DUP_HANDLE`, 토큰 `ADJUST_DEFAULT`는 거부됐습니다. 허용·거부의 경계는 각 객체 형식의 `GENERIC_WRITE` 매핑과 일치합니다.
  - **Codex `elevated`.** 로그온 SID가 사용자 것과 같았습니다. `desktop.rs` 주석이 맞고 `token.rs` 주석은 실제와 다릅니다. 그래서 DACL이 로그온 SID에 권한을 주는 사용자 프로세스(explorer 포함 106개 중 96개)를 `VM_READ`·`TERMINATE`로 열었습니다. 로그온 SID ACE가 없는 프로세스는 열지 못했습니다.
  - **실행기와 다른 샌드박스.** Codex `elevated` 샌드박스 명령은 자기 실행기를 모든 권한으로 열었습니다. QwenPaw 비관리자와 Codex 두 구성은 동시에 실행 중인 다른 작업 폴더의 샌드박스 프로세스를 모든 권한으로 열었습니다.
  - [실측 결과](../runs/2026-11-25-01.md#8-다른-프로세스-접근-p-g5) · [desktop.rs 주석](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/desktop.rs#L287-L289) · [token.rs 주석](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/token.rs#L55)
- Codex는 백그라운드 개발 서버처럼 셸보다 오래 실행되는 프로세스를 의도적으로 허용합니다. 그 대신 그 프로세스는 Codex가 관리하지 않게 됩니다.
- `elevated`는 실행기와 명명된 파이프로 입출력을 주고받습니다. 이 파이프의 DACL은 샌드박스 계정만 허용하고, 연결한 프로세스의 PID도 확인합니다. 파이프 연결이 끊기면 실행기가 Job 전체를 종료합니다.
- [Codex Job 설정](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/utils/pty/src/win/job.rs#L72-L88) · [자식 보존](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/utils/pty/src/win/job.rs#L240-L278) · [QwenPaw Job 설정](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_unelevated_sandbox.py#L1060-L1075)

## 8. `elevated` 계열의 계정과 비밀번호

| 항목 | QwenPaw 관리자 | Codex `elevated` |
| --- | --- | --- |
| 계정 | 설정 지문마다 `qwenpaw_<12자리>` 계정을 새로 만듦 | 고정 계정 `CodexSandboxOffline`, `CodexSandboxOnline` |
| 그룹 | `QwenpawUsers` | `CodexSandboxUsers` |
| 로그온 방식 | 일괄 작업 로그온 권한을 주고 `LogonUser` | `CreateProcessWithLogonW`로 실행기 시작 |
| 비밀번호 | 무작위 생성. 현재 사용자 범위 DPAPI로 암호화해 메타데이터에 저장 | 24자 무작위, 설치 단계를 실행할 때마다 새로 생성. **컴퓨터 범위** DPAPI(`CRYPTPROTECT_LOCAL_MACHINE`)로 암호화해 `CODEX_HOME\.sandbox-secrets`에 저장. 이 폴더 DACL에 샌드박스 그룹 SID 대상 거부 ACE |
| 로그인 화면 | 숨기는 코드 없음 | 숨김(`Winlogon\SpecialAccounts\UserList`) |
| 로그온 권한 | 로컬 보안 정책에 "일괄 작업으로 로그온" 권한을 추가. 정리할 때 회수하는 코드는 찾지 못함(실측: 계정 삭제 뒤에도 SID 항목이 남음) | 별도 권한 추가 없음(`CreateProcessWithLogonW`) |
| 사용자 프로필 | `CreateProfile`로 전용 계정 프로필을 만들고, 자식의 `USERPROFILE`·`APPDATA`·`LOCALAPPDATA`·`TEMP`·`TMP`·`HOMEPATH`를 그 프로필로 바꿈 | 명시적으로 만들지 않음. 자식 환경 변수는 호출자 값 그대로 |
| 정리 | 정리 함수가 ACE, 방화벽 규칙, 계정, 프로필을 삭제 | 계정·그룹·방화벽 규칙·WFP 필터가 계속 남음. `codex sandbox uninstall`(관리자)로만 제거하며, 이때도 파일 ACE와 `.sandbox*` 폴더는 남김 |

- **비밀번호 암호화 범위.**
  - QwenPaw는 DPAPI 사용자 범위(현재 사용자만 복호화)로 암호화합니다.
  - Codex는 관리자 프로세스와 일반 프로세스가 모두 복호화할 수 있도록 DPAPI 컴퓨터 범위(이 PC의 모든 계정이 복호화)로 암호화합니다. 대신 폴더 DACL에 샌드박스 그룹 SID 대상 거부 ACE를 추가합니다.
- **계정 관리 방식.**
  - QwenPaw는 설정 지문마다 첫 명령 때 계정을 만들고, 같은 설정의 다음 명령에서는 그 계정과 토큰을 다시 씁니다. QwenPaw 프로세스가 끝날 때(`atexit`) 정리 함수가 계정, 프로필, 방화벽 규칙, 기록된 ACE를 삭제합니다. `QwenpawUsers` 그룹과 Python 폴더의 그룹 읽기·실행 ACE는 삭제하지 않습니다. [재사용](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_elevated_sandbox.py#L2326-L2340) · [종료 시 정리](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_elevated_sandbox.py#L2746-L2789) · [Python 폴더 그룹 ACE](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_elevated_sandbox.py#L1484-L1523)
  - Codex는 계정을 한 번 만들어 두고 계속 사용합니다. 대신 명령마다 설치 도우미를 갱신 모드로 실행해 ACE를 확인·추가하고, 실행기를 샌드박스 계정 로그온으로 새로 시작합니다.
  - 따라서 시간 비용이 생기는 시점이 다릅니다. QwenPaw는 첫 명령과 프로세스 종료 때, Codex는 최초 설치 때와 명령마다입니다.
  - **실측(2026-11-25).** QwenPaw 관리자의 시간과 계정 재생성은 다음과 같았습니다.
    - 첫 명령(계정 생성 포함)은 0.77~1.00초였고, 그중 프로필 생성이 0.38~0.47초였습니다.
    - 같은 설정의 반복 명령 중앙값은 0.25초, 정리는 0.14~0.31초였습니다.
    - 정리로 계정을 지운 뒤 같은 설정으로 다시 만들면, 이름은 같아도 SID가 새로 발급됐습니다(측정 중 20회 생성, 이름 3가지). [실측](../runs/2026-11-25-02.md#11-시간-h)
- [QwenPaw 계정 준비](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_elevated_sandbox.py#L558-L672) · [QwenPaw 관리자 환경 변수](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_elevated_sandbox.py#L2400-L2416) · [QwenPaw 관리자 기본 DACL](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_elevated_sandbox.py#L812-L815) · [QwenPaw 정리](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_elevated_sandbox.py#L2887-L2940) · [Codex 계정 생성](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/setup_provisioning/sandbox_users.rs#L86-L177) · [Codex DPAPI 범위](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/dpapi.rs#L20-L40) · [Codex 제거 범위](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/windows-sandbox-rs/src/uninstall_windows.rs#L21-L41)

## 9. 실행 후 남는 항목

- **QwenPaw 두 구성의 시점.** 첫 명령 때(샌드박스 생성) ACE와, 관리자 방식이면 계정·방화벽 규칙을 만들고, 같은 QwenPaw 프로세스의 다음 명령에서 다시 씁니다. QwenPaw 프로세스가 끝날 때 `atexit`에 등록된 정리 함수가 삭제합니다. 명령 하나가 끝날 때나 `stop()`으로는 삭제되지 않습니다(실측 5/5). [비관리자 정리 등록](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_unelevated_sandbox.py#L3070)
- **QwenPaw 비관리자.** QwenPaw 프로세스가 실행 중인 동안에만 작업 폴더에 ACE가 있고, 종료 시 정리 함수가 삭제합니다. 비정상 종료하면 다음 실행의 정리까지 남습니다(실측 5/5).
  - 예외가 있습니다. 같은 설정의 다음 실행은 `icacls` 출력에서 이전 capability SID를 찾아 재사용 여부를 정합니다.
  - SID 조회가 실패하는 PC(도메인 트러스트 오류 등)에서는 `icacls`가 SID를 출력하지 않아 이 확인이 항상 실패합니다. 그러면 새 SID로 메타데이터를 덮어쓰고 이전 ACE는 기록 없이 계속 남습니다(2026-11-25 실측, 강제 종료 15회 → ACE 15개). [실측](../runs/2026-11-25-01.md#6-qwenpaw-작업-폴더에-남은-capability-sid-ace)
- **QwenPaw 관리자(2026-11-25 실측).** 정리 함수는 다음을 지웠습니다.
  - 지운 것: 계정, 프로필 폴더, 메타데이터, 시험 경로의 ACE(작업 폴더, mount, 거부 폴더, 관리자 소유 폴더).
    - ACE 제거는 Win32 API로 하므로 도메인 트러스트 오류의 영향을 받지 않았습니다.
    - 명령 실행 중에 작업자를 강제 종료하면 계정과 메타데이터가 남고, 다음 실행의 정리가 지웠습니다.
  - 정리 뒤에도 남은 것: 다음 항목이 **계정을 만들 때마다 하나씩** 남았습니다.
    - ProfileList 키
    - "일괄 작업으로 로그온" 권한 항목
    - `WinSta0` ACE와 `Default` 데스크톱 ACE
    - `\\.\NUL` 장치 ACE
  - 정리 뒤에도 남은 것(한 세트): `QwenpawUsers` 그룹, Python 환경 폴더의 그룹 ACE와 표시 파일.
  - [실측](../runs/2026-11-25-02.md#12-정리와-pc에-남는-것)
- **Codex `unelevated`.**
  - 쓰기 허용 ACE와 보호 경로의 쓰기 거부 ACE를 **삭제하지 않습니다**.
  - 매번 같은 ACE가 있는지 확인하고 없으면 다시 추가합니다.
  - `CODEX_HOME\cap_sid` 파일도 계속 남습니다.
- **Codex `elevated`.** 계정, 그룹, 방화벽 규칙, WFP 필터, 로그인 화면 계정 숨김 레지스트리 값, 프로필, 모든 ACE, `.sandbox*` 폴더가 남습니다. 명령마다 새로 하는 것은 설치 도우미 갱신 실행(작업 폴더 기준 ACE 확인·추가), 실행기 시작, 토큰 생성, Job 생성입니다.
  - **읽기 거부 ACE.** 설정에서 경로를 지워도 남습니다.
    - 소스는 이전 경로의 ACE를 `revoke_ace`로 지우려고 합니다. 그러나 이 함수가 쓰는 `REVOKE_ACCESS`는 허용 ACE만 지우고 거부 ACE는 남깁니다.
    - 상태 파일에서는 경로가 지워지므로 이후에도 정리되지 않습니다. 시험 폴더 재현과 실측으로 확인했습니다. [실측](../runs/2026-11-25-01.md#거부-설정을-지워도-codex-elevated의-거부-ace가-남음)

QwenPaw에서 실행 후 항목이 남는 것은 정리 실패입니다. Codex에서 항목이 남는 것은 의도된 동작입니다. 그래서 Codex를 측정할 때는 남는지 여부가 아니라 무엇이 남고 그것이 어떤 접근을 허용하는지를 기록해야 합니다.

## 10. QwenPaw 실측 결과가 Codex에서 반복될지

| QwenPaw 비관리자 실측 결과 | Codex `unelevated` 예상 | Codex `elevated` 예상 | 근거 |
| --- | --- | --- | --- |
| 작업 폴더 밖 파일 읽기 허용 | 반복 | 대부분 반복(사용자 프로필 하위 폴더에 읽기 허용 ACE 추가). 민감 폴더와 다른 사용자 파일은 달라질 수 있음 | 4장 |
| Everyone 쓰기 허용 폴더에 쓰기 성공 | 반복 | 반복 | 제한 SID 목록에 Everyone 포함 |
| 사용자 레지스트리 쓰기 거부 | 반복 | 실제 사용자 레지스트리와 분리됨 | 제한 SID 목록에 사용자 SID 없음 / 다른 계정 |
| 프록시 환경 변수를 사용하지 않는 연결 성공 | 반복 | 오프라인 계정이면 차단 | 방화벽·WFP 유무 |
| 로컬 연결 | 허용(`NO_PROXY`에 로컬 포함) | 오프라인 계정이면 프록시 포트 외 차단 | 5장 |
| 읽기 전용 하위 폴더 실패 | `.git` 등 보호 경로와 지정 경로에 쓰기 거부 ACE가 있어 달라질 것 | 같음 | 3장 |
| 임시 폴더에 쓰지 못함 | 임시 폴더가 쓰기 경로가 되어 달라질 것 | 같음 | 3장 |
| 환경 변수 노출 | 반복 | 반복 | 필터 없음 |
| 클립보드 열림 | 반복 가능성 | 반복 가능성 | 같은 창 스테이션 |
| 시간 초과 시 자식 종료 | 반복(에이전트 경로) | 반복(에이전트 경로) | Job 전체 종료. `codex sandbox` 명령으로는 측정할 수 없음 |
| 백그라운드 자식 때문에 도구 호출이 반환되지 않음 | 자식은 계속 실행됨. 호출 반환은 확인 필요 | 같음 | 자식을 종료하지 않는 설계 |
| 자원 한도 미집행 | 반복 | 반복 | Job 한도 없음 |
| 명명된 파이프 병렬 빌드 실패 | 확인 필요 | 확인 필요 | 기본 DACL과 `WRITE_RESTRICTED` 검사 |
| 정리 후 남는 항목 없음 | ACE가 의도적으로 남음 | 계정·방화벽 규칙까지 남음 | 9장 |

### 2026-11-25 실측 결과

위 예상을 네 구성에서 각 5회 측정했습니다. QwenPaw 비관리자와 Codex 두 구성은 일반 세션에서, QwenPaw 관리자는 사용자가 UAC를 승인한 세션에서 측정했습니다. [UAC 없는 세 구성](../runs/2026-11-25-01.md) · [UAC 단계](../runs/2026-11-25-02.md)

| 예상 | Codex `unelevated` 실측 | Codex `elevated` 실측 | QwenPaw 관리자 실측 |
| --- | --- | --- | --- |
| 작업 폴더 밖 읽기 | 반복. 사용자 범위 DPAPI 복호화도 허용 | 사용자만 허용한 파일, `.ssh`, `.sandbox-secrets`, 사용자 레지스트리 하이브는 거부. `~/.codex` 인증·설정 파일, `AppData`, `.gitconfig`, 프로필 아래 새 폴더는 허용 | 사용자만 허용한 파일, `.ssh`, `~/.codex`, `.gitconfig`, 사용자 하이브, 사용자 범위 DPAPI는 거부. `Users`·`Everyone` 읽기가 상속되는 `AppData`·프로필 아래 새 폴더와 컴퓨터 범위 DPAPI는 허용 |
| Everyone 쓰기 허용 폴더에 쓰기 | 반복. 로그온 SID에 쓰기를 준 폴더·레지스트리 키도 씀 | 같음 | Everyone은 반복. 사용자 로그온 SID에 쓰기를 준 위치는 거부(별도 로그온 SID) |
| 사용자 레지스트리 쓰기 거부 | 반복 | 반복. HKCU는 `.DEFAULT`를 가리킴 | 반복. HKCU는 샌드박스 계정 하이브 |
| 보호 경로 | 시작 전에 있던 `.git`·`.codex`·`.agents`·`ro`는 쓰기·이름 변경·삭제 모두 거부. 없던 폴더는 새로 만들 수 있음 | 같음. 새로 만든 폴더 때문에 그 작업 폴더의 다음 명령이 모두 실패 | 보호 없음(QwenPaw 비관리자와 같음) |
| 임시 폴더 | 쓰기 허용. 같은 `TEMP`를 쓰는 다른 작업 폴더 실행의 파일도 덮어씀 | 같음 | 계정 프로필의 `Temp`에 씀. 작업 폴더마다 계정이 달라 공유 없음 |
| 읽기 거부 | 실행 거부 | 기존·새 파일·하드 링크는 거부, 옮겨 온 파일은 허용. 설정에서 지워도 거부 ACE가 남음 | 기존·새 파일·하드 링크는 거부, 옮겨 온 파일은 허용. 정리 때 거부 ACE 삭제 |
| 환경 변수 노출 | 반복 | 반복 | 반복. 프로필 관련 변수만 계정 프로필로 바꿈 |
| 백그라운드 자식과 호출 반환 | 표준 출력을 물려받은 손자가 있으면 손자가 끝날 때까지 반환하지 않음. 출력을 `NUL`로 돌리면 바로 반환하고 손자는 계속 실행 | 같음 | 표준 출력 상속 시 손자가 끝날 때까지 반환하지 않음. `NUL`이면 약 8초 뒤 반환 |
| Job 밖 프로세스 | `CREATE_BREAKAWAY_FROM_JOB`으로 띄운 손자는 제품 종료 뒤에도 실행 | 같음 | 손자 시작 자체가 거부 |
| 명명된 파이프 병렬 빌드 | 실패(`WinError 5`) | 성공 | 성공 |
| 다른 프로세스 접근 | 사용자 프로세스 거의 전부를 메모리 읽기·종료·토큰 복제 권한으로 열 수 있음 | DACL이 로그온 SID에 권한을 주는 사용자 프로세스를 같은 권한으로 열 수 있음. 실행기는 모든 권한으로 열림 | 사용자 프로세스, 다른 작업 폴더 샌드박스, 승격된 작업자 모두 거부(`QUERY_LIMITED`만 22개) |
| 데스크톱 | 사용자 데스크톱에 창이 보이지 않음 | 같음 | 사용자 데스크톱에 창이 보임. 샌드박스 계정에 `WinSta0`·`Default` 전체 권한 ACE |
| 사용자가 DACL을 바꿀 수 없는 폴더를 쓰기 경로로 지정(B10) | 실행, 쓰기 거부 | 명령 실행 거부(갱신 단계 `WRITE_DAC` 실패) | 관리자 권한으로 ACE를 추가해 씀 |
| 다른 계정 하이브(R2) | QwenPaw 관리자 계정 하이브 읽기 거부 | — | 다른 비관리자 구성이 이 계정 하이브를 열지 못함 |

## 11. 실측할 때 주의할 점

- **이미 설치된 Codex `elevated`.** 측정 PC에 Codex `elevated`가 이미 설치돼 있으면, 그 계정·그룹·방화벽 규칙은 사용자가 실제로 쓰는 Codex 설정입니다.
  - Codex는 설치 단계를 다시 실행할 때 비밀번호를 새로 만들고 방화벽 규칙을 다시 씁니다.
  - 측정 전후 상태를 기록하고, 측정 때문에 설치 단계가 다시 실행되는지 확인해야 합니다. 그럴 수 없으면 시험용 PC나 가상 머신을 씁니다.
- **남는 ACE.** Codex `unelevated`·`elevated`는 작업 폴더와 임시 폴더에 ACE를 남깁니다.
  - 측정용 작업 폴더는 측정 전용 폴더로 한정합니다.
  - 임시 폴더는 측정 전에 측정 전용 폴더로 바꿔 사용자 임시 폴더에 ACE가 남지 않게 합니다.
- **어느 백엔드로 실행됐는지 확인.** 결과마다 실제로 선택된 백엔드와 권한 프로필을 기록합니다. Codex는 설정에 따라 MXC를 먼저 고를 수 있습니다.
