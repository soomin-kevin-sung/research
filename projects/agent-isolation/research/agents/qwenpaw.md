# QwenPaw의 Windows 실행 격리

2026-11-23 확인 · 안정 릴리스 `2.3.0.post1` · 대상은 AgentScope의 QwenPaw입니다. [QwenPaw v2.3.0.post1 릴리스](https://github.com/agentscope-ai/QwenPaw/releases/tag/v2.3.0.post1)

[조사 목록](../README.md)

관련 기술은 [AppContainer](../solutions/appcontainer.md) · [전용 계정·Restricted Token·ACL·WFP](../solutions/windows-accounts-tokens.md)에서 설명합니다.

## 거버넌스와 실제 실행 경로

QwenPaw는 Tool Guard·File Guard와 거버넌스 정책으로 도구 호출을 평가합니다. 셸 호출이 `SANDBOX_FALLBACK`으로 분기될 때 OS 샌드박스에서 실행하며, 정책에 따라 허용·거부·승인 요청 결과도 가능합니다. `SMART` 기본 정책의 모델과 Windows 백엔드의 기본 읽기 정책은 별개의 설정이므로, 측정할 때 실제 거버넌스 판정과 프로세스 백엔드를 함께 기록해야 합니다. [버전 고정 보안 문서](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/website/public/docs/security.en.md) · [거버넌스와 샌드박스 설계](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/website/public/blog/qwenpaw-sandbox.en.md)

## Windows 백엔드

| 조건 | 메커니즘 | 적용 범위 |
| --- | --- | --- |
| `allow_read_all=False` | AppContainer 프로필과 capability SID, Win32 API로 파일 ACL 적용 | 허용 경로와 기존 거부 경로를 초기 ACL에 반영. 네트워크는 capability로 제어 |
| `allow_read_all=True` (기본값), 관리자 권한 있음 | 전용 로컬 사용자와 `CreateRestrictedToken`의 `WRITE_RESTRICTED`, ACL, WFP 방화벽 | 읽기는 기본적으로 넓게 허용하고 쓰기는 허용 경로로 제한. 전체 네트워크 차단을 WFP가 강제할 수 있음 |
| `allow_read_all=True` (기본값), 관리자 권한 없음 | 현재 토큰에서 파생한 `WRITE_RESTRICTED`와 ACL | 제한 쓰기를 제공하며 기본 실행 경로에서 명시적 읽기 거부를 집행하지 않음. 네트워크 차단 요청은 프록시 환경 변수 수준이며 직접 연결을 OS 수준에서 강제 차단하지 못함 |

릴리스의 팩토리는 Windows 백엔드를 `SandboxMode.WINDOWS`로 표현하고 `allow_read_all` 및 관리자 권한을 바탕으로 클래스를 선택합니다. 백엔드를 사용할 수 없어 `none`이 선택되면 명령 전달, 시간 제한, 환경 설정 등만 남습니다. 정책이 요청한 격리 제약을 백엔드가 강제하지 못할 때는 로그에 표시합니다. [백엔드 선택과 기능 경고 소스](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/config.py) · [Windows AppContainer 소스](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_appcontainer_sandbox.py)

## 네트워크와 환경 변수의 제약

AppContainer와 관리자 Restricted Token에서 실질적으로 비교할 수 있는 범위는 전체 허용과 전체 차단입니다. 도메인 목록을 주면 AppContainer는 네트워크를 열고 WFP 경로는 전체 차단으로 처리할 수 있다고 해당 버전 문서에 명시돼 있습니다. `env_mode="allowlist"`는 구현되지 않아 자식 환경이 현재 환경을 상속하고 지정 변수를 덧씁니다. 프로세스 수와 메모리 한도 설정도 이 버전에서 강제되지 않습니다. [보안 문서의 구현 제약](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/website/public/docs/security.en.md#current-limitations)

AppContainer 프로필은 동일 구성에서 재사용됩니다. [Windows 프로필 재사용 설계](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/website/public/blog/qwenpaw-sandbox.en.md)

### Restricted Token으로 셸을 실행하는 방식

Windows 샌드박스 분기에서 기본값 `allow_read_all=True`이면 QwenPaw는 `CreateRestrictedToken`으로 제한 SID 목록이 있는 토큰을 만들고 `WRITE_RESTRICTED`를 적용합니다. QwenPaw는 작업 폴더 등 쓰기를 허용한 경로의 ACL에 샌드박스용 SID 권한을 부여하고, 생성한 토큰으로 셸을 시작합니다. 쓰기에는 실행 계정의 일반 검사와 제한 SID 검사가 모두 적용되고, 읽기에는 일반 검사만 적용됩니다. [두 권한 검사의 차이](../solutions/windows-accounts-tokens.md#제한-sid와-write_restricted) · [비관리자 토큰 생성 코드](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_unelevated_sandbox.py#L1519-L1574)

비관리자 경로는 QwenPaw를 실행한 Windows 사용자의 토큰에서 시작합니다. 관리자 경로는 별도 저권한 샌드박스 계정의 토큰에서 시작합니다. 관리자 경로는 설정 시 존재하는 `deny_paths` 항목에 이 전용 계정의 접근 거부 ACE를 적용하며, 그 거부는 일반 권한 검사에서 효력이 있습니다. 비관리자 경로의 Web Console **Deny Paths Protection**은 선택 기능으로, 같은 Windows 사용자로 실행되는 다른 프로세스에도 영향을 줄 수 있는 ACL을 사용합니다. [관리자 경로 구현](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_elevated_sandbox.py) · [비관리자 경로 구현](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_unelevated_sandbox.py#L1980-L2010)

## 실측에서 확인할 항목

Restricted Token에서 허용 경로 안팎의 쓰기, 관리자·비관리자 경로의 명시적 읽기 거부, 실제 차단 이후 위반 감지·재승인·재시도 권한을 따로 확인합니다. [QwenPaw 실측 프로토콜](../../protocol.md#qwenpaw-restricted-token과-차단-후-재승인)

Windows 백엔드는 셸 출력의 접근 거부 문구로 위반을 분류합니다. 표준 오류가 패턴과 일치하거나, 종료 코드가 0이 아니면서 표준 출력이 패턴과 일치하면 위반을 반환합니다. 도구 어댑터는 `ToolChunk`의 `DENIED` 상태를 보고 재승인 여부를 판단합니다. 실제 OS 접근 차단과 애플리케이션의 위반 분류를 따로 기록하는 이유입니다. [Windows 위반 감지 코드](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_unelevated_sandbox.py#L1360-L1379) · [재승인 코드](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/governance/tool_adapter.py#L476-L506)

- 같은 합성 파일로 일반 파일 도구의 File Guard 판정과 셸 프로세스의 OS 접근 결과를 나눠 기록합니다. 관리자 계정 유무, 실제 클래스명, `allow_read_all`, 정책 경고를 남깁니다.
- AppContainer와 두 Restricted Token 경로에서 쓰기 범위, 네트워크 전체 차단, 가짜 환경 변수 상속을 각각 측정합니다. 네트워크는 프록시 준수 클라이언트와 직접 연결을 구분합니다.
- WFP·ACL·프로필이 처음 준비되는 시간과 같은 구성에서 재실행하는 시간을 구분합니다.
