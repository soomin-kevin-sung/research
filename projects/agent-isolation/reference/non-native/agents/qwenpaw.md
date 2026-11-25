# QwenPaw의 Windows 실행 격리

2026-11-23 확인 · 안정 릴리스 `2.3.0.post1` · 대상은 AgentScope의 QwenPaw입니다. [QwenPaw v2.3.0.post1 릴리스](https://github.com/agentscope-ai/QwenPaw/releases/tag/v2.3.0.post1)

[조사 목록](../README.md)

관련 기술은 [AppContainer](../../../research/solutions/appcontainer.md) · [전용 계정·Restricted Token·ACL·WFP](../../../research/solutions/windows-accounts-tokens.md) · [Bubblewrap](../solutions/bubblewrap.md) · [Landlock](../solutions/landlock.md) · [WSL2](../solutions/wsl2.md)에서 설명합니다.

## 거버넌스와 실제 실행 경로

QwenPaw는 Tool Guard·File Guard와 거버넌스 정책으로 도구 호출을 평가합니다. 셸 호출이 `SANDBOX_FALLBACK`으로 분기될 때 OS 샌드박스에서 실행하며, 정책에 따라 허용·거부·승인 요청 결과도 가능합니다. `SMART` 기본 정책의 모델과 Windows 백엔드의 기본 읽기 정책은 별개의 설정이므로, 측정할 때 실제 거버넌스 판정과 프로세스 백엔드를 함께 기록해야 합니다. [버전 고정 보안 문서](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/website/public/docs/security.en.md) · [거버넌스와 샌드박스 설계](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/website/public/blog/qwenpaw-sandbox.en.md)

## Windows 백엔드

| 조건 | 메커니즘 | 적용 범위 |
| --- | --- | --- |
| `allow_read_all=False` | AppContainer 프로필과 capability SID, `icacls`로 허용 경로에 ACL 부여 | 명시적 파일 접근 허용 방식. 초기 ACL 설정에 관리자 권한이 필요하며 네트워크는 capability로 제어 |
| `allow_read_all=True`, 관리자 권한 있음 | 전용 로컬 사용자와 `CreateRestrictedToken`의 `WRITE_RESTRICTED`, ACL, WFP 방화벽 | 읽기는 기본적으로 넓게 허용하고 쓰기는 허용 경로로 제한. 전체 네트워크 차단을 WFP가 강제할 수 있음 |
| `allow_read_all=True`, 관리자 권한 없음 | 현재 토큰에서 파생한 `WRITE_RESTRICTED`와 ACL | 제한 쓰기를 제공. 네트워크 차단 요청은 프록시 환경 변수 수준이며 직접 연결을 OS 수준에서 강제 차단하지 못함 |

릴리스의 팩토리는 Windows 백엔드를 `SandboxMode.WINDOWS`로 표현하고 `allow_read_all` 및 관리자 권한을 바탕으로 클래스를 선택합니다. 백엔드를 사용할 수 없어 `none`이 선택되면 명령 전달, 시간 제한, 환경 설정 등만 남습니다. 정책이 요청한 격리 제약을 백엔드가 강제하지 못할 때는 로그에 표시합니다. [백엔드 선택과 기능 경고 소스](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/config.py) · [Windows AppContainer 소스](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_appcontainer_sandbox.py)

## 네트워크와 환경 변수의 제약

AppContainer와 관리자 Restricted Token에서 실질적으로 비교할 수 있는 범위는 전체 허용과 전체 차단입니다. 도메인 목록을 주면 AppContainer는 네트워크를 열고 WFP 경로는 전체 차단으로 처리할 수 있다고 해당 버전 문서에 명시돼 있습니다. `env_mode="allowlist"`는 구현되지 않아 자식 환경이 현재 환경을 상속하고 지정 변수를 덧씁니다. 프로세스 수와 메모리 한도 설정도 이 버전에서 강제되지 않습니다. [보안 문서의 구현 제약](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/website/public/docs/security.en.md#current-limitations)

AppContainer 프로필은 동일 구성에서 재사용됩니다. WSL2에 Linux 버전을 설치하면 Windows 백엔드 대신 Linux 프로브 결과에 따라 Bubblewrap, Landlock 또는 `none` 경로를 선택합니다. QwenPaw 버전 고정 문서에서 Bubblewrap의 네트워크 네임스페이스 격리는 계획 항목이므로, Linux 백엔드라는 사실만으로 네트워크 차단을 인정할 수 없습니다. [QwenPaw 구성과 지원 플랫폼](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/website/public/docs/security.en.md#supported-platforms) · [Windows 프로필 재사용 설계](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/website/public/blog/qwenpaw-sandbox.en.md)

## 실측에서 확인할 항목

- 같은 합성 파일로 일반 파일 도구의 File Guard 판정과 셸 프로세스의 OS 접근 결과를 나눠 기록합니다. 관리자 계정 유무, 실제 클래스명, `allow_read_all`, 정책 경고를 남깁니다.
- AppContainer와 두 Restricted Token 경로에서 쓰기 범위, 네트워크 전체 차단, 가짜 환경 변수 상속을 각각 측정합니다. 네트워크는 프록시 준수 클라이언트와 직접 연결을 구분합니다.
- WFP·ACL·프로필이 처음 준비되는 시간과 같은 구성에서 재실행하는 시간을 구분합니다.
