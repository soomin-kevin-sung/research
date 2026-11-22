# Windows 네이티브 격리 조사

[프로젝트 개요](../README.md) · [실측 프로토콜](../protocol.md) · [결과 및 판단](../findings.md)

[Windows 격리의 보안 한계](security-boundaries.md)에서 상·하위 경로 규칙을, [파일 외 자원과 작업 호환성](security-boundaries.md#파일-외-자원과-작업-호환성)에서 로컬 서비스, 프로세스 간 통신, 레지스트리, UI, 자원 한도와 도구별 정책을 확인할 수 있습니다.

Windows 호스트에서 명령과 파일 작업을 실행할 때 적용되는 OS 수준 격리를 비교합니다. 셸·내장 파일 도구별로 실제 실행 위치와 계정을 기록합니다. WSL2, Linux 컨테이너, 외부 VM과 원격 실행은 비교 범위에서 제외합니다.

## 에이전트별 Windows 실행 경로

| 에이전트 | Windows 실행 경로 | 비교 시 확인할 조건 |
| --- | --- | --- |
| [Codex](agents/codex.md) | [MXC ProcessContainer](solutions/mxc.md), 레거시 [전용 계정·제한 토큰](solutions/windows-accounts-tokens.md) | 장치 호환성, 데스크톱·CLI의 유효 백엔드, 권한 프로필 |
| [QwenPaw](agents/qwenpaw.md) | [AppContainer](solutions/appcontainer.md) 또는 [제한 토큰·ACL·WFP](solutions/windows-accounts-tokens.md) | 거버넌스 판정, 읽기 정책, 관리자 권한 |
| [OpenClaw](agents/openclaw.md) | Gateway 도구 및 Windows Hub 노드의 [MXC](solutions/mxc.md), Store 네이티브 Gateway의 [IsolationSession](solutions/mxc-isolation-session.md), Gateway 기본 [호스트 실행](solutions/tool-approval.md) | 도구 실행 경로와 Gateway 서비스의 배치 경계, 장치 호환성 |
| [Claude Code](agents/claude-code.md) | [도구 승인 후 호스트 셸](solutions/tool-approval.md) | Windows 네이티브 셸의 기준 동작 |
| [Hermes Agent](agents/hermes.md) | 기본 [호스트 셸](solutions/tool-approval.md) | `local` 백엔드의 기준 동작 |
| [OpenCode](agents/opencode.md) | [도구 승인 후 호스트 셸](solutions/tool-approval.md) | 버전별 승인 규칙과 호스트 셸의 기준 동작 |
| [OpenHuman](agents/openhuman.md) | 안정판의 [TinyBox 탐지](solutions/tinybox.md)가 [AppContainer](solutions/appcontainer.md)를 선택하지 않아 [호스트 셸](solutions/tool-approval.md)로 실행 | 요청한 모드, 실제 백엔드, 별도 환경 변수 처리 |

## 격리 기술과 기준 동작

| 기술 | Windows에서 적용되는 경계 |
| --- | --- |
| [MXC ProcessContainer](solutions/mxc.md) | Windows PSEC로 명령 프로세스에 파일·네트워크 정책 적용 |
| [MXC IsolationSession](solutions/mxc-isolation-session.md) | 별도 Windows 계정과 OS 관리 세션에 서비스 배치 |
| [AppContainer](solutions/appcontainer.md) | AppContainer SID와 capability, 객체 ACL로 접근 제어 |
| [전용 계정·제한 토큰·ACL·WFP](solutions/windows-accounts-tokens.md) | 계정과 토큰으로 실행 주체를 정하고 파일 접근과 네트워크 필터를 적용 |
| [TinyBox의 Windows 백엔드 선택](solutions/tinybox.md) | OpenHuman 안정판에서 AppContainer 구현이 실제 실행 경로에 선택되는지 확인 |
| [도구 승인과 호스트 셸](solutions/tool-approval.md) | 호출 전 애플리케이션 판정과 Windows 사용자 권한을 따르는 기준 동작 |

현재 결과는 공식 문서와 조사 버전의 소스에 근거합니다. 실제 격리 동작과 성능 측정은 아직 진행 전입니다.
