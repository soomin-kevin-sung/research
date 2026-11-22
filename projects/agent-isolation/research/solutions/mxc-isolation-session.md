# MXC IsolationSession

## 실행 경계

MXC의 IsolationSession은 별도 Windows 사용자 계정과 OS가 관리하는 세션을 준비합니다. SDK는 세션 생성·시작·명령 실행·중지·제거를 제공하며, 세션을 재사용하면 명령 실행 간 상태를 유지할 수 있습니다. [Microsoft MXC 백엔드 스키마](https://github.com/microsoft/mxc/blob/main/docs/schema.md)

## 에이전트 적용

[OpenClaw](../agents/openclaw.md)의 Store 네이티브 Gateway 배포는 지원 Windows에서 Gateway 서비스 자체를 격리 세션에 둡니다. Windows Hub의 설치 흐름은 세션 전용 기능을 확인합니다. 서비스 배치 경계, Gateway의 도구별 [MXC](mxc.md) 플러그인, Windows Hub 노드의 `system.run`은 실행 기록에서 각각 식별합니다. [Windows Hub 2026.11.3 온보딩](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/docs/ONBOARDING_WIZARD.md) · [Gateway 패키징 구현과 검증 기록](https://github.com/openclaw/openclaw-windows-packaging/blob/main/docs/mxc-compatibility-evidence.md)

## 실측 시 확인

Gateway 패키지 버전, 세션 지원 판정, 실제 실행 계정과 세션, 프로젝트 공유 방식 및 유효 네트워크 정책을 기록합니다. 신규 세션 준비, 기존 세션 재사용, Gateway 재시작, 세션 제거 이후의 상태를 구분합니다.

공유 경로의 유효 ACL과 명령 취소 후 하위 프로세스 종료를 별도로 확인합니다. [경계와 상태 관리 검토](../security-boundaries.md#함께-확인할-경계)
