# NVIDIA OpenShell

## 실행 경계

OpenShell은 컴퓨트 드라이버 위에서 정책을 적용하는 샌드박스 런타임입니다. NVIDIA의 Linux 아키텍처 문서에서 Landlock은 파일 접근을 제어하고, seccomp 사용자 알림과 네트워크 감독 계층은 연결 판단을 중계합니다. 실제 규칙은 컴퓨트 드라이버, NVIDIA 런타임 버전, 유효 정책에 따릅니다. 파일·프로세스 정책은 시작 시 적용되고, 네트워크 정책은 실행 중 변경할 수 있습니다. [OpenShell 아키텍처](https://docs.nvidia.com/openshell/about/architecture) · [정책 참조](https://docs.nvidia.com/openshell/latest/how-it-works/policies/schema) · [지원 매트릭스](https://docs.nvidia.com/openshell/latest/about/support-matrix)

## 에이전트 적용

[OpenClaw](../agents/openclaw.md)는 OpenShell 플러그인을 통해 대상 도구를 관리형 샌드박스로 보냅니다. `mirror`는 설정된 Workspace 동기화를 사용하고 `remote`는 원격 작업 영역을 기준으로 삼습니다. 제품과 제공자의 버전을 따로 남기고, Gateway 호스트에 남은 작업과 OpenShell에서 실행된 작업을 기록합니다. [OpenClaw 2026.11.6 OpenShell 통합](https://github.com/openclaw/openclaw/blob/v2026.11.6/docs/gateway/openshell.md)

## 실측 시 확인

컴퓨트 드라이버, [Landlock](landlock.md) ABI, 유효 파일·네트워크 정책, Workspace 모드와 동기화 범위를 기록합니다. 제공자 문서의 기능과 OpenClaw 플러그인이 실제로 적용한 옵션을 함께 확인합니다.
