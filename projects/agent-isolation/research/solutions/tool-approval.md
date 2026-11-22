# 도구 승인과 호스트 셸

## 실행 경계

도구 승인은 애플리케이션이 명령이나 파일 요청을 시작하기 전에 규칙을 평가하는 방식입니다. 호스트 셸로 실행되면 운영체제에서 관찰되는 파일·환경·네트워크 권한은 실행 계정과 적용된 OS 정책을 따릅니다. 실측에서는 도구가 실행을 거부한 경우와 실행된 프로세스가 시험 리소스에 접근하지 못한 경우를 구분합니다.

## 에이전트 적용

- [Claude Code](../agents/claude-code.md) 네이티브 Windows는 권한 모드로 셸 호출을 제어합니다. [Claude Code 샌드박싱](https://code.claude.com/docs/en/sandboxing)
- [OpenCode](../agents/opencode.md)는 안정판 V1에서 셸 호출과 인식한 외부 경로를 승인하며, V2 문서는 변경된 규칙과 기본값을 설명합니다. [OpenCode 1.19.6 셸 소스](https://github.com/anomalyco/opencode/blob/v1.19.6/packages/opencode/src/tool/shell.ts) · [OpenCode 권한 레퍼런스](https://opencode.ai/docs/permissions/)
- [Hermes Agent](../agents/hermes.md)의 기본 로컬 백엔드와 [OpenClaw](../agents/openclaw.md)의 Gateway 직접 실행은 호스트 실행 계정의 권한에 의존합니다. [QwenPaw](../agents/qwenpaw.md)는 거버넌스 판정에 따라 일반 실행 또는 샌드박스를 선택합니다. [OpenHuman](../agents/openhuman.md)은 Windows에서 TinyBox 탐지 결과에 따라 비격리 실행으로 이어질 수 있습니다. [Codex](../agents/codex.md)의 승인 동작은 선택된 샌드박스 정책과 별도의 제어입니다.

## 실측 시 확인

호출 도구, 유효 승인 규칙, 판정과 프로세스 생성 여부를 기록합니다. 실행이 허용된 시험은 합성 리소스를 사용해 파일 접근, 환경 변수 상속, 네트워크 접근을 관찰합니다.

하위 폴더 보호는 도구 호출 판정과 Windows에 의해 실행된 프로세스의 파일 접근을 별도 관찰값으로 기록합니다. [상위·하위 폴더 비교](../security-boundaries.md#상위-폴더-허용과-하위-폴더-보호)
