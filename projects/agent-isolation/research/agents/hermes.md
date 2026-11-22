# Hermes Agent의 Windows 실행 격리

2026-11-23 확인 · Nous Research의 Hermes Agent 안정 릴리스 `0.23.3` · 대상은 Windows CLI와 Hermes Desktop에서 시작한 작업입니다. [Hermes Agent v0.23.3 릴리스](https://github.com/NousResearch/hermes-agent/releases/tag/v0.23.3)

[조사 목록](../README.md)

관련 기술은 [도구 승인과 호스트 셸](../solutions/tool-approval.md)에서 설명합니다.

## Windows 로컬 터미널

Windows용 로컬 터미널 도구는 Git Bash를 통해 실행됩니다. 기본 `terminal.backend: local`은 호스트 사용자의 권한을 사용하며 파일·프로세스·네트워크에 별도 OS 격리를 적용하지 않습니다. 위험 명령 확인과 정책 검사는 도구 요청을 제어합니다. MSIX 설치 여부와 실제 터미널 백엔드를 각각 기록합니다. [버전 고정 Windows 가이드](https://github.com/NousResearch/hermes-agent/blob/v0.23.3/website/docs/user-guide/windows-native.md) · [Hermes 터미널 구성](https://hermes-agent.nousresearch.com/docs/user-guide/configuration) · [보안 정책](https://hermes-agent.nousresearch.com/docs/user-guide/security)

## 실측에서 확인할 항목

- `local` 백엔드, Git Bash 경로와 Windows 실행 계정을 기록합니다.
- 도구 승인 결과와 승인된 프로그램의 시험 파일·환경 변수·네트워크 접근을 각각 확인합니다.
