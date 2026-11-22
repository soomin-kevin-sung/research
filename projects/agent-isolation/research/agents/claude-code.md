# Claude Code의 Windows 실행 격리

2026-11-23 확인 · 안정 릴리스 `2.1.330` · 대상은 Windows 네이티브 Claude Code CLI입니다. [Claude Code v2.1.330 릴리스](https://github.com/anthropics/claude-code/releases/tag/v2.1.330)

[조사 목록](../README.md)

관련 기술은 [도구 승인과 호스트 셸](../solutions/tool-approval.md)에서 설명합니다.

## Windows 네이티브 셸과 도구 승인

Windows 네이티브에서 에이전트가 실행하는 셸 명령에는 내장 Bash 샌드박스가 적용되지 않습니다. 실행 여부는 Claude Code 권한 모드와 사전 승인 규칙이 결정하며, 승인된 프로세스는 Windows 실행 계정의 권한을 사용합니다. Read, Edit, Write, WebFetch는 각각 Claude Code 도구 권한을 따릅니다. [Claude Code 샌드박싱](https://code.claude.com/docs/en/sandboxing) · [도구별 적용 범위](https://code.claude.com/docs/en/sandboxing#what-runs-outside-the-sandbox)

## 실측에서 확인할 항목

- Windows용 CLI에서 권한 모드, 사전 승인 요구, 명령 시작 여부와 실행 계정을 기록합니다.
- 정책이 허용한 셸과 내장 Read·Edit·Write의 시험 파일 접근을 각각 관찰합니다.
