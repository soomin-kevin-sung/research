# Bubblewrap

## 실행 경계

Bubblewrap은 Linux에서 새로운 마운트 네임스페이스를 만들고 호출자가 지정한 경로를 읽기 전용 또는 쓰기 가능하게 노출합니다. 사용자·PID·네트워크 등 다른 네임스페이스와 seccomp 필터는 호출자의 구성에 따라 추가됩니다. 보이는 파일, 네트워크 연결, 환경 변수는 에이전트가 조립한 실행 정책에 좌우됩니다. [Bubblewrap 공식 문서](https://github.com/containers/bubblewrap/blob/main/README.md) · [Linux seccomp 문서](https://docs.kernel.org/userspace-api/seccomp_filter.html)

## 에이전트 적용

- [Claude Code](../agents/claude-code.md)는 [WSL2](wsl2.md)에서 내장 샌드박스를 활성화했을 때 Bash 명령에 Bubblewrap을 적용합니다. 네트워크 네임스페이스와 `socat` 릴레이로 프록시 연결을 중계하고, 프록시가 도메인·포트 정책을 적용합니다. 기본 파일 읽기 범위는 넓고 쓰기에는 작업 영역 제한이 있습니다. [Claude Code 샌드박싱](https://code.claude.com/docs/en/sandboxing) · [Anthropic Sandbox Runtime](https://github.com/anthropics/sandbox-runtime)
- [Codex](../agents/codex.md)의 Linux/WSL2 경로는 Bubblewrap으로 파일 뷰를 구성하고, 내부 실행 단계에서 seccomp와 `no_new_privs`를 적용합니다. 관리형 네트워크의 중계 경로는 유효 프로필에 따라 선택됩니다. [Codex 0.171.0 Linux 실행 소스](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/linux-sandbox/src/linux_run_main.rs)
- [QwenPaw](../agents/qwenpaw.md)는 Linux 런타임의 기능 탐지 결과에 따라 Bubblewrap을 선택할 수 있습니다. 고정 버전은 Bubblewrap의 네트워크 네임스페이스 적용을 계획 항목으로 설명합니다. [QwenPaw 보안 문서](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/website/public/docs/security.en.md)

## 실측 시 확인

커널과 Bubblewrap 버전, 사용자 네임스페이스 사용 가능 여부, 실제 마운트와 네트워크 정책을 남깁니다. 작업 경로가 배포판 내부인지 Windows 마운트인지 기록하고, 셸과 내장 파일 도구를 각각 관찰합니다.
