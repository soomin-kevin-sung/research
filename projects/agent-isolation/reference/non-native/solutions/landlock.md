# Linux Landlock

## 실행 경계

Landlock은 프로세스가 자신의 접근 권한을 줄이고 해당 제약을 이후 자식에게 적용하는 Linux Security Module입니다. 파일 경로 계층의 접근 종류를 제한할 수 있고, 커널 ABI에 따라 지원 범위가 달라집니다. ABI v4부터 TCP 바인드와 목적지 포트 연결을 제한할 수 있습니다. 도메인별 프록시 정책, 마운트 네임스페이스, 환경 변수 필터는 각각 별도 계층에서 제공됩니다. [Linux 커널 Landlock 문서](https://docs.kernel.org/userspace-api/landlock.html)

## 에이전트 적용

- [QwenPaw](../agents/qwenpaw.md)는 WSL2에 Linux 버전을 설치한 경우 기능 탐지에 따라 Landlock 경로를 선택할 수 있습니다. QwenPaw의 TCP 포트 규칙은 Landlock ABI v4 이상이고 기본 네트워크가 차단되도록 설정된 경우에 적용됩니다. [QwenPaw 보안 문서](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/website/public/docs/security.en.md)
- [OpenClaw](../agents/openclaw.md)의 [OpenShell](openshell.md) 구성에서는 OpenShell Linux 런타임이 파일 규칙을 Landlock으로 적용합니다. 네트워크 판단은 OpenShell의 중계 계층에서 이루어집니다. [NVIDIA OpenShell 아키텍처](https://docs.nvidia.com/openshell/about/architecture)
- [Codex](../agents/codex.md) 0.171.0 소스에 레거시 Landlock 경로가 남아 있습니다. 이 버전의 실행 헬퍼는 파일시스템 쓰기가 제한된 정책에 Bubblewrap을 요구합니다. 레거시 경로의 유효 범위는 해당 버전과 정책을 명시해 해석합니다. [Codex 0.171.0 실행 헬퍼](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/linux-sandbox/src/linux_run_main.rs)

## 실측 시 확인

탐지된 ABI와 선택된 백엔드, 적용 경고 및 미지원 항목을 기록합니다. 동일 합성 경로에서 읽기·새 파일 생성·기존 파일 수정과 자식 프로세스의 결과를 관찰합니다.
