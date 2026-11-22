# Dev Containers

## 실행 경계

Dev Containers는 개발 컨테이너의 이미지, 설정, 작업 폴더 등을 구성하는 방식입니다. 프로세스 경계는 [Docker 등 컨테이너 엔진](docker.md)이 제공하며, 편집기 서버와 도구가 컨테이너 안에서 실행되는지 확인해야 합니다. 프로젝트 디렉터리, 포트 전달 및 자격 증명 공유는 설정에 따라 접근 경계를 바꿉니다. [VS Code Dev Containers](https://code.visualstudio.com/docs/devcontainers/containers)

## 에이전트 적용

[Claude Code](../agents/claude-code.md)는 Dev Container를 전체 세션 배포 옵션으로 안내합니다. [Codex](../agents/codex.md)도 WSL 기반 개발 컨테이너에서 실행할 수 있는 구성으로 조사했으며, 내부 Linux 샌드박스까지 활성화하려면 필요한 커널 기능과 권한이 컨테이너에서도 사용 가능해야 합니다. [Claude Code 격리 환경](https://code.claude.com/docs/en/sandbox-environments) · [Codex WSL 가이드](https://learn.chatgpt.com/docs/windows/wsl)

## 실측 시 확인

에이전트 본체와 셸·파일 도구의 실행 위치, 유효 마운트와 전달된 변수, 내부 샌드박스 상태를 확인합니다. 이미지 준비, 컨테이너 시작, 셸 실행을 각각 기록합니다.
