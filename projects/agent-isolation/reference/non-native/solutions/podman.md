# Podman

## 실행 경계

Podman은 Linux에서 컨테이너별 파일시스템, 네트워크, 프로세스 트리를 구성합니다. Windows에서는 Podman Machine을 통해 Linux 실행 환경을 제공하며 WSL 공급자의 네트워크 설정이 별도로 적용됩니다. rootless 여부, 마운트, capability 및 `--network` 정책은 최종 실행 설정입니다. [Podman run](https://docs.podman.io/en/stable/markdown/podman-run.1.html) · [Podman Machine](https://docs.podman.io/en/stable/markdown/podman-machine-init.1.html)

## 에이전트 적용

[OpenClaw](../agents/openclaw.md)는 `podman`을 Gateway 백엔드로 선택하며 Docker 계열의 작업 영역·네트워크 설정을 공유합니다. 브라우저 샌드박스는 Docker 엔진 경로에서 제공됩니다. [Hermes Agent](../agents/hermes.md)는 Docker 터미널 경로에서 호환 Podman 구성을 사용할 수 있습니다. 어떤 CLI·소켓·엔진에 연결되는지는 실제 환경에서 확인합니다. [OpenClaw 백엔드 비교](https://github.com/openclaw/openclaw/blob/v2026.11.6/docs/gateway/sandboxing/modes-scope-and-backend.md) · [Hermes 0.23.3 Docker 구현](https://github.com/NousResearch/hermes-agent/blob/v0.23.3/tools/environments/docker.py)

## 실측 시 확인

Machine 공급자와 엔진 실행 계정, rootless 여부, 마운트, 컨테이너 네트워크를 기록합니다. [Docker](docker.md)와 비교할 때 Linux 실행 환경과 이미지, 워크스페이스가 놓인 파일시스템을 함께 기록합니다.
