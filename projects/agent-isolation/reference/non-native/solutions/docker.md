# Docker Engine과 Docker Desktop

## 실행 경계

Linux 컨테이너는 엔진이 실행되는 Linux 커널을 공유하며 네임스페이스, capability, seccomp와 자원 제어를 사용합니다. Windows의 Docker Desktop에서 WSL2 백엔드를 사용하면 Linux 엔진은 WSL2 쪽에서 실행됩니다. 바인드 마운트는 엔진 호스트의 파일을 컨테이너에 노출하며 쓰기 가능하게 연결한 경로의 변경은 컨테이너 제거 후에도 유지됩니다. `--network=none`은 컨테이너에 루프백만 남기는 네트워크 구성입니다. [Docker Engine 보안](https://docs.docker.com/engine/security/) · [Windows WSL2 백엔드](https://docs.docker.com/desktop/features/wsl/) · [바인드 마운트](https://docs.docker.com/engine/storage/bind-mounts/) · [none 네트워크](https://docs.docker.com/engine/network/drivers/none/)

## 에이전트 적용

| 제품 | 기본값과 실행 수명 |
| --- | --- |
| [OpenClaw](../agents/openclaw.md) | Gateway 샌드박스를 활성화할 때 기본 백엔드입니다. 기본 컨테이너 정책은 네트워크 `none`, 읽기 전용 루트, capability 제거이며 스코프에 따라 컨테이너를 재사용합니다. |
| [Hermes Agent](../agents/hermes.md) | 선택형 백엔드입니다. 기본 네트워크는 켜져 있고 컨테이너는 지속형입니다. 호스트 작업 폴더 자동 마운트는 기본 꺼져 있습니다. |
| [OpenHuman](../agents/openhuman.md) | 선택형 [TinyBox](../../../research/solutions/tinybox.md) OneShot 경로입니다. 기본 네트워크는 `none`이며 명령 종료 시 컨테이너를 제거합니다. |
| [Claude Code](../agents/claude-code.md) · [Codex](../agents/codex.md) · [OpenCode](../agents/opencode.md) | 외부 배포 방식으로 전체 에이전트 또는 엔진을 컨테이너에 둘 수 있습니다. 내부 셸 정책과 컨테이너의 마운트·네트워크 정책을 함께 기록합니다. |

[OpenClaw Docker 기본값](https://github.com/openclaw/openclaw/blob/v2026.11.6/docs/gateway/sandboxing/docker-backend.md) · [Hermes Docker 소스](https://github.com/NousResearch/hermes-agent/blob/v0.23.3/tools/environments/docker.py) · [OpenHuman Docker 소스](https://github.com/tinyhumansai/openhuman/blob/v0.64.15/crates/openhuman-core/src/sandbox/docker.rs) · [Claude Code 배포 옵션](https://code.claude.com/docs/en/sandbox-environments)

## 실측 시 확인

엔진 위치, 이미지, 파일 마운트, 네트워크, 명시적으로 전달한 환경 변수와 컨테이너 수명을 기록합니다. 최초 이미지 준비, 새 컨테이너 시작, 준비된 컨테이너에서 명령 실행을 따로 재고, 쓰기 마운트에 저장한 상태와 컨테이너 내부 상태를 각각 확인합니다.
