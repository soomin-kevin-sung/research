# Hermes Agent의 Windows 실행 격리

2026-11-23 확인 · Nous Research의 Hermes Agent 안정 릴리스 `0.23.3` · 대상은 Windows CLI와 Hermes Desktop에서 시작한 작업입니다. [Hermes Agent v0.23.3 릴리스](https://github.com/NousResearch/hermes-agent/releases/tag/v0.23.3)

[조사 목록](../README.md)

관련 기술은 [도구 승인과 호스트 셸](../../../research/solutions/tool-approval.md) · [Docker](../solutions/docker.md) · [Podman](../solutions/podman.md) · [SSH](../solutions/ssh.md) · [Modal](../solutions/modal.md) · [Daytona](../solutions/daytona.md) · [Vercel Sandbox](../solutions/vercel-sandbox.md) · [WSL2](../solutions/wsl2.md)에서 설명합니다.

## 네이티브 실행과 백엔드 선택

Windows 10·11 네이티브 설치와 WSL2 설치를 지원합니다. Windows용 로컬 터미널 도구는 Git Bash를 통해 명령을 실행합니다. 기본 `terminal.backend: local`은 호스트 사용자의 권한으로 실행되며 파일·프로세스·네트워크의 OS 격리를 추가하지 않습니다. 위험 명령 확인과 정책 검사는 도구 요청을 제어합니다. MSIX로 설치했는지와 실제 터미널 백엔드는 별도 항목입니다. [버전 고정 Windows 가이드](https://github.com/NousResearch/hermes-agent/blob/v0.23.3/website/docs/user-guide/windows-native.md) · [Hermes 터미널 구성](https://hermes-agent.nousresearch.com/docs/user-guide/configuration) · [보안 정책](https://hermes-agent.nousresearch.com/docs/user-guide/security)

| 백엔드 | 명령이 실행되는 곳 | Windows 실측 시 의미 |
| --- | --- | --- |
| `local` | Hermes 실행 호스트 또는 WSL 배포판의 사용자 세션 | 파일과 네트워크는 실행 계정 및 배포 환경의 권한을 따름 |
| `docker` | Docker 또는 호환 Podman 컨테이너 | 에이전트 본체는 호스트에 둘 수 있고, 터미널과 해당 실행 환경을 사용하는 코드·파일 도구는 컨테이너 경계를 적용 |
| `ssh` | 지정 원격 계정의 셸 | Windows 호스트와 실행 위치가 분리되며 원격 내부 경계는 대상 계정과 서버 설정에 의존 |
| `modal`, `daytona`, `vercel_sandbox` | 클라우드 제공자의 샌드박스·워크스페이스 | 공급자별 컴퓨트와 저장소 수명 적용. Windows 네이티브 프로세스 격리와 성능군을 구분 |

WSL2에서 Hermes를 직접 설치하는 방식과 Windows Hermes에서 기존 WSL 배포판으로 터미널을 보내는 `hermes-wsl-terminal` 플러그인이 있습니다. 후자는 지정 배포판 사용자로 실행되며 WSL 마운트와 네트워크를 그대로 사용합니다. [플랫폼 지원](https://hermes-agent.nousresearch.com/docs/getting-started/platform-support) · [WSL 터미널 플러그인](https://hermes-agent.nousresearch.com/marketplace/hermes-wsl-terminal)

## Docker 파일 경계와 상태 수명

Docker 실행 백엔드는 Linux capabilities를 제거하고 일부 필요한 capability를 다시 부여하며, `no-new-privileges`, PID 한도, 제한된 tmpfs를 적용합니다. 명령, 코드 실행, 해당 백엔드에 연결된 파일 도구가 같은 컨테이너 작업 영역을 볼 수 있습니다. 호스트의 현재 작업 폴더 마운트는 기본 꺼져 있고, `docker_mount_cwd_to_workspace`를 켜면 `/workspace`로 연결됩니다. `docker_volumes`로 추가한 경로와 `docker_forward_env`로 전달한 자격 증명은 컨테이너의 가시범위에 포함됩니다. [Hermes 구성](https://hermes-agent.nousresearch.com/docs/user-guide/configuration) · [Docker 실행 코드](https://github.com/NousResearch/hermes-agent/blob/v0.23.3/tools/environments/docker.py)

`container_persistent`의 기본값은 `true`입니다. 호스트 작업 폴더 마운트를 끈 경우 같은 프로필의 세션이 지속 컨테이너와 작업 데이터를 공유합니다. 작업 폴더 마운트를 켜면 프로필과 작업 영역이 공유 단위를 정합니다. `false`에서는 대화별로 새 컨테이너가 만들어지고 하위 에이전트는 부모의 컨테이너를 사용합니다. 읽기·쓰기 호스트 바인드에 쓴 파일은 컨테이너의 수명과 별개입니다. [버전 고정 터미널 구성](https://github.com/NousResearch/hermes-agent/blob/v0.23.3/website/docs/user-guide/configuration.md)

기본 네트워크는 켜져 있으며 `terminal.docker_network: false`를 적용하면 컨테이너에 `--network=none`을 사용합니다. 지속 컨테이너의 네트워크 정책을 바꾸면 새 컨테이너가 필요할 수 있습니다. Hermes 전체를 Docker에 올리는 방식은 구성·키·세션 상태가 담긴 호스트 볼륨을 별도로 갖습니다. [Hermes Docker 보안](https://hermes-agent.nousresearch.com/docs/user-guide/security) · [Hermes 전체 컨테이너 배포](https://hermes-agent.nousresearch.com/docs/user-guide/docker)

## 실측에서 확인할 항목

- Windows `local`, WSL2 `local`, Windows에서 연결한 Docker를 각각 측정합니다. Git Bash 경로와 Docker 엔진의 실제 실행 위치를 기록합니다.
- Docker 기본 네트워크와 `docker_network: false`를 비교하고, 기본 마운트와 명시적 작업 폴더 마운트에서 터미널·파일 도구의 실제 접근을 확인합니다.
- 동일 프로필에서 새 세션, 새 작업 폴더, 하위 에이전트가 이전 임시 파일을 볼 수 있는지 구분합니다. Browser, MCP 및 Gateway 도구는 실행 위치를 확인한 뒤 별도로 기록합니다.
