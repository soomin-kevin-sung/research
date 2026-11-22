# OpenHuman의 Windows 실행 격리

2026-11-23 확인 · TinyHumansAI의 OpenHuman 안정 릴리스 `0.64.15` · Windows 네이티브 데스크톱 패키지와 Rust 코어의 셸 경로를 대상으로 합니다. [OpenHuman v0.64.15 릴리스](https://github.com/tinyhumansai/openhuman/releases/tag/v0.64.15) · [Windows 설치 문서](https://github.com/tinyhumansai/openhuman/blob/v0.64.15/INSTALL.md)

[조사 목록](../README.md)

관련 기술은 [도구 승인과 호스트 셸](../../../research/solutions/tool-approval.md) · [TinyBox](../../../research/solutions/tinybox.md) · [AppContainer](../../../research/solutions/appcontainer.md) · [Docker](../solutions/docker.md)에서 설명합니다.

## 안정판의 Windows 네이티브 격리 상태

로컬 대화형 에이전트가 `SandboxMode::Sandboxed`이고 런타임이 로컬이면 정책은 `Local` 백엔드를 선택합니다. 이 실행은 릴리스에 고정된 TinyBox `0.1.15`의 `cwd_jail`을 호출합니다. TinyBox에는 Windows AppContainer 클래스가 있지만, 해당 버전의 탐지 목록은 실행 핸들을 Rust의 대기 가능한 `std::process::Child`로 넘길 수 없다는 이유로 Windows 백엔드를 제외합니다. Windows의 AppContainer 파일 쓰기 차단 테스트도 같은 제약을 이유로 무시 처리됐습니다. [릴리스의 의존성 잠금](https://github.com/tinyhumansai/openhuman/blob/v0.64.15/Cargo.lock#L6909-L6918) · [고정 TinyBox 리비전](https://github.com/tinyhumansai/tinybox/tree/8b3c7c9a208c9240e8ce3af7902722652aba7b47) · [TinyBox 백엔드 탐지](https://github.com/tinyhumansai/tinybox/blob/8b3c7c9a208c9240e8ce3af7902722652aba7b47/crates/tinybox-jail/src/detect.rs) · [Windows AppContainer 구현](https://github.com/tinyhumansai/tinybox/blob/8b3c7c9a208c9240e8ce3af7902722652aba7b47/crates/tinybox-jail/src/windows.rs) · [격리 테스트](https://github.com/tinyhumansai/openhuman/blob/v0.64.15/tests/cwd_jail_e2e.rs)

TinyBox는 사용 가능한 OS jail이 없으면 `unsupported`를 반환합니다. OpenHuman은 상태를 `Inactive`로 보고하고, 명령을 `NoopBackend`로 실행합니다. 따라서 안정판의 Windows 로컬 셸은 `Sandboxed` 정책이 선택돼도 이 경로에서 AppContainer 수준의 파일·네트워크 제약을 받지 않습니다. 환경 변수를 한 번 비우고 허용 변수와 Windows 부팅용 변수를 주입하는 처리, 경로 검증, 도구 승인 등은 각각 적용 조건이 있습니다. [릴리스 정책 및 실행 구현](https://github.com/tinyhumansai/openhuman/blob/v0.64.15/crates/openhuman-core/src/sandbox/ops.rs) · [Windows 자식 환경 테스트](https://github.com/tinyhumansai/openhuman/blob/v0.64.15/tests/windows_sandbox_env_e2e.rs)

## Docker 실행과 정책 범위

| 모드 또는 조건 | 선택되는 실행 경로 | 격리 결과 |
| --- | --- | --- |
| `Sandboxed` · 로컬 런타임 · 대화형 세션 | `Local` → TinyBox 탐지 → Windows에서 `NoopBackend` | 이 안정 태그의 Windows 로컬 셸은 OS jail 없이 실행 |
| `Sandboxed` · `runtime.kind = "docker"` 또는 원격 세션 경로 | `Docker` → TinyBox Docker OneShot | Docker 엔진에서 일회성 컨테이너로 실행. Windows Docker 엔진 및 Linux 이미지 사용 조건 확인 필요 |
| `None` 또는 `ReadOnly` | 백엔드 `None` | `ReadOnly` 표기는 별도 정책에 해당하며 이 모드에서 셸 OS jail은 선택되지 않음 |

Docker 경로는 `docker run --rm`으로 합성 작업 영역을 `/workspace`에 연결할 수 있습니다. 기본 네트워크는 `none`이고 capability, 임시 파일시스템, CPU·메모리 자원 한도를 적용합니다. 컨테이너를 제거해도 읽기·쓰기 바인드 마운트에 쓴 파일은 호스트에 남습니다. Docker 시작 오류는 별도 실행 실패로 반환됩니다. 원격 채널·스케줄러의 정책은 각 진입점에서 유효 백엔드를 확인해야 합니다. [릴리스 샌드박스 구조](https://github.com/tinyhumansai/openhuman/blob/v0.64.15/crates/openhuman-core/src/sandbox/README.md) · [Docker 실행 구현](https://github.com/tinyhumansai/openhuman/blob/v0.64.15/crates/openhuman-core/src/sandbox/docker.rs)

공개 개발 브랜치에서는 TinyBox와 TinySecurity를 연결하는 네이티브 실행 어댑터가 바뀌었습니다. 위 Windows 판정은 안정 태그와 그 태그가 고정한 TinyBox 경로에 적용됩니다. 이후 버전은 새로 참조하는 TinyBox 리비전과 Windows에서 실제 선택된 백엔드를 다시 확인해야 합니다. [개발 브랜치의 네이티브 실행 어댑터 리비전](https://github.com/tinyhumansai/openhuman/blob/5e0ed58425e14d42ee078a521c3965439deef5c5/crates/openhuman-core/src/sandbox/native_jail.rs)

## 실측에서 확인할 항목

- Windows 로컬에서 요청한 모드, 해석된 정책, 백엔드 ID, `sandbox.status`와 자식 프로세스의 관찰 결과를 함께 기록합니다. 일반 셸 성공과 AppContainer 실행 성공을 구분합니다.
- Docker를 활성화한 경우 엔진과 이미지 버전, 실제 컨테이너 옵션, 허용 경로 및 네트워크를 확인합니다. 컨테이너 내부 임시 파일과 `/workspace`에 쓴 파일을 각각 관찰합니다.
- `SystemRoot`와 같은 부팅용 환경 변수는 정상 실행 조건으로 분리하고, 상속을 의도하지 않은 가짜 변수로 실제 환경 격리를 검증합니다.
