# TinyBox

## 실행 경계

TinyBox는 실행 환경의 jail을 탐지하는 라이브러리입니다. OpenHuman 0.64.15가 고정한 TinyBox 0.1.15 리비전에는 Windows AppContainer 구현이 있습니다. 해당 리비전의 자동 탐지에서는 Windows 실행 핸들을 호출자가 기다릴 수 있는 Rust 자식 프로세스 형태로 넘기는 제약 때문에 이 백엔드를 선택하지 않습니다. [OpenHuman 의존성 잠금](https://github.com/tinyhumansai/openhuman/blob/v0.64.15/Cargo.lock#L6909-L6918) · [TinyBox 백엔드 탐지](https://github.com/tinyhumansai/tinybox/blob/8b3c7c9a208c9240e8ce3af7902722652aba7b47/crates/tinybox-jail/src/detect.rs)

## 에이전트 적용

[OpenHuman](../agents/openhuman.md)의 Windows 로컬 대화형 실행은 TinyBox가 `unsupported`를 반환하면 샌드박스 상태를 `Inactive`로 두고 `NoopBackend`에서 명령을 실행합니다. 환경 변수 정리와 도구 경로 검증은 OpenHuman의 별도 처리입니다. [OpenHuman 실행 선택 소스](https://github.com/tinyhumansai/openhuman/blob/v0.64.15/crates/openhuman-core/src/sandbox/ops.rs)

## 실측 시 확인

제품 빌드·TinyBox 리비전·요청 모드·실제 백엔드·상태를 함께 기록합니다. Windows 로컬 셸의 실행 계정과 가짜 환경 변수의 상속 여부를 확인합니다.

안정판에서 선택된 `NoopBackend`는 [하위 폴더 OS 보호 비교](../security-boundaries.md#상위-폴더-허용과-하위-폴더-보호)의 호스트 실행 조건입니다.
