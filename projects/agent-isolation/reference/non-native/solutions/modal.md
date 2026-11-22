# Modal Sandboxes

## 실행 경계

Modal은 이미지로부터 원격 샌드박스를 시작하고 SDK로 명령을 실행합니다. 제공자는 런타임에 따라 gVisor 또는 VM 경계를 사용한다고 설명합니다. 샌드박스의 최대·유휴 시간으로 실행 수명을 관리하며 볼륨과 파일시스템 스냅샷을 통해 상태를 별도로 남길 수 있습니다. 일반 샌드박스의 외부 연결은 기본 허용이며, 전체 차단 또는 CIDR·도메인 기반 제한은 선택 옵션입니다. [Modal Sandboxes](https://modal.com/docs/guide/sandboxes) · [런타임 경계](https://modal.com/docs/guide/sandbox-sidecars) · [네트워크 정책](https://modal.com/docs/guide/sandbox-networking)

## 에이전트 적용

[Hermes Agent](../agents/hermes.md)는 `modal` 터미널 백엔드로 원격 실행을 선택할 수 있습니다. 제공자가 문서화한 모든 네트워크 정책이 Hermes 설정으로 노출되는지는 실제 어댑터 설정과 계정 정책을 함께 확인해야 합니다. [Hermes 0.23.3 Modal 어댑터](https://github.com/NousResearch/hermes-agent/blob/v0.23.3/tools/environments/modal.py)

## 실측 시 확인

런타임과 이미지, 최초 시작·재사용, 동기화 파일과 주입 환경, 아웃바운드 정책, 종료 후 볼륨·스냅샷의 상태를 확인합니다. 제공자 API 대기와 원격 명령 시간을 구분합니다.
