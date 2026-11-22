# Daytona Sandboxes

## 실행 경계

Daytona는 관리형 샌드박스마다 커널·파일시스템·네트워크 및 컴퓨트 자원을 제공한다고 설명합니다. 제공자의 방화벽·아웃바운드 정책은 별도 설정이며, 볼륨은 샌드박스 수명과 독립적으로 유지되고 여러 샌드박스에 연결할 수 있습니다. 중지·아카이브와 삭제는 상태가 달라지는 서로 다른 작업입니다. [Daytona 샌드박스](https://www.daytona.io/docs/sandboxes) · [네트워크 정책](https://www.daytona.io/docs/en/network-limits/) · [볼륨](https://www.daytona.io/docs/en/volumes/)

## 에이전트 적용

- [Hermes Agent](../agents/hermes.md)는 Python SDK를 사용해 샌드박스를 만들거나 다시 시작합니다. 지속 파일시스템을 사용하는 경로는 정리 시 중지하고, 비지속 경로는 삭제합니다. [Hermes 0.23.3 Daytona 어댑터](https://github.com/NousResearch/hermes-agent/blob/v0.23.3/tools/environments/daytona.py)
- [OpenClaw](../agents/openclaw.md)는 [Crabbox](crabbox.md)를 통해 Daytona 임대를 사용합니다. 스코프, 작업 영역 초기 복사와 반환은 OpenClaw·Crabbox 통합 정책을 따릅니다. [OpenClaw 2026.11.6 Crabbox 백엔드](https://github.com/openclaw/openclaw/blob/v2026.11.6/docs/gateway/sandboxing/crabbox-backend.md)

## 실측 시 확인

직접 SDK 구성과 임대 구성을 따로 기록합니다. 이미지와 네트워크 정책, 최초 생성·중지 후 재개·삭제, 동기화 범위와 유지되는 볼륨을 관찰합니다.
