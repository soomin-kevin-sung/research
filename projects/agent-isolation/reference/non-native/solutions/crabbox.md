# Crabbox

## 실행 경계

Crabbox는 원격 머신의 임대, 명령 실행, 반환을 관리합니다. 머신 내부 파일·네트워크·컴퓨트 경계는 선택한 제공자와 머신 구성에서 정해집니다. 임대 재사용은 준비 시간을 줄일 수 있으며, 상태 유지와 정리는 임대·제공자 수명 정책을 따릅니다. [Crabbox 공식 소스](https://github.com/openclaw/crabbox) · [임대 시작과 반환](https://github.com/openclaw/crabbox/blob/main/docs/getting-started.md)

## 에이전트 적용

[OpenClaw](../agents/openclaw.md) 2026.11.6은 직접 [Daytona](daytona.md) 임대 경로를 문서화합니다. 지원되는 제공자는 지정 임대에 대한 실행과 현재 저장소의 임대 종료 기능을 갖춰야 합니다. OpenClaw는 스코프당 임대 ID와 원격 Workspace를 관리하고 초기 작업 폴더를 전송합니다. Gateway와 모델 자격 증명은 호스트에 남으며 대상 셸·파일 작업은 임대한 환경에서 실행됩니다. 임대가 중지·아카이브 후 재개되면 원격 작업 영역이 유지될 수 있습니다. [OpenClaw 2026.11.6 Crabbox 백엔드](https://github.com/openclaw/openclaw/blob/v2026.11.6/docs/gateway/sandboxing/crabbox-backend.md)

## 실측 시 확인

제공자와 이미지, 새 임대와 재개, 초기 업로드 범위와 시간, 유휴·최대 수명, 명시적 반환 후 상태를 기록합니다. 파일과 네트워크 경계는 임대 내부에서 관찰합니다.
