# Vercel Sandbox

## 실행 경계

Vercel Sandbox는 Firecracker microVM에서 명령을 실행하며 각 VM에 파일시스템과 네트워크를 제공합니다. 제공자의 아웃바운드 방화벽은 전면 허용·차단과 목적지 제한을 지원합니다. 샌드박스와 실행 세션의 수명을 구분하며, 스냅샷에 저장된 파일 상태는 이후 세션에서 복원할 수 있습니다. [Vercel Sandbox](https://vercel.com/docs/sandbox) · [네트워크와 스냅샷 SDK](https://vercel.com/docs/sandbox/sdk/javascript)

## 에이전트 적용

[Hermes Agent](../agents/hermes.md)의 `vercel_sandbox`는 이 서비스에 연결하는 선택형 터미널 백엔드입니다. 런타임, 세션 시간과 상태 보존 설정은 Hermes 어댑터가 사용하는 값을 기록합니다. Vercel의 SDK 기능 목록과 Hermes가 실제로 전달하는 방화벽 정책은 각각 확인해야 합니다. [Hermes 0.23.3 Vercel 어댑터](https://github.com/NousResearch/hermes-agent/blob/v0.23.3/tools/environments/vercel_sandbox.py)

## 실측 시 확인

새 VM과 스냅샷 복원 비용, 실제 네트워크 정책, 파일 이동 범위, 명령 종료와 세션 종료 후 상태를 관찰합니다. 제공자 API 응답 시간과 VM 내부 작업 시간을 구분합니다.
