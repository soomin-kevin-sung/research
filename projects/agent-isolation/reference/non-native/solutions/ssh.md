# SSH 원격 실행

## 실행 경계

SSH는 인증된 원격 세션에서 명령을 실행합니다. 실행 계정의 파일과 네트워크 권한은 원격 OS·계정·방화벽·추가 컨테이너 또는 VM 정책을 따릅니다. OpenSSH 서버에서 환경 변수 전달, 포워딩, 강제 명령, 파일시스템 루트 변경의 적용 여부는 서버 설정에 따라 달라집니다. [OpenSSH 서버 설정](https://man.openbsd.org/sshd_config)

## 에이전트 적용

[OpenClaw](../agents/openclaw.md)의 SSH 백엔드는 원격 작업 영역을 초기화하고 원격 파일을 작업 상태의 기준으로 사용합니다. [Hermes Agent](../agents/hermes.md)는 SSH를 터미널 백엔드로 선택해 지정 원격 계정에서 실행합니다. [OpenCode](../agents/opencode.md)의 별도 서버 배포는 OpenCode 서버 API 경로이며, SSH는 운영자가 서버 접근과 배치에 사용할 수 있습니다. [OpenClaw SSH 백엔드](https://docs.openclaw.ai/gateway/sandboxing/ssh-backend) · [Hermes 0.23.3 구성](https://github.com/NousResearch/hermes-agent/blob/v0.23.3/website/docs/user-guide/configuration.md) · [OpenCode 서버 API](https://opencode.ai/docs/api/)

## 실측 시 확인

원격 호스트, 사용자, 작업 경로, 초기 복사 범위, 허용된 환경 변수와 원격 네트워크 규칙을 기록합니다. 접속·초기 동기화·원격 작업 시간을 따로 재고, 접속을 닫은 뒤 원격 작업 영역과 합성 상태가 유지되는지 확인합니다.
