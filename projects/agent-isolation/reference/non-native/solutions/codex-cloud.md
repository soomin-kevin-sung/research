# Codex Cloud

## 실행 경계

문서가 설명하는 Codex Cloud는 작업마다 원격 VM과 개별 작업 파일을 제공합니다. 새 작업은 게시한 환경의 준비된 파일시스템에서 시작하고, 기존 작업은 자체 저장 상태를 이어갑니다. 공용 인터넷은 환경의 도메인 정책을 따르며, 사설 연결을 위한 VPN 설정은 별도입니다. 일반 환경 변수는 프로세스에 전달하고 HTTP 비밀은 프록시에서 허용 목적지에 대해 치환할 수 있습니다. 레거시 Cloud는 별도 환경 설정을 사용합니다. [Codex Cloud 환경](https://learn.chatgpt.com/docs/environments/cloud-environments) · [레거시 Cloud 환경](https://learn.chatgpt.com/docs/environments/cloud-environment)

## 에이전트 적용

[Codex](../agents/codex.md)의 원격 실행 경로입니다. Windows 로컬과 Worktree 모드에서는 명령이 로컬에서 실행되고 Windows 샌드박스 정책을 따릅니다. Cloud의 실행 환경과 Git worktree의 작업 디렉터리 분리를 각각 기록합니다. [Codex 실행 모드](https://learn.chatgpt.com/docs/environments/modes)

## 실측 시 확인

Cloud 환경과 작업의 식별자, 준비된 이미지 상태, 일반 변수와 프록시를 통한 비밀의 처리, 공용·사설 네트워크 정책, 세션 재개 시 상태를 기록합니다. 원격 준비 시간과 VM 내부 워크로드 시간을 구분합니다.
