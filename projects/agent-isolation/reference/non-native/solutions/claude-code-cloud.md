# Claude Code 관리형 클라우드

## 실행 경계

Anthropic 호스팅 클라우드 세션은 셸과 파일 작업을 관리형 VM에 배치합니다. 기본 외부 네트워크는 제한되며 환경 설정에서 접근 수준, 환경 변수, 초기화 스크립트를 정합니다. 일반 네트워크를 비활성화해도 Anthropic API 경로는 남습니다. Git 자격 증명과 서명 키는 실행 VM 밖에 두고 프록시가 범위가 제한된 자격 증명으로 인증합니다. 조직에서 자체 호스팅을 선택한 경우의 실행 경계는 조직 배포에 따릅니다. [Claude Code 클라우드 보안과 환경 설정](https://code.claude.com/docs/en/claude-code-on-the-web)

## 에이전트 적용

[Claude Code](../agents/claude-code.md)의 전체 원격 세션 배포 방식입니다. Windows 네이티브 CLI의 승인이나 WSL2에서 셸을 제한하는 [Bubblewrap](bubblewrap.md)과 별개의 실행 경로로 기록합니다.

## 실측 시 확인

세션 호스팅 유형, 초기 파일과 환경 변수 전달, 외부 네트워크 정책, 새 세션과 기존 세션에서 관찰한 상태 수명을 기록합니다. 관리형 경로는 Windows 로컬 기준 실행과 별도의 환경으로 비교합니다.
