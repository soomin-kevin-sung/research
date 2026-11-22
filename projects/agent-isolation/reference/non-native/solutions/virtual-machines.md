# 외부 가상 머신

## 실행 경계

Hyper-V 같은 하이퍼바이저는 게스트가 자체 OS와 커널을 실행할 경계를 제공합니다. 호스트 데이터의 노출은 작업 파일을 옮기는 방법, 공유 폴더, 관리 채널, 네트워크 구성에 좌우됩니다. 디스크를 재사용하는 경우 VM 종료 후에도 파일이 남습니다. [Microsoft Hyper-V 개요](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/overview)

## 에이전트 적용

[Claude Code](../agents/claude-code.md) 공식 문서는 에이전트 전체를 VM에서 실행하는 배포 방식을 설명합니다. [OpenCode](../agents/opencode.md) 엔진을 별도 VM에 배치하는 것도 조사에서 고려한 외부 구성입니다. OpenCode의 내장 승인과 VM의 OS 정책은 각각 적용됩니다. [Claude Code 격리 환경](https://code.claude.com/docs/en/sandbox-environments) · [OpenCode 서버 API](https://opencode.ai/docs/api/)

## 실측 시 확인

게스트 OS, 호스트 통합 기능, 네트워크, 데이터 공유 및 디스크 수명을 기록합니다. 새 VM 부팅과 이미 부팅된 VM에서의 작업 시간을 구분합니다.
