# OpenCode의 Windows 실행 격리

2026-11-23 확인 · Anomaly의 OpenCode 안정 릴리스 `1.19.6` · 대상은 Windows CLI와 로컬 데스크톱 엔진입니다. [OpenCode v1.19.6 릴리스](https://github.com/anomalyco/opencode/releases/tag/v1.19.6)

[조사 목록](../README.md)

관련 기술은 [도구 승인과 호스트 셸](../../../research/solutions/tool-approval.md) · [WSL2](../solutions/wsl2.md) · [Docker](../solutions/docker.md) · [외부 VM](../solutions/virtual-machines.md)에서 설명합니다.

## 로컬 셸 실행 방식

안정 태그의 Windows 셸 도구는 네이티브 자식 프로세스를 실행합니다. PowerShell은 `-NoProfile`, `-NonInteractive`, `-Command` 인자로 호출하고, 다른 셸도 해당 호스트에서 실행합니다. 이 코드 경로에서는 AppContainer, MXC, Restricted Token, 컨테이너와 같은 OS 격리를 추가하지 않습니다. 셸의 작업 디렉터리와 타임아웃을 지정할 수 있으며, 환경은 호스트의 `process.env`에 플러그인의 `shell.env` 값을 합칩니다. [안정 태그 셸 구현](https://github.com/anomalyco/opencode/blob/v1.19.6/packages/opencode/src/tool/shell.ts)

## V1과 V2의 승인 규칙

| 표면 | 권한 설정 | 실행 경계 |
| --- | --- | --- |
| 안정 릴리스의 V1 경로 | `permission`, 셸 도구 키 `bash`, 외부 경로 키 `external_directory` | 셸 명령과 발견된 외부 경로를 사전 평가하고, 허용된 명령은 호스트 계정으로 실행 |
| 현재 V2 온라인 안내 | `permissions` 규칙 배열, `shell`과 `external_directory` 액션, 마지막 일치 규칙 적용 | 공식 문서는 셸 실행이 호스트 사용자의 파일·프로세스·네트워크 권한을 사용한다고 명시 |

V1의 기본 에이전트 규칙은 일반 도구를 허용하면서 외부 디렉터리를 기본적으로 묻고, 직접 파일 읽기에서 일부 `.env` 패턴을 확인합니다. 셸 구현은 구문을 파싱해 처리할 명령과 추론한 디렉터리에 대한 승인을 요청합니다. 이 제어는 OpenCode가 관찰 가능한 도구 요청에 걸립니다. 셸이 시작한 프로그램의 파일 읽기·네트워크 접근까지 OS 권한으로 가두는 방식은 해당 코드에서 확인되지 않습니다. V2 온라인 문서는 외부 디렉터리의 기본값을 허용으로 설명하므로 V1 설정과 혼용하면 평가 결과가 달라집니다. [V1 에이전트 권한 소스](https://github.com/anomalyco/opencode/blob/v1.19.6/packages/opencode/src/agent/agent.ts) · [V1 도구 키](https://github.com/anomalyco/opencode/blob/v1.19.6/packages/opencode/src/tool/shell/id.ts) · [V2 권한과 스캐너](https://opencode.ai/docs/permissions/) · [V2 셸 도구](https://opencode.ai/docs/tools/)

## WSL과 외부 실행 환경

Windows에서 컴퓨트 경계를 따로 두려면 OpenCode 엔진을 격리된 컨테이너, VM 또는 별도 계정의 원격 호스트에서 실행하는 구성이 비교 대상이 됩니다. 이 경우 경계는 해당 환경의 마운트, 네트워크, 사용자 권한이 제공합니다. Windows UI가 연결한 OpenCode 서버의 위치와 명령이 실제로 실행된 위치를 함께 기록합니다. WSL만 사용하는 조건에서는 드라이브 자동 마운트와 Windows interop의 유효 설정도 확인합니다. [OpenCode 서버 API](https://opencode.ai/docs/api) · [WSL 설정](https://learn.microsoft.com/en-us/windows/wsl/wsl-config)

## 실측에서 확인할 항목

- V1과 V2를 빌드 및 설정 버전별로 구분하고, 사전 승인 요구와 실제 파일·네트워크 접근 결과를 별도 값으로 기록합니다.
- V1의 `external_directory` 승인, 내장 `read` 권한, 승인된 셸 자식의 권한을 각각 합성 파일로 확인합니다. 가짜 환경 변수와 목적지 테스트는 호스트 실행과 별도 컨테이너 실행을 비교합니다.
- 원격 UI나 서버를 사용할 때 작업 경로, 셸, 실행 계정, 프로세스가 생성된 호스트를 명시합니다.
