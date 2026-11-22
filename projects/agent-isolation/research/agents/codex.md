# Codex의 Windows 실행 격리

2026-11-23 확인 · CLI 안정 릴리스 `0.171.0` · 대상은 Windows 데스크톱, CLI, IDE의 로컬 명령 실행입니다. 이 조사 환경의 CLI도 `codex-cli 0.171.0`으로 확인했습니다. [Codex v0.171.0 릴리스](https://github.com/openai/codex/releases/tag/rust-v0.171.0)

[조사 목록](../README.md)

관련 기술은 [MXC](../solutions/mxc.md) · [전용 계정·제한 토큰·ACL·WFP](../solutions/windows-accounts-tokens.md)에서 설명합니다.

## 네이티브 실행과 백엔드 선택

Codex는 Windows에서 PowerShell 명령과 자식 프로세스를 네이티브 샌드박스에 넣을 수 있습니다. 호환 장치에서 소비자 계정의 데스크톱 앱은 MXC를 우선합니다. CLI와 관리 배포에서는 `features.prefer_mxc = true`로 호환 장치에서 MXC를 먼저 시도하고, 사용할 수 없으면 기존 백엔드 선택을 따릅니다. CLI 소스에서 명시적 `windows.sandbox = "mxc"`는 엄격한 선택이며, 명령 실행 실패 자체는 백엔드 전환 조건이 아닙니다. [Windows 샌드박스](https://learn.chatgpt.com/docs/windows/windows-sandbox) · [v0.171.0 MXC 구현 설명](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/mxc-sandbox/README.md)

| 백엔드 | Windows 격리 메커니즘 | 파일 및 네트워크 정책 |
| --- | --- | --- |
| `mxc` | Microsoft Execution Containers의 `BaseContainerRunner`와 Windows PSEC. 호환성은 OS 버전명보다 런타임 프로브로 확인 | 경로별 쓰기·읽기·거부 정책과 네트워크 정책 적용. 별도 샌드박스 계정이나 로컬 방화벽 규칙 없이 실행 |
| `elevated` | 관리자 승인으로 별도 샌드박스 계정과 ACL 등을 준비. 명령은 해당 비관리자 계정에서 실행 | ACL과 계정 경계로 파일 접근을 제어. 오프라인 샌드박스 사용자에 대한 방화벽 규칙으로 네트워크 차단 |
| `unelevated` | 현재 사용자에서 파생한 제한 토큰과 ACL. 관리자 사전 준비가 어려운 환경의 레거시 대체 경로 | 파일 경계는 적용하지만 읽기 거부 경로를 지원하지 않음. 오프라인 정책은 환경 변수에 의존하여 네트워크 격리가 약함 |

MXC 구현은 Windows PSEC의 BaseContainer 경로를 사용합니다. 두 레거시 백엔드는 기본적으로 별도 데스크톱도 사용합니다. 관리 설정의 `windows.allow_mxc`는 MXC 선택을 제어하고, `windows.allowed_sandbox_implementations`는 허용할 레거시 백엔드를 제어합니다. Windows 11은 권장 기준이며, MXC 사용 가능 여부는 대상 PC에서 별도로 확인해야 합니다. [Windows 샌드박스](https://learn.chatgpt.com/docs/windows/windows-sandbox) · [레거시 Windows 구현](https://github.com/openai/codex/tree/rust-v0.171.0/codex-rs/windows-sandbox-rs)

## 권한 정책과 적용 범위

권한 프로필은 읽기·쓰기·네트워크를 정하고, 승인 정책은 추가 권한을 요청하는 시점을 정합니다. 따라서 데스크톱 앱의 이름이나 세션의 승인 모드만으로 실제 파일 제한을 판단할 수 없습니다. CLI에서는 `/status`와 `/debug-config`로 유효 설정을 확인합니다. MXC의 프로세스 환경은 일부 Windows 변수와 네트워크 프록시 변수를 런타임에서 다루므로, 환경 변수 격리는 실제 자식 프로세스에서 관찰해야 합니다. MCP 서버와 UI 자동화에는 각 실행 경로의 별도 권한을 적용해 평가합니다. [Windows 샌드박스](https://learn.chatgpt.com/docs/windows/windows-sandbox) · [MXC 런타임 환경 및 네트워크](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/mxc-sandbox/README.md)

MXC의 관리형 프록시를 사용하려면 유효 `allow_local_binding` 정책이 필요합니다. 이 경우 호스트 루프백과 통신할 수 있으며, 프록시를 거치는 트래픽에는 도메인 규칙이 계속 적용됩니다. 포그라운드 명령이 끝나면 남은 자식도 종료되는 동작이 있으므로, 백그라운드 개발 서버는 별도 작업 조건으로 확인합니다. [MXC 호환성 및 네트워크 설명](https://learn.chatgpt.com/docs/windows/windows-sandbox)

## 실측에서 확인할 항목

- 같은 Windows 빌드에서 MXC, elevated, unelevated를 각각 기록합니다. 명령 결과에 선택된 백엔드와 적용 권한 프로필을 함께 남깁니다.
- 작업 폴더 쓰기, 폴더 밖 합성 파일 읽기·쓰기, 네트워크 차단, 가짜 환경 변수 상속을 명령과 자식 프로세스에서 각각 확인합니다. 읽기 거부를 지원하지 않는 조합은 지원 범위를 구분합니다.
- 최초 설치·프로비저닝과 반복 명령 비용을 분리합니다. MXC 호환성 프로브와 레거시 관리자 승인·방화벽 정책을 환경 조건으로 기록합니다.
