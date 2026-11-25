# Microsoft eXecution Container (MXC)

## 실행 경계

MXC는 애플리케이션이 실행 정책을 전달하는 Microsoft SDK입니다. Windows의 ProcessContainer는 Windows Process Security Environment(PSEC)를 사용해 호스트에서 자식 프로세스를 제한합니다. SDK에는 VM 등 다른 백엔드도 있으므로 실행 기록에는 MXC라는 이름과 함께 실제 백엔드를 남겨야 합니다. Codex의 네이티브 MXC 경로는 별도 격리 계정, 호스트 ACL 변경, 관리자 초기 설정 없이 동작합니다. [Microsoft MXC SDK](https://github.com/microsoft/mxc) · [MXC 정책 스키마](https://github.com/microsoft/mxc/blob/main/docs/schema.md) · [Codex 0.171.0 구현](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/mxc-sandbox/README.md)

## 에이전트 적용

| 경로 | 제품에서 전달하는 정책 |
| --- | --- |
| [Codex](../agents/codex.md) Windows 네이티브 | 유효 읽기·쓰기·거부 경로 및 네트워크 프로필을 BaseContainerRunner에 전달합니다. 관리형 프록시와 루프백은 권한 프로필에 따릅니다. |
| [OpenClaw Gateway](../agents/openclaw.md) | 플러그인이 MXC에 명령을 전달합니다. 호스트 프로브는 BaseContainer와 AppContainer 계열 격리 등급을 받아들입니다. 기본 네트워크는 `none`이며, 파일 거부 경로와 목적지별 네트워크 목록은 플러그인이 노출하지 않습니다. |
| [OpenClaw Windows Hub](../agents/openclaw.md) | 노드 `system.run`의 별도 MXC 통합입니다. 실행 전 BaseContainer가 보호 경로 거부를 비롯한 파일·네트워크·UI 정책을 적용할 수 있는지 판정합니다. |

제품별 정책 근거는 버전이 고정된 코드와 문서에 있습니다. [Codex Windows 샌드박스](https://learn.chatgpt.com/docs/windows/windows-sandbox) · [Gateway MXC 2026.11.6](https://github.com/openclaw/openclaw/blob/v2026.11.6/extensions/mxc/README.md) · [Hub 2026.11.3](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/docs/OPENCLAW_GATEWAY_NODE_EXEC_FAQ.md)

Store 네이티브 OpenClaw Gateway의 서비스 배치에는 SDK의 별도 [IsolationSession](mxc-isolation-session.md) 백엔드가 사용됩니다.

Codex는 지원 호스트에서 더 구체적인 경로 규칙을 적용합니다. Gateway 플러그인은 보호 스킬 경로가 쓰기 허용과 겹치면 셸 시작을 거부합니다. [제품별 하위 경로 비교](../security-boundaries.md#상위-폴더-허용과-하위-폴더-보호)

## OpenClaw Windows Hub의 지원 판정

Windows Hub `2026.11.3`의 노드 `system.run`은 **SDK 준비, BaseContainer 격리 등급, 호스트 ACL 변경 불필요, 보호 경로 거부 지원**을 요구합니다. 지원 장치에서도 명령별 전체 SDK 요청이 검사를 통과해야 합니다. Hub는 MXC 요청 검증 또는 호스트 호환 실행 준비가 끝나면, 어느 경로에서든 프로세스를 시작하기 직전에 승인을 다시 확인합니다.

| 판정 | 실행 경로 |
| --- | --- |
| BaseContainer에 필요한 정책을 적용할 수 있음 | MXC에서 실행하고 실행 중 파일·네트워크 등의 접근을 제한합니다. |
| OS 미지원 확인 | Windows Server로 확인됐거나, 오류 없는 프로브에서 BaseContainer API 부재와 AppContainer 계열 등급이 함께 확인됐습니다. 유효한 Hub 명령 승인을 거쳐 경고와 함께 비격리 호스트 경로에서 실행합니다. |
| 지원 여부 불명확, SDK·정책 검증 오류 | 프로세스 시작을 차단합니다. |
| 프로세스 시작 후 실행 오류 | 실행 실패로 처리하며 호스트에서 재시도하지 않습니다. |

[지원 판정 코드](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/src/OpenClaw.Shared/Mxc/MxcAvailability.cs#L16-L89) · [실행 경로 코드](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/src/OpenClaw.Shared/Mxc/NodeSandboxExecutor.cs) · [공식 호환 실행 설명](https://github.com/openclaw/openclaw-windows-node/blob/v2026.11.3/docs/OPENCLAW_GATEWAY_NODE_EXEC_FAQ.md#how-does-windows-sandboxing-work-and-is-it-a-gateway-plugin)

## 사용할 수 있는 장치와 비율

2026-11-25에 확인한 공식 문서와 통계입니다. 이 프로젝트에서는 MXC를 실측하지 않기로 했고, 이 절은 MXC를 쓸 수 있는 장치의 범위와 그 비율만 정리합니다.

### 지원 Windows 버전

MXC의 ProcessContainer는 Windows 11에서만 지원됩니다. Codex는 이 백엔드에서 BaseContainerRunner로 명령을 실행합니다. 기능 버전마다 최소 빌드가 다릅니다.

| Windows 11 버전 | ProcessContainer 최소 빌드 | 해당 업데이트 |
| --- | --- | --- |
| 24H2 | 26100.9278 | KB5120998(2026-08-27, 선택적 미리 보기 업데이트) |
| 25H2 | 26200.9278 | KB5120998(2026-08-27, 선택적 미리 보기 업데이트) |
| 26H2 | 26300.9550 | KB5124010(2026-09-29) |
| 26H1(새 장치 전용) | 28000.2804 | KB5120996 |

- 24H2·25H2에서 최소 빌드를 포함하는 첫 월간 보안 업데이트는 2026-09-08의 KB5124008(빌드 .9445)입니다. 2026년 9월 이후의 보안 업데이트를 설치한 24H2·25H2 장치는 빌드 조건을 만족합니다.
- 아키텍처는 x64와 ARM64입니다. ProcessContainer는 사용자 세션 안에서 실행되며 중첩 가상화가 필요 없습니다.
- Windows 10과 Windows Server는 지원 목록에 없습니다.
- 에디션(Home·Pro·Enterprise·Education)별 지원 여부는 문서에 없습니다. 24H2 기반인 Windows 11 Enterprise LTSC 2024의 지원 여부도 확인하지 못했습니다.
- OpenClaw Store Gateway가 쓰는 [IsolationSession](mxc-isolation-session.md)은 26100.9550·26200.9550·26300.9550·28000.3086 이상이 필요합니다. Microsoft 문서는 이 빌드를 만족해도 IsolationSession을 쓸 수 있다고 보장하지 않습니다.

빌드 조건을 만족해도 실제 사용 가능 여부는 장치마다 다릅니다.

- Microsoft 문서는 MXC가 지원하는 Windows 버전이어도 특정 정책 기능이 없을 수 있다고 설명합니다.
- Codex 문서는 Microsoft가 필요한 기능을 Windows 11 장치에 배포하는 중이며, 버전 표만으로 특정 장치의 MXC 사용 가능 여부를 확정할 수 없다고 설명합니다.
- Codex 소스는 OS 빌드 번호가 아니라 MXC의 실행 시점 프로브 결과로 사용 가능 여부를 판정합니다. SDK의 플랫폼 지원 조회와 프로브로 장치별 지원 여부를 확인할 수 있습니다.

### Windows 사용자 중 비율

StatCounter의 2026년 10월 데스크톱 통계입니다. 설치 대수가 아니라 웹 페이지 조회 기준입니다.

| 지역 | Windows 중 Windows 11 | Windows 중 Windows 10 | 데스크톱 중 Windows | 데스크톱 전체 중 Windows 11(두 비율의 곱) |
| --- | --- | --- | --- | --- |
| 전 세계 | 74.29% | 25.13% | 76.65% | 약 56.9% |
| 한국 | 66.03% | 33.73% | 86.1% | 약 56.9% |

- **상한.** MXC는 Windows 11에서만 지원되므로 Windows 데스크톱 사용자 중 MXC를 쓸 수 있는 비율은 전 세계 최대 약 74%, 한국 최대 약 66%입니다.
- **실제 비율은 이보다 낮습니다.** 다음 장치가 빠지기 때문입니다.
  - 23H2 이하의 Windows 11. 23H2는 Home·Pro가 2025-11-11에, Enterprise·Education이 2026-11-10에 업데이트가 끝났습니다. Microsoft는 IT 부서가 관리하지 않는 Home·Pro 장치를 자동으로 새 기능 버전으로 올립니다.
  - 2026년 9월 이후의 업데이트를 설치하지 않은 24H2·25H2 장치.
  - 빌드 조건을 만족해도 기능이 아직 배포되지 않은 장치.
- **얼마나 낮은지는 정할 수 없습니다.** Windows 11을 기능 버전이나 업데이트 수준별로 나눈 공개 통계를 찾지 못했습니다. StatCounter도 Windows 11을 나누지 않습니다.
- 이 프로젝트의 측정 PC(Windows 11 Pro 25H2, 빌드 26200.9974)는 빌드 조건을 만족합니다. 실제로 MXC를 쓸 수 있는지는 확인하지 않았습니다.

[MXC ProcessContainer OS 버전 지원](https://github.com/microsoft/mxc/blob/main/docs/backends/process-container/os-version-support.md) · [MXC 플랫폼 지원](https://learn.microsoft.com/en-us/windows/apps/develop/mxc/platform-support) · [Windows 365의 MXC 지원](https://learn.microsoft.com/en-us/windows-365/process-isolation-on-cloud-pcs) · [Codex Windows 샌드박스](https://learn.chatgpt.com/docs/windows/windows-sandbox) · [Codex 0.171.0 MXC 구현](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/mxc-sandbox/README.md) · [Windows 11 릴리스 정보](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information) · [23H2 Home·Pro 지원 종료](https://www.bleepingcomputer.com/news/microsoft/microsoft-windows-11-23h2-reaches-end-of-support-in-30-days/amp/) · [StatCounter Windows 버전(전 세계)](https://gs.statcounter.com/windows-version-market-share/desktop/worldwide) · [StatCounter Windows 버전(한국)](https://gs.statcounter.com/windows-version-market-share/desktop/south-korea) · [StatCounter 데스크톱 OS(전 세계)](https://gs.statcounter.com/os-market-share/desktop/worldwide) · [StatCounter 데스크톱 OS(한국)](https://gs.statcounter.com/os-market-share/desktop/south-korea)

## 실측 시 확인

이 프로젝트에서는 MXC를 실측하지 않기로 했습니다(2026-11-25). 아래는 실측할 때 확인할 항목입니다.

OS 빌드와 MXC 기능 프로브, 최종 백엔드, 자식 실행과 종료 여부를 기록합니다. 정책이 적용된 합성 파일과 가짜 환경 변수, 허용·비허용 시험 서버의 결과를 경로별로 관찰합니다. 선택 실패와 정책에 의한 접근 차단을 각각 기록합니다.

### 보호 폴더 이름 변경 후 읽기 거부

Codex MXC의 경로 거부 지원 검사는 Windows가 거부 규칙을 집행할 수 있는지 확인합니다. 쓰기가 허용된 상위 폴더에서 보호 폴더의 이름을 바꿀 수 있는지, 새 이름에서도 보호가 유지되는지는 실측 항목입니다. 이름 변경을 요청한 주체를 샌드박스 셸과 호스트 사용자로 나눠 기록합니다. [Codex MXC 구현](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/mxc-sandbox/README.md) · [실측 프로토콜](../../protocol.md#mxc-보호-폴더-이름-변경)
