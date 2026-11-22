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

## 실측 시 확인

OS 빌드와 MXC 기능 프로브, 최종 백엔드, 자식 실행과 종료 여부를 기록합니다. 정책이 적용된 합성 파일과 가짜 환경 변수, 허용·비허용 시험 서버의 결과를 경로별로 관찰합니다. 선택 실패와 정책에 의한 접근 차단을 각각 기록합니다.
