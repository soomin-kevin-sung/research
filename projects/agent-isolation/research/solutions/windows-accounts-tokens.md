# Windows 전용 계정, Restricted Token, ACL과 WFP

## 실행 경계

전용 Windows 계정은 실행 주체를 바꾸고, ACL은 해당 주체가 파일 등 객체에 가진 권한을 결정합니다. `CreateRestrictedToken`은 기존 토큰에서 권한을 제거하거나 SID 사용을 제한할 수 있습니다. `WRITE_RESTRICTED`는 제한 SID 검사를 쓰기 요청에 적용하므로 읽기 범위에는 별도 정책이 필요합니다. Windows Filtering Platform(WFP)은 계정·애플리케이션 등에 대한 네트워크 필터를 적용할 수 있는 별도 계층입니다. [Microsoft Restricted Token API](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken) · [Windows ACL](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists) · [Microsoft WFP](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)

## 에이전트 적용

- [Codex](../agents/codex.md)의 `elevated`는 관리자 권한으로 격리 계정, ACL, 필요 시 방화벽 정책을 준비합니다. 실제 명령은 비관리자 격리 계정에서 실행합니다. `unelevated`는 현재 사용자에서 파생한 Restricted Token과 ACL을 사용하며 읽기 거부 경로를 지원하지 않습니다. 이 경로의 오프라인 설정은 환경 변수에 의존합니다. [Codex 0.171.0 소스](https://github.com/openai/codex/tree/rust-v0.171.0/codex-rs/windows-sandbox-rs) · [Codex Windows 샌드박스](https://learn.chatgpt.com/docs/windows/windows-sandbox)
- [QwenPaw](../agents/qwenpaw.md)는 `allow_read_all=True`인 Windows 샌드박스 경로에서 `WRITE_RESTRICTED`를 사용합니다. 관리자 경로는 전용 계정과 WFP를 사용해 전체 네트워크 차단을 강제할 수 있습니다. 비관리자 경로의 프록시 환경 변수는 이를 따르는 클라이언트에 영향을 줍니다. [QwenPaw 2.3.0.post1 보안 문서](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/website/public/docs/security.en.md)

## 제한 SID와 WRITE_RESTRICTED

제한 SID는 Windows 접근 토큰의 제한 목록에 넣는 보안 식별자입니다. Windows가 추가 검사를 적용하는 접근 요청은 **토큰의 일반 권한 검사와 제한 SID 목록을 사용한 검사**를 모두 통과해야 합니다. 파일의 ACL은 각 검사에서 어떤 식별자에 어떤 권한을 허용하는지 정합니다.

| 토큰 | 파일 읽기 | 파일 쓰기 |
| --- | --- | --- |
| 일반 토큰 | 일반 검사 | 일반 검사 |
| 제한 SID가 있는 토큰 | 일반 검사 + 제한 SID 검사 | 일반 검사 + 제한 SID 검사 |
| 같은 Restricted Token에 `WRITE_RESTRICTED` 적용 | 일반 검사 | 일반 검사 + 제한 SID 검사 |

같은 Restricted Token에서 플래그를 켜면 **읽기에서 제한 SID 검사만 빠지고, 쓰기 검사는 그대로**입니다. 읽기에도 실행 계정의 일반 권한과 파일 ACL은 적용됩니다. [Microsoft CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)

## 실측 시 확인

상위 ACL의 상속 아래에서 하위 읽기 전용과 거부를 따로 확인합니다. QwenPaw 관리자 경로의 거부 ACE와 비관리자 경로의 상속 쓰기 권한은 같은 결과로 합치지 않습니다. [제품별 하위 경로 비교](../security-boundaries.md#상위-폴더-허용과-하위-폴더-보호)

초기 관리자 작업과 일반 실행을 구분하고, 유효 계정·토큰·ACL·네트워크 정책을 기록합니다. 같은 합성 경로에서 읽기와 쓰기를 각각 확인하고, 첫 설정과 반복 실행에 드는 시간 및 ACL·계정·필터 정리 절차를 남깁니다.
