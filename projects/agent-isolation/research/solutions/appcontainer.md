# Windows AppContainer

## 실행 경계

AppContainer는 Windows에서 프로세스 토큰에 AppContainer SID와 capability SID를 부여하고, 해당 보안 주체에 허용된 리소스 접근을 강제합니다. 파일·레지스트리, 네트워크, 프로세스와 UI의 적용 범위는 객체 권한과 capability에 따릅니다. 네트워크 capability는 연결 범주를 부여하며, 제품이 세밀한 목적지 정책을 제공하는지는 별도로 확인해야 합니다. [Microsoft AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)

## 에이전트 적용

- [QwenPaw](../agents/qwenpaw.md)는 Windows 샌드박스로 분기하고 `allow_read_all=False`일 때 AppContainer를 선택합니다. 초기 설정은 Win32 API로 작업 영역과 기존 거부 경로에 ACL을 적용합니다. 거부 ACE 설정 실패와 프로필 재사용 시의 유효 ACL은 별도 확인이 필요합니다. 네트워크 도메인 목록과 환경 변수 허용 목록은 이 버전에서 강제되지 않습니다. [QwenPaw 구현](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_appcontainer_sandbox.py) · [지원 제약](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/website/public/docs/security.en.md#current-limitations)
- [OpenHuman](../agents/openhuman.md)이 고정한 [TinyBox](tinybox.md)에는 AppContainer 구현이 있지만, 해당 리비전의 자동 탐지는 Windows를 선택하지 않습니다. Windows 로컬 셸의 유효 백엔드는 OpenHuman 상태와 실행 경로로 확인합니다. [TinyBox 탐지 소스](https://github.com/tinyhumansai/tinybox/blob/8b3c7c9a208c9240e8ce3af7902722652aba7b47/crates/tinybox-jail/src/detect.rs)

## 실측 시 확인

프로필 선택과 재사용 여부, 작업 폴더에 부여한 ACL, 네트워크 capability, 가짜 변수의 자식 상속을 기록합니다. 초기 프로필·ACL 준비 비용과 반복 명령 실행 비용을 구분합니다. [MXC 통합](mxc.md)은 각 제품이 실제 선택하는 SDK 백엔드를 기준으로 추적합니다.
