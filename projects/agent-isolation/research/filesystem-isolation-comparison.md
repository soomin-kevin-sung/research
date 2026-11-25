# Windows 셸의 파일 권한과 읽기 거부 비교

Codex `0.171.0`, QwenPaw `2.3.0.post1`의 Windows 셸과 자식 프로세스를 비교합니다. 이 문서의 내용은 문서·소스 기준입니다. QwenPaw와 Codex `unelevated`·`elevated`의 실측 결과는 [결과 및 판단](../findings.md#restricted-token-네-구성-실측-2026-11-25)과 [상위·하위 폴더 권한 조합 실행 기록](../runs/2026-11-25-04.md)에 있습니다. MXC BaseContainer는 측정하지 않았습니다.

## 실행 방식

| 경로 | 실행 경계 | 파일 접근 검사 |
| --- | --- | --- |
| Codex MXC BaseContainer | MXC SDK가 Windows PSEC 정책을 적용한 프로세스를 시작합니다. | 파일의 읽기·쓰기·거부 경로를 명령별 정책으로 전달합니다. 명시적 거부에는 호스트의 네이티브 경로 거부 기능이 필요합니다. |
| QwenPaw AppContainer | AppContainer SID와 capability를 셸에 부여합니다. | 읽기와 쓰기에 컨테이너 권한이 적용됩니다. 허용 경로에 SID별 ACL을 설정합니다. |
| QwenPaw Restricted Token | 비관리자는 현재 사용자, 관리자는 별도 저권한 계정의 토큰을 사용합니다. | `WRITE_RESTRICTED`로 제한 SID 검사를 쓰기에만 추가합니다. 읽기는 실행 계정의 일반 권한과 ACL을 따릅니다. |
| Codex `elevated` | 관리자 권한으로 초기 설정을 하고, 실제 셸은 별도 저권한 계정의 Restricted Token으로 실행합니다. | QwenPaw 관리자 경로와 마찬가지로 `WRITE_RESTRICTED`와 ACL을 사용합니다. 명시적 읽기 거부는 파일 ACL로 적용할 수 있습니다. |

Restricted Token은 Windows 기능입니다. Codex `elevated`는 그 기능과 계정·ACL·방화벽을 조합한 구현으로, 이름의 `elevated`는 **초기 설정에 필요한 관리자 권한**을 뜻합니다. [Codex MXC 구현](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/mxc-sandbox/README.md) · [Codex elevated 설계](https://openai.com/index/building-codex-windows-sandbox/) · [QwenPaw 백엔드 선택](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/config.py#L800-L816) · [Restricted Token 검사](solutions/windows-accounts-tokens.md#제한-sid와-write_restricted)

## 상위 허용과 하위 보호

| 경로 | 이미 존재하는 하위 경로 | 나중에 생기는 파일·폴더 |
| --- | --- | --- |
| Codex MXC BaseContainer | 더 구체적인 하위 경로 규칙을 적용할 수 있습니다. | 거부 글롭은 셸 시작 시 존재하는 경로로 확장됩니다. 이후 생성된 일치 파일은 다른 정책이 허용하면 읽을 수 있습니다. 명시적으로 거부된 폴더 안의 새 파일은 별도 사례입니다. |
| QwenPaw AppContainer | 상위 폴더에 허용 ACL을 설정한 뒤 기존 `deny_paths`에 컨테이너 SID의 접근 거부 ACE를 설정합니다. 설정 성공을 실측에서 확인해야 합니다. | 자식 객체에 부모 ACL이 상속될 수 있습니다. 초기 설정 시 없던 거부 대상은 건너뛰므로 해당 경로가 생길 때 별도 거부가 적용되는지 확인해야 합니다. |
| QwenPaw Restricted Token | 관리자 경로는 기존 `deny_paths`에 전용 계정의 접근 거부 ACE를 적용합니다. 비관리자 기본 경로에는 해당 집행이 없습니다. | 관리자 경로도 설정 시 없던 거부 대상을 건너뜁니다. 새 객체의 실제 권한은 적용된 ACL과 상속에 따릅니다. |
| Codex `elevated` | 하위 읽기 거부와 읽기 전용 예외를 적용할 수 있습니다. 조사 버전은 읽기 전용 하위 경로 안의 더 깊은 쓰기 재허용을 요구하는 정책이면 시작을 거부합니다. | 거부 글롭은 MXC와 동일하게 프로세스 시작 시점에 확장됩니다. 이미 거부 ACL이 적용된 폴더의 자식은 ACL 상속으로 별도 확인합니다. |

[MXC 경로 우선순위](https://github.com/microsoft/mxc/blob/main/docs/schema.md#overlapping-paths-for-windows-basecontainer) · [Codex 글롭 처리](https://learn.chatgpt.com/docs/windows/windows-sandbox) · [QwenPaw AppContainer ACL](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_appcontainer_sandbox.py#L225-L279) · [QwenPaw 관리자 ACL](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_elevated_sandbox.py#L1527-L1540) · [Codex elevated의 중첩 쓰기 제약](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/sandboxing/src/windows.rs#L217-L227)

## 상위 거부와 특정 하위 허용

예를 들어 `A`의 목록과 일반 내용을 막고, 정확한 경로를 알고 있는 `A\B`만 열어 주는 정책입니다. 상위 폴더의 **목록 조회**, 상위를 거치는 **경로 탐색**, 하위 파일의 **읽기·쓰기**는 각각 확인합니다.

| 경로 | 문서·소스 기준 |
| --- | --- |
| MXC BaseContainer | Microsoft 스키마는 상위가 `deniedPaths`에 있어도 명시적으로 `readwritePaths`에 넣은 하위는 읽고 쓸 수 있고, 다른 하위는 거부된다고 명시합니다. 같은 하위 경로를 허용과 거부에 모두 지정하면 거부됩니다. Codex의 유효 프로필이 이 조합을 실제로 전달하는지와 상위 탐색이 필요한 도구의 호환성은 별도 확인합니다. |
| QwenPaw AppContainer | 상위에 컨테이너 접근 허용이 없고 하위만 허용한 경우와, 상위에 상속되는 명시적 거부 ACE를 준 경우를 구분합니다. 후자는 하위의 직접 허용, 상속 거부 및 경로 탐색에 따라 결과가 달라집니다. 조사 버전의 설정 경로에서 조합 전체를 보장하는 근거는 확인하지 못했습니다. |
| QwenPaw Restricted Token | 비관리자 기본 백엔드는 명시적 상위 읽기 거부를 집행하지 않습니다. 관리자 경로는 기존 부모에 전용 계정 거부 ACE를 설정할 수 있습니다. 하위 허용이 동일 실행 계정과 Restricted Token에서 유효한지는 실제 ACL과 경로 탐색 권한을 확인해야 합니다. |
| Codex `elevated` | ACL의 직접·상속 권한에 따라 결과가 정해집니다. 조사 버전이 거부하는 것은 **쓰기 허용 영역 안의 읽기 전용 구간 아래에 쓰기를 다시 여는 조합**입니다. 상위의 명시적 읽기 거부 아래에 읽기만 다시 여는 조합은 별도로 실측합니다. |

Windows의 `SeChangeNotifyPrivilege`는 허용된 하위 경로로 이동할 때 상위 경로의 탐색 검사를 건너뛰게 할 수 있습니다. 이 권한으로 상위 폴더의 목록 조회나 하위 파일 자체의 읽기·쓰기 권한이 생기지는 않습니다. NTFS에서는 직접 지정한 ACE와 상속 ACE의 평가 순서도 확인해야 합니다. [MXC 상하위 우선순위](https://github.com/microsoft/mxc/blob/main/docs/schema.md#overlapping-paths-for-windows-basecontainer) · [Windows 경로 탐색 권한](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/bypass-traverse-checking) · [Windows DACL 평가 순서](https://learn.microsoft.com/en-us/windows/win32/secauthz/order-of-aces-in-a-dacl) · [Codex elevated 제약](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/sandboxing/src/windows.rs#L217-L227)

## 읽기 거부가 유지되는지 확인할 조건

| 조건 | 문서·소스로 확인한 범위 | 실측에서 판단할 것 |
| --- | --- | --- |
| 보호 폴더 이름 변경 또는 같은 볼륨 내 이동 | Windows에서 읽기 권한은 이름 변경 권한과 별개입니다. 대상의 삭제 권한과 부모의 자식 삭제 권한이 이름 변경에 관여합니다. 동일 NTFS 객체에 설정된 거부 ACL이 유지된다면 새 이름에도 적용됩니다. | 샌드박스 셸이 이름을 변경할 수 있는지와 변경 후 읽기 가능 여부를 분리합니다. 호스트가 변경했을 때 실행 중 셸의 결과도 따로 기록합니다. 특히 MXC의 기존 거부가 새 경로에 유지되는지는 미실측입니다. |
| 동일 파일의 다른 이름 | Codex MXC 문서는 이미 존재하는 **하드 링크 이름의 권한이 독립적**이라고 명시합니다. 한 이름의 거부는 같은 파일의 모든 이름에 대한 객체 단위 거부를 보장하지 않습니다. Microsoft MXC의 동등 경로 및 심볼릭 링크·정션 규칙은 하드 링크와 구분합니다. | 합성 파일에 대해 일반 경로와 이미 존재하는 대체 이름에서의 읽기 판정을 각각 확인합니다. 대체 이름을 셸이 만들 수 있는지는 별도 항목입니다. |
| 실행 중 새 파일 또는 폴더 생성 | Codex의 글롭은 시작 시점의 상태를 사용합니다. QwenPaw AppContainer·관리자 Restricted Token은 설정 시 없던 명시적 거부 대상을 건너뜁니다. | 기존 거부 폴더 **안에** 새로 생긴 파일과, 설정할 때 없던 **거부 대상 자체**의 생성을 구분합니다. 같은 셸과 새 셸의 결과를 기록합니다. |
| 거부 ACL 적용 실패 | QwenPaw의 두 ACL 설정 호출부는 거부 ACE를 설정하는 함수의 성공 여부를 확인하지 않습니다. | 설정 로그, 실제 ACL, 프로세스 시작 여부, 실제 파일 읽기 결과를 각각 확인합니다. |

[이름 변경 권한](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-deletefilew#remarks) · [NTFS 이동과 ACL](https://learn.microsoft.com/en-us/troubleshoot/windows-client/windows-security/permissions-on-copying-moving-files) · [Codex MXC 경로 별칭과 하드 링크](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/mxc-sandbox/README.md) · [이름 변경 실측 프로토콜](../protocol.md#mxc-보호-폴더-이름-변경)

## AppContainer의 파이프와 이름 있는 객체

AppContainer는 파일 외 자원에도 영향을 줍니다. Microsoft는 AppContainer의 이름 있는 객체에 별도 이름 공간을 설명합니다. 이벤트·뮤텍스·공유 메모리 등을 호스트와 공유하려면 이름과 객체 ACL 조건이 맞아야 합니다. 명명된 파이프 문서에는 Windows 10 1709 AppContainer/UWP 경로의 같은 앱과 `LOCAL` 이름 제약이 명시됩니다. QwenPaw가 셸 시작 시 표준 출력·오류 핸들을 전달하는 방식과 셸이 외부 서비스 파이프를 이름으로 여는 방식은 별도로 검증합니다. [이름 있는 객체 공유](https://learn.microsoft.com/en-us/windows/apps/develop/communication/sharing-named-objects) · [명명된 파이프](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea#remarks) · [QwenPaw 셸 시작 코드](https://github.com/agentscope-ai/QwenPaw/blob/v2.3.0.post1/src/qwenpaw/sandbox/windows_appcontainer_sandbox.py#L402-L472)
