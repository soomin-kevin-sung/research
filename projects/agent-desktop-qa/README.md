# agent-desktop QA

## 조사 질문

- 기존 E2E가 검증하는 에디터 저장 충돌을 Windows 사용자 화면에서 재현하고, 실패 시 원인을 좁힐 증거를 남길 수 있는가?

## 확인한 환경

연구 브랜치에는 앱이나 테스트 러너가 없다. 인접한 대상 앱 저장소 체크아웃의 한 커밋을 QA 대상 후보로 선정했다.

- `npm run test:ui`는 프런트엔드 빌드 후 Playwright를 실행한다. `playwright.config.mjs`는 headless 브라우저, 4개 워커, 기본 포트 4179를 사용하고 `scripts/preview-desktop.mjs`가 제공하는 Tauri 브리지 fixture에 연결한다. `test/ui/editor-save.spec.mjs`에는 외부 변경 후 저장 및 닫기를 시도하면 경고가 뜨고 초안이 보존되는 사례가 있다.
- `npm run test:files`는 `test/native/files.mjs`를 실행한다. 격리된 데이터 디렉터리로 실제 Windows EXE를 띄운 뒤 Playwright CDP로 WebView2에 접속하여 Rust 파일 I/O와 디스크 바이트까지 검사한다. 대용량 텍스트의 저장 충돌도 포함한다. `npm run test:native`는 별도의 수명주기 및 복구 검사다.
- Vercel Labs의 `agent-desktop`을 후보 도구로 잡았다. Windows UI Automation을 통해 접근성 트리를 JSON으로 읽고 요소 참조로 데스크톱 앱을 조작한다. PoC에서는 CLI로 UI를 조작하고 다시 관찰하며, 판정은 실행 스크립트가 UI와 디스크를 확인해 내린다. [공식 README](https://github.com/vercel-labs/agent-desktop)

## 범위와 완료 기준

- [PoC 실행 절차와 판정 기준](protocol.md)에 Windows 단일 시나리오를 정의했다.
- [x] 동일 소스 커밋에서 브라우저 및 네이티브 기준 테스트 결과를 확보했다.
- [ ] 독립된 세 번의 실행에서 경고, 초안, 외부 파일 보존 여부를 확인했다.
- [x] 실패 또는 판정 불가 시 단계별 증거를 실행 기록에서 찾을 수 있다.

[첫 실행](runs/2026-11-23-01.md)에서 브라우저 5개 테스트와 네이티브 파일 E2E가 통과했다. agent-desktop으로 실제 앱 창의 접근성 트리와 스크린샷을 수집했으나, 전경 창 확보 오류로 첫 키가 전달되지 않아 저장 충돌 경로는 미실측이다.

[Windows 커서 오버레이 검증 보고서](windows-cursor-overlay.html)에 npm 배포본의 렌더링 실패, 실행 파일 이름을 바꾼 우회 검증, 계산기 시연 결과를 기록했다.
