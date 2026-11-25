"""Builds index.html, the case-by-case Restricted Token report, from the case data below and report_head.html.

Usage: python gen_report.py  (writes index.html next to this file)
Sources: runs/2026-11-25-01.md to 04.md and findings.md.
"""
from html import escape as e
from pathlib import Path

OUT = Path(__file__).with_name("index.html")
CFG = [("q", "QwenPaw 비관리자"), ("c", "Codex unelevated"), ("c", "Codex elevated"), ("q", "QwenPaw 관리자")]

ICON = {
    "term": '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="M6 10l3 2-3 2M11 15h5"/>',
    "file": '<path d="M6 2h8l5 5v15H6z"/><path d="M14 2v5h5"/>',
    "folder": '<path d="M2 6h7l2 2h11v12H2z"/>',
    "key": '<circle cx="8" cy="12" r="4"/><path d="M12 12h10M18 12v4M21 12v3"/>',
    "proc": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 8h18"/><circle cx="6" cy="6" r=".6"/><circle cx="8.5" cy="6" r=".6"/>',
    "reg": '<rect x="3" y="3" width="8" height="8"/><rect x="13" y="3" width="8" height="8"/><rect x="3" y="13" width="8" height="8"/><rect x="13" y="13" width="8" height="8"/>',
    "env": '<rect x="2" y="5" width="20" height="14" rx="2"/><path d="M6 10h5M6 14h8M15 10h3"/>',
    "screen": '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>',
}


def icon(name):
    return f'<svg class="ico" viewBox="0 0 24 24" aria-hidden="true">{ICON[name]}</svg>'


# res: n=막힘(초록) y=뚫림(빨강) p=일부(주황) x=실행 안 함(회색)
# step status: pass=통과(주황) fail=거부(초록) skip=하지 않음(회색) info=참고(중립)
P1 = ("pass", "검사 1", "나 → 허용")
SKIP2 = ("skip", "검사 2", "읽기는 하지 않음")
CASES = [
 ("파일 쓰기", [
  dict(id="c1", title="작업 폴더 밖 문서 파일을 덮어쓴다", action="덮어쓰기",
       target=("file", "문서 폴더의 파일", "작업 폴더 밖, 사용자만 쓰기 허용"),
       acl=[("나", "수정"), ("SYSTEM", "모든 권한"), ("Administrators", "모든 권한")],
       lanes=[("n", "막힘", [("pass", "검사 1", "나 → 수정 허용"), ("fail", "검사 2", "제한 SID에 쓰기 허용 없음")]),
              ("n", "막힘", [("pass", "검사 1", "나 → 수정 허용"), ("fail", "검사 2", "제한 SID에 쓰기 허용 없음")]),
              ("n", "막힘", [("fail", "검사 1", "샌드박스 계정이 목록에 없음")]),
              ("n", "막힘", [("fail", "검사 1", "샌드박스 계정이 목록에 없음")])],
       why="현재 사용자 토큰은 검사 1을 통과하지만 쓰기라서 검사 2에서 걸립니다. 별도 계정 토큰은 검사 1에서 걸립니다.",
       ev="B2 · 네 구성 5/5"),
  dict(id="c2", title="Everyone 쓰기 허용 폴더에 파일을 심는다", action="새 파일 쓰기",
       target=("folder", "공용 폴더", "Everyone에 쓰기 허용"),
       acl=[("Everyone", "쓰기"), ("나", "수정")],
       lanes=[("y", "뚫림", [("pass", "검사 1", "Everyone → 쓰기 허용"), ("pass", "검사 2", "Everyone이 제한 SID 목록에 있음")])] * 4,
       why="네 구성 모두 제한 SID 목록에 Everyone을 넣습니다. 그래서 Everyone에 쓰기를 준 곳은 두 검사를 모두 통과합니다.",
       ev="B3 · 네 구성 5/5"),
  dict(id="c3", title="작업 폴더 안 .git 설정을 바꾼다", action="덮어쓰기·이름 변경·삭제",
       target=("folder", "작업 폴더\\.git", "시작할 때부터 있던 폴더"),
       acl=[("capability SID", "쓰기 허용(작업 폴더에서 상속)"), ("capability SID", "쓰기 거부(Codex만 추가)")],
       lanes=[("y", "뚫림", [("pass", "검사 1", "나 → 수정 허용"), ("pass", "검사 2", "작업 폴더 허용 상속, 보호 없음")]),
              ("n", "막힘", [("pass", "검사 1", "나 → 수정 허용"), ("fail", "검사 2", "capability SID 쓰기 거부 ACE")]),
              ("n", "막힘", [("pass", "검사 1", "샌드박스 그룹 → 허용"), ("fail", "검사 2", "capability SID 쓰기 거부 ACE")]),
              ("y", "뚫림", [("pass", "검사 1", "샌드박스 계정 → 허용"), ("pass", "검사 2", "작업 폴더 허용 상속, 보호 없음")])],
       why="Codex는 .git·.codex·.agents에 쓰기 거부 ACE를 달고, QwenPaw는 달지 않습니다. 시작 때 없던 .git은 네 구성 모두 새로 만들 수 있었습니다.",
       ev="B6 · 5/5"),
  dict(id="c4", title="사용자 레지스트리(HKCU\\Software)에 값을 쓴다", action="값 쓰기·하위 키 만들기",
       target=("reg", "HKCU\\Software", "자동 실행 위치(Run)도 이 아래"),
       acl=[("나", "모든 권한"), ("SYSTEM", "모든 권한"), ("Administrators", "모든 권한")],
       lanes=[("n", "막힘", [("pass", "검사 1", "나 → 모든 권한"), ("fail", "검사 2", "제한 SID에 쓰기 허용 없음")]),
              ("n", "막힘", [("pass", "검사 1", "나 → 모든 권한"), ("fail", "검사 2", "제한 SID에 쓰기 허용 없음")]),
              ("n", "막힘", [("fail", "검사 1", "사용자 하이브에 샌드박스 계정 없음")]),
              ("n", "막힘", [("fail", "검사 1", "사용자 하이브에 샌드박스 계정 없음")])],
       why="레지스트리 키도 파일과 같은 두 단계 검사를 받습니다. QwenPaw 관리자 샌드박스에서 HKCU는 샌드박스 계정 하이브를 가리키고, 그 하이브에는 쓸 수 있습니다. 사용자 하이브는 바뀌지 않습니다.",
       ev="B9·R1 · 5/5"),
 ]),
 ("파일 읽기", [
  dict(id="c5", title="~/.ssh 개인 키를 읽는다", action="읽기",
       target=("key", "~/.ssh 키 파일", "사용자만 읽기 허용"),
       acl=[("나", "모든 권한"), ("SYSTEM", "모든 권한"), ("Administrators", "모든 권한")],
       lanes=[("y", "뚫림", [("pass", "검사 1", "나 → 읽기 허용"), SKIP2]),
              ("y", "뚫림", [("pass", "검사 1", "나 → 읽기 허용"), SKIP2]),
              ("n", "막힘", [("fail", "검사 1", "샌드박스 계정·그룹이 목록에 없음")]),
              ("n", "막힘", [("fail", "검사 1", "샌드박스 계정이 목록에 없음")])],
       why="읽기는 검사 1만 받습니다. 현재 사용자 토큰이면 사용자가 읽는 것을 모두 읽습니다. Codex는 .ssh를 읽기 허용 대상에서 뺍니다.",
       ev="C3 · 5/5"),
  dict(id="c6", title="에이전트 인증 파일(~/.codex/auth.json)을 읽는다", action="읽기",
       target=("file", "~/.codex/auth.json", "에이전트 인증 정보"),
       acl=[("나", "모든 권한"), ("CodexSandboxUsers", "읽기(Codex가 추가)")],
       lanes=[("y", "뚫림", [("pass", "검사 1", "나 → 읽기 허용"), SKIP2]),
              ("y", "뚫림", [("pass", "검사 1", "나 → 읽기 허용"), SKIP2]),
              ("y", "뚫림", [("pass", "검사 1", "샌드박스 그룹 → 읽기 허용"), SKIP2]),
              ("n", "막힘", [("fail", "검사 1", "QwenPaw 계정이 목록에 없음")])],
       why="Codex elevated는 명령마다 프로필 바로 아래 항목에 샌드박스 그룹 읽기 ACE를 달고, .codex는 제외 목록에 없습니다. 그래서 별도 계정인데도 읽혔습니다.",
       ev="C3 · 5/5"),
  dict(id="c7", title="프로필 아래 AppData 파일을 읽는다", action="읽기",
       target=("folder", "~/AppData 아래 파일", "프로필 루트에서 읽기 상속"),
       acl=[("나", "모든 권한"), ("Users", "읽기(상속)"), ("Everyone", "읽기(상속)")],
       lanes=[("y", "뚫림", [("pass", "검사 1", "나 → 읽기 허용"), SKIP2]),
              ("y", "뚫림", [("pass", "검사 1", "나 → 읽기 허용"), SKIP2]),
              ("y", "뚫림", [("pass", "검사 1", "Users → 읽기 허용"), SKIP2]),
              ("y", "뚫림", [("pass", "검사 1", "Users → 읽기 허용"), SKIP2])],
       why="다른 계정이어도 Users·Everyone이 읽을 수 있는 파일은 읽습니다. 이 PC는 프로필 루트가 그 읽기를 하위로 상속합니다.",
       ev="C2·C3 · 5/5"),
  dict(id="c8", title="사용자 비밀값(DPAPI)을 복호화한다", action="복호화",
       target=("key", "DPAPI로 암호화한 값", "사용자 범위: 사용자 마스터 키로 암호화"),
       acl=[("사용자 범위", "그 사용자만 복호화"), ("컴퓨터 범위", "PC의 모든 계정이 복호화")],
       lanes=[("y", "뚫림", [("pass", "마스터 키", "같은 사용자")]),
              ("y", "뚫림", [("pass", "마스터 키", "같은 사용자")]),
              ("n", "막힘", [("fail", "마스터 키", "다른 계정이라 없음")]),
              ("n", "막힘", [("fail", "마스터 키", "다른 계정이라 없음")])],
       why="DPAPI는 DACL이 아니라 계정의 마스터 키로 보호합니다. 컴퓨터 범위로 암호화한 값은 네 구성 모두 복호화했습니다.",
       ev="C7 · 5/5"),
  dict(id="c9", title="읽기 거부로 지정한 .key 폴더를 읽는다", action="읽기·목록·쓰기·삭제",
       target=("folder", "작업 폴더\\.key", "설정에서 거부로 지정"),
       acl=[("샌드박스 계정·그룹", "거부(별도 계정 구성만 추가)"), ("capability SID", "쓰기 허용(작업 폴더에서 상속)")],
       lanes=[("y", "뚫림", [("info", "설정", "무시하고 경고 로그만"), ("pass", "검사 1", "나 → 읽기 허용")]),
              ("x", "실행 안 함", [("fail", "제품", "읽기 거부를 만들 수 없어 실행 거부")]),
              ("n", "막힘", [("fail", "검사 1", "샌드박스 그룹 거부 ACE")]),
              ("n", "막힘", [("fail", "검사 1", "샌드박스 계정 거부 ACE")])],
       why="현재 사용자 토큰으로 읽기를 막으려면 사용자 SID에 거부를 달아야 해서, 사용자 본인도 못 읽게 됩니다. 별도 계정 구성만 그 계정에 거부를 달 수 있습니다. 다른 폴더에서 옮겨 온 파일은 거부를 상속받지 않아 읽혔습니다.",
       ev="C5·C6, 작업 폴더 안 .key · 5/5"),
 ]),
 ("다른 프로그램", [
  dict(id="c10", title="explorer를 메모리 읽기·종료 권한으로 연다", action="메모리 읽기·종료 권한으로 열기",
       target=("proc", "explorer.exe", "사용자 데스크톱 프로세스"),
       acl=[("나", "모든 권한"), ("SYSTEM", "모든 권한"), ("로그온 SID", "읽기·조회·종료")],
       lanes=[("y", "뚫림", [("pass", "검사 1", "나 → 모든 권한"), ("skip", "검사 2", "읽기·종료는 쓰기 계열 아님")]),
              ("y", "뚫림", [("pass", "검사 1", "나 → 모든 권한"), ("skip", "검사 2", "읽기·종료는 쓰기 계열 아님")]),
              ("y", "뚫림", [("pass", "검사 1", "로그온 SID 일치 → 읽기·종료"), ("skip", "검사 2", "쓰기 계열 아님")]),
              ("n", "막힘", [("fail", "검사 1", "계정도 로그온 SID도 다름")])],
       why="Codex elevated는 CreateProcessWithLogonW로 실행기를 띄워 사용자의 로그온 SID를 함께 가집니다. 실측에서 로그온 SID ACE가 있는 사용자 프로세스 106개 중 96개가 열렸습니다.",
       ev="P7 · 5/5"),
  dict(id="c11", title="사용자 프로그램에 코드를 넣으려고 메모리 쓰기 권한으로 연다", action="메모리 쓰기·스레드 만들기 권한으로 열기",
       target=("proc", "사용자 프로그램", "explorer 등"),
       acl=[("나", "모든 권한"), ("SYSTEM", "모든 권한"), ("로그온 SID", "읽기·조회·종료만")],
       lanes=[("n", "막힘", [("pass", "검사 1", "나 → 모든 권한"), ("fail", "검사 2", "제한 SID에 쓰기 허용 없음")]),
              ("n", "막힘", [("pass", "검사 1", "나 → 모든 권한"), ("fail", "검사 2", "제한 SID에 쓰기 허용 없음")]),
              ("n", "막힘", [("fail", "검사 1", "로그온 SID에는 읽기·종료만")]),
              ("n", "막힘", [("fail", "검사 1", "일치하는 SID 없음")])],
       why="메모리 쓰기와 스레드 만들기는 쓰기 계열 권한이라 검사 2를 받습니다. 네 구성 모두 사용자 프로세스를 이 권한으로 하나도 열지 못했습니다.",
       ev="P1·P7 · 5/5"),
  dict(id="c12", title="옆 프로젝트에서 도는 샌드박스 프로세스를 조작한다", action="모든 권한으로 열기",
       target=("proc", "다른 작업 폴더의 샌드박스", "동시에 실행 중"),
       acl=[("로그온 SID", "모든 권한(샌드박스 기본 DACL)"), ("Everyone", "모든 권한(QwenPaw 비관리자)")],
       lanes=[("y", "뚫림", [("pass", "검사 1", "Everyone → 모든 권한"), ("pass", "검사 2", "Everyone이 목록에 있음")]),
              ("y", "뚫림", [("pass", "검사 1", "로그온 SID → 모든 권한"), ("pass", "검사 2", "로그온 SID가 목록에 있음")]),
              ("y", "뚫림", [("pass", "검사 1", "로그온 SID → 모든 권한"), ("pass", "검사 2", "로그온 SID가 목록에 있음")]),
              ("n", "막힘", [("fail", "검사 1", "프로젝트마다 계정·로그온 SID가 다름")])],
       why="샌드박스 프로세스의 기본 DACL이 로그온 SID나 Everyone에 모든 권한을 줍니다. 세 구성은 같은 로그온 SID를 쓰므로 서로의 샌드박스를 열 수 있습니다.",
       ev="P6 · 5/5"),
 ]),
 ("작업 사이와 수명", [
  dict(id="c13", title="다른 프로젝트 명령이 읽을 파일을 남겨 둔다", action="파일 쓰기",
       target=("folder", "임시 폴더, 샌드박스 계정 프로필", "작업 폴더끼리 같이 쓰는 위치"),
       acl=[("capability SID(임시 폴더용)", "쓰기 허용(Codex)"), ("고정 샌드박스 계정", "프로필 모든 권한(Codex elevated)")],
       lanes=[("n", "막힘", [("fail", "검사 2", "사용자 임시 폴더에 쓰기 허용 없음")]),
              ("y", "뚫림", [("pass", "검사 2", "임시 폴더 capability SID를 모든 작업이 공유")]),
              ("y", "뚫림", [("pass", "공유", "임시 폴더, 고정 계정 프로필")]),
              ("n", "막힘", [("fail", "계정", "프로젝트마다 다른 계정·프로필·Temp")])],
       why="Codex는 모든 작업 폴더가 같은 임시 폴더 capability SID를 쓰고, elevated는 계정 프로필까지 같이 씁니다. QwenPaw 비관리자는 임시 폴더에 아예 쓰지 못했고, QwenPaw 관리자의 프로필 분리는 간접 근거입니다.",
       ev="B8b·R3 · 5/5"),
  dict(id="c14", title="명령이 끝난 뒤에도 프로세스를 남겨 둔다", action="Job 밖으로 프로세스 띄우기",
       target=("proc", "손자 프로세스", "CREATE_BREAKAWAY_FROM_JOB"),
       acl=[("QwenPaw Job", "KILL_ON_JOB_CLOSE"), ("Codex Job", "KILL_ON_JOB_CLOSE + BREAKAWAY_OK")],
       lanes=[("n", "막힘", [("fail", "Job", "Job 밖 생성 거부, 종료 때 함께 끝남")]),
              ("y", "뚫림", [("pass", "Job", "BREAKAWAY_OK라 Job 밖에서 계속 실행")]),
              ("y", "뚫림", [("pass", "Job", "BREAKAWAY_OK라 Job 밖에서 계속 실행")]),
              ("n", "막힘", [("fail", "Job", "Job 밖 생성 거부, 종료 때 함께 끝남")])],
       why="Codex는 개발 서버처럼 셸보다 오래 도는 프로세스를 허용하려고 Job에 BREAKAWAY_OK를 둡니다. 그 프로세스는 제품이 종료돼도 계속 실행됩니다.",
       ev="G6·G2 · 5/5"),
 ]),
 ("그 밖", [
  dict(id="c15", title="환경 변수의 API 키를 읽는다", action="읽기",
       target=("env", "환경 변수", "API_KEY 같은 이름"),
       acl=[("필터", "없음")],
       lanes=[("y", "뚫림", [("pass", "환경 변수", "호스트 값을 그대로 전달")])] * 4,
       why="네 구성 모두 비밀값처럼 보이는 이름의 환경 변수를 걸러내지 않았습니다.",
       ev="E1 · 5/5"),
  dict(id="c16", title="사용자 화면에 창을 띄운다", action="창 만들기",
       target=("screen", "사용자 데스크톱", "WinSta0\\Default"),
       acl=[("QwenPaw", "사용자 데스크톱에서 실행"), ("Codex", "별도 데스크톱에서 실행")],
       lanes=[("y", "뚫림", [("pass", "데스크톱", "사용자 데스크톱에서 실행")]),
              ("n", "막힘", [("fail", "데스크톱", "별도 데스크톱")]),
              ("n", "막힘", [("fail", "데스크톱", "별도 데스크톱")]),
              ("y", "뚫림", [("pass", "데스크톱", "사용자 데스크톱, 샌드박스 계정에 접근 ACE")])],
       why="창은 그 프로세스가 붙은 데스크톱에 나타납니다. 클립보드는 측정하지 않았습니다.",
       ev="F1 · 5/5"),
 ]),
 ("폴더 규칙", [
  dict(id="c17", title="거부한 폴더 안의 특정 하위 폴더만 열어 둔다", action="하위 폴더 읽기·쓰기",
       target=("folder", "비밀 폴더\\공개", "상위: 읽기 거부, 하위: 읽기 허용 또는 쓰기 허용"),
       acl=[("상위 거부 ACE", "하위로 상속"), ("하위 명시적 허용 ACE", "있으면 상속된 거부보다 먼저 적용")],
       lanes=[("y", "설정과 다름", [("info", "설정", "상위 거부를 무시, 모두 읽힘")]),
              ("x", "실행 안 함", [("fail", "제품", "읽기 거부가 있어 실행 거부")]),
              ("p", "일부만", [("info", "쓰기 허용 하위", "명시적 허용 ACE → 열림"), ("fail", "읽기 허용 하위", "ACE 없음 → 상속된 거부")]),
              ("n", "설정대로", [("info", "하위", "mount마다 명시적 허용 ACE → 둘 다 열림")])],
       why="Windows는 폴더에 직접 단 ACE를 물려받은 ACE보다 먼저 봅니다. Codex는 다른 그룹이 이미 읽을 수 있는 경로에 읽기 ACE를 달지 않아, 읽기만 허용한 하위 폴더가 막혔습니다.",
       ev="2026-11-25-04 A · 5/5"),
  dict(id="c18", title="읽기 전용 폴더 안의 쓰기 허용 하위 폴더를 통째로 지운다", action="폴더 삭제",
       target=("folder", "읽기 전용 폴더\\작업", "상위: 읽기 전용, 하위: 쓰기 허용"),
       acl=[("하위 허용 ACE", "수정(DELETE 포함)")],
       lanes=[("y", "뚫림", [("pass", "하위 폴더", "허용 ACE의 DELETE로 삭제됨")])] * 4,
       why="상위 폴더에 쓰지 못해도, 하위 폴더 자체의 허용 ACE에 삭제 권한이 들어 있어 폴더째 지워집니다.",
       ev="2026-11-25-04 B · 5/5"),
  dict(id="c19", title="사용자가 바꿀 수 없는 폴더를 쓰기 경로로 지정한다", action="쓰기",
       target=("folder", "관리자 소유 폴더", "사용자에게 DACL 변경 권한 없음"),
       acl=[("Administrators", "소유자, 모든 권한"), ("나", "수정(DACL 변경 불가)")],
       lanes=[("n", "쓰기 안 됨", [("fail", "ACE 추가", "권한이 없어 실패, 경고만 남기고 실행")]),
              ("n", "쓰기 안 됨", [("fail", "ACE 추가", "실패, 경고 없이 실행")]),
              ("x", "실행 안 함", [("fail", "ACL 갱신", "일반 사용자 권한이라 실패 → 명령 거부")]),
              ("y", "씀", [("pass", "ACE 추가", "관리자 권한으로 추가 → 샌드박스가 씀")])],
       why="QwenPaw 관리자는 앱이 관리자 권한이라 사용자 권한 밖의 경로도 샌드박스에 열어 줍니다.",
       ev="B10 · 5/5"),
 ]),
]

RES_LABEL = {"n": "res-n", "y": "res-y", "p": "res-p", "x": "res-x"}
STEP = {"pass": ("st-pass", "통과"), "fail": ("st-fail", "거부"), "skip": ("st-skip", "안 함"), "info": ("st-info", "참고")}


def lane_html(i, lane):
    res, label, steps = lane
    tone, name = CFG[i]
    s = "".join(f'<li class="{STEP[st][0]}"><b>{e(k)}</b><span class="tag">{STEP[st][1]}</span><span>{e(v)}</span></li>'
                for st, k, v in steps)
    return (f'<div class="lane"><div class="lane-h {tone}">{e(name)}</div>'
            f'<div class="res {RES_LABEL[res]}">{e(label)}</div><ol class="chain">{s}</ol></div>')


def case_html(n, c):
    ic, tname, tsub = c["target"]
    acl = "".join(f"<tr><td>{e(w)}</td><td>{e(r)}</td></tr>" for w, r in c["acl"])
    lanes = "".join(lane_html(i, l) for i, l in enumerate(c["lanes"]))
    return f'''
<article class="case" id="{c["id"]}">
  <header class="case-h"><span class="num">사례 {n}</span><h3>{e(c["title"])}</h3></header>
  <div class="scene" role="img" aria-label="샌드박스 명령이 {e(tname)}에 {e(c["action"])}를 시도">
    <div class="actor">{icon("term")}<b>샌드박스 명령</b><span>에이전트가 실행</span></div>
    <div class="act"><span>{e(c["action"])}</span><i aria-hidden="true"></i></div>
    <div class="target"><div class="t-head">{icon(ic)}<div><b>{e(tname)}</b><span>{e(tsub)}</span></div></div>
      <div><div class="acl-h">대상의 허용 목록·보호 설정</div><table class="acl"><tbody>{acl}</tbody></table></div></div>
  </div>
  <div class="lanes">{lanes}</div>
  <p class="why"><b>왜</b> {e(c["why"])} <span class="ev">근거: {e(c["ev"])}</span></p>
</article>'''


def build():
    n = 0
    nav, body, rows = [], [], []
    for gi, (group, cases) in enumerate(CASES):
        items, cards = [], []
        for c in cases:
            n += 1
            items.append(f'<li><a href="#{c["id"]}"><span>{n}</span>{e(c["title"])}</a></li>')
            cards.append(case_html(n, c))
            cells = "".join(f'<td><span class="dot {RES_LABEL[l[0]]}">{e(l[1])}</span></td>' for l in c["lanes"])
            rows.append(f'<tr><th><a href="#{c["id"]}">{n}. {e(c["title"])}</a></th>{cells}</tr>')
        nav.append(f'<li class="g"><a href="#g{gi}">{e(group)}</a><ol>{"".join(items)}</ol></li>')
        body.append(f'<section class="group" id="g{gi}"><h2>{e(group)}</h2>{"".join(cards)}</section>')
    return nav, body, rows


nav, body, rows = build()
head = Path(__file__).with_name("report_head.html").read_text(encoding="utf-8")
html = head.replace("{{NAV}}", "".join(nav)).replace("{{BODY}}", "".join(body)).replace("{{ROWS}}", "".join(rows))
cut = html.index("</style>") + len("</style>")
DOC_HEAD = """<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
"""
html = DOC_HEAD + html[:cut] + "\n<style>body { margin: 0; }</style>\n</head>\n<body>\n" + html[cut:] + "\n</body>\n</html>\n"
OUT.write_text(html, encoding="utf-8")
print("written", OUT, len(html))
