# FINSEC FUSE 운영 콘솔

React + TypeScript + Vite 기반의 Mock 금융 AI 운영 화면입니다. 브라우저는 같은 origin의 `/api/v1`만 호출합니다. Python KYC, PostgreSQL, 직접 지급 API에는 접근하지 않습니다.

## 실행

Node 24.15 이상을 권장합니다. 현재 고정된 테스트 의존성은 Node `^22.22.2 || ^24.15.0 || >=26.0.0`을 지원합니다. 의존성의 정확한 버전은 `package-lock.json`에 고정되어 있습니다.

```sh
cd frontend
npm ci
npm run dev
```

- 화면: http://localhost:5173
- 개발 proxy: `http://localhost:8080`
- 다른 Spring 주소: `FUSE_API_PROXY_TARGET=http://127.0.0.1:8081 npm run dev`
- 개발 proxy 설정에는 키나 토큰을 넣지 않습니다.
- 루트의 bootstrap/README로 서버를 준비하고 발급된 역할별 개발 토큰을 화면에 입력합니다. `Bearer ` 접두어는 제외합니다.

로그인 입력은 개발용 토큰 연결 기능입니다. 실제 인증과 역할 검사는 Spring이 수행합니다. 토큰은 React와 API client의 메모리에만 보관하며 localStorage/sessionStorage/cookie/URL에 쓰지 않습니다. 새로고침 또는 연결 해제 시 사라집니다. 실제 권한은 화면 탭이나 요청 body로 선택할 수 없습니다.

## 제공하는 화면

- 업무 목록: 서버의 접근 가능한 범위, 상태 필터, 페이지 조회, 사용/예약/현재 유효 위험 한도
- 업무 상세: AI 제안과 서버 검증 상태 분리, 실제 문서 버전과 독립 증거, 실행과 감사 시간선
- 직원 승인: 서버 preview의 고객·금액·계좌·회차·결과·증거 지문 전체 표시, 원래 reviewSnapshotHash 그대로 전송
- 권한/장부: 실제 전달 봉투의 범위, 위험 이벤트, 승인 이력, Mock 지급 영수증
- 영향 관계: 저장된 실행/출처/결과/지급/의존 간선만 표시, 준비 실행과 실제 시작 구분
- 격리 조사: RUN/RESULT/WORKFLOW/SOURCE_VERSION/AGENT_VERSION, 실제/잠재 영향, 안전 조치 검사 후 해제
- 복구: 서버 `canResume`가 허용한 업무에서 명시적 resume. 현재 회차를 expectedGeneration으로 전송
- 비교 실험: 등록된 6개 또는 60개 fixture의 PAIRED 실행, 기본 REPLAY 1회 또는 선택형 LIVE 3회, 서버 지표/분모/제외 사유, JSON/CSV 내려받기

등록 신청 모달의 네 고객은 명세의 기본 registry 입력 예시입니다. 결과나 실시간 데이터가 아닙니다. 정상/공격·숫자·성공 상태를 프런트에서 생성하지 않습니다. 단위 테스트의 fixture는 테스트 파일에만 있습니다.

## 안전한 동작

- 변경 요청마다 UUID Idempotency-Key를 사용합니다. 중복 클릭은 방지합니다.
- 응답 손실/5xx는 결과 불명으로 표시합니다. 같은 body와 키로만 명시적으로 재확인합니다. 미확인 키는 API 세션 메모리에 유지하므로 화면을 닫았다 같은 요청을 다시 보내도 재사용합니다.
- 202 접수나 201 승인을 지급 성공으로 표시하지 않습니다. 지급 완료 표시는 서버 상태 PAID 및 실제 지급 기록을 따릅니다.
- 승인 화면 내용이 변경되면 REVIEW_CHANGED를 표시하고, 새 preview를 조회하고 다시 확인하기 전 제출을 막습니다.
- `canApprove`와 `canResume`는 서버 값입니다. 숨겨진 버튼은 보안 경계가 아니며 Spring의 재검증이 필수입니다.
- 실패한 조회를 마지막 성공 기록과 구분합니다. 뒤늦은 응답은 다른 업무 또는 다른 토큰의 화면을 덮어쓰지 못합니다.
- 격리 해제는 resume나 지급을 요청하지 않습니다. 격리·현재 회차·과거 회차·이미 지급된 금액을 구분합니다.
- 잠재 값이 null이면 계산 불가로 표시합니다. 계획된 기대값을 실제 측정으로 바꾸지 않습니다.
- 기본 모드는 REPLAY 1회입니다. LIVE는 사용자가 별도로 선택하고 외부 모델 전송·비용 발생 가능성 확인란에 동의해야 요청할 수 있으며 반복은 3회로 고정됩니다. 사례 묶음이나 모드를 바꾸면 동의를 다시 받습니다.
- LIVE는 서버 `FUSE_EXPERIMENT_LIVE_ENABLED=true`와 실제 제공자 연결이 필요합니다. 브라우저에는 제공자 키를 입력하지 않고 Spring만 호출합니다. 서버가 비활성화하면 LIVE_NOT_AVAILABLE를 표시하며 다른 모드나 제공자로 자동 전환하지 않습니다.
- LIVE는 사례·반복마다 한 번 캡처한 동일 모델 출력을 Baseline/FUSE 두 환경에 공유합니다. 캡처 실패·유도 실패는 양쪽 공통 분모에서 제외합니다. 비-RAG 변조는 별도 시험 도구 주입이며 모델이 생성한 행동이라고 표시하지 않습니다.
- 결과 화면은 서버의 modelMode/syntheticModelOutputs/liveRobustnessMeasured와 trace.modelCapture를 표시합니다. LIVE 접수만으로 실제 모델 측정 완료를 주장하지 않습니다. REPLAY는 합성 후보 출력이며 실제 모델 공격 성공률이 아닙니다.
- 전용 보안 검사 시간은 증거·위임·격리 일치 검사만의 실행 시간입니다. 모델·직원 대기와 공통 승인·장부 처리를 제외하며 전체 지연이나 두 환경의 시간 차이가 아닙니다. null인 격리 적용 시간은 미측정으로 표시합니다.
- CSV 값에는 수식 주입 방어를 적용합니다. 키·토큰·MAC 원문·leaseToken은 원시 기록 패널에서도 제거합니다.

이 코드는 실제 금융 운영, 실제 IAM, 은행 지급, 지급 취소, 독립 전자서명을 구현하지 않습니다.

## 테스트와 빌드

```sh
npm run typecheck
npm run test
npm run build
npm run format:check
```

단위/컴포넌트 테스트는 API 계약, 키 재사용, 중복 클릭, 응답 손실, ROLE 오류, preview 확인/변경, 없는 후속 실행을 그리지 않는 동작, 격리 scope/버전 직렬화, 해제와 재개 분리, 실제/잠재 구분, 쌍 단위 실험 제외, LIVE 비용 동의·모드/범위 변경 재확인·고정 3회 요청·캡처 메타데이터·호출 실패 구분, CSV 보안을 검사합니다. LIVE 테스트도 mock fetch만 사용하며 실제 외부 제공자를 호출하지 않습니다. 이 테스트의 mock fetch는 프런트 검증용입니다. PostgreSQL 통합시험이나 실제 서버 end-to-end 시험을 대신하지 않습니다.

### 실제 Chromium smoke

```sh
# 실행 가능한 Chromium 설치가 필요합니다.
CHROMIUM_PATH=/usr/bin/chromium npm run test:e2e

# 이미 실행 중인 환경을 사용하려면:
FUSE_UI_URL=http://localhost:5173 CHROMIUM_PATH=/usr/bin/chromium npm run test:e2e
```

API 응답을 가로채지 않는 smoke입니다. 초기 화면/모바일 overflow/키보드 입력/잘못된 토큰 또는 실제 backend 연결 오류/히스토리 이동을 확인합니다. 실제 정상 지급까지 확인하려면 추가적인 실제 서버 통합 검증이 필요합니다. 결과 screenshot과 trace는 `test-results/`에 생성되며 Git에서 제외됩니다.

개발 중 이 실행 환경에서는 Chromium이 페이지를 열기 전에 `process_singleton_posix socket() failed: Operation not permitted`로 종료되었습니다. 기본 실행과 허용된 escalation 재시도 모두 같은 제한이었으므로 브라우저 smoke 통과나 screenshot 확인을 주장하지 않습니다. 환경이 달라지면 위 명령으로 다시 검증해야 합니다.

## 컨테이너

Dockerfile은 Node 빌드 후 공식 unprivileged NGINX 이미지에서 정적 파일을 제공합니다. NGINX는 8080 포트로 동작하며 `/api/`를 Compose 서비스 `backend:8080`으로 전달합니다. 루트 Compose의 `5173:8080` 매핑에 맞춰져 있습니다.

기본 CSP는 자기 origin만 허용하고 외부 스크립트·폰트·iframe을 사용하지 않습니다. Docker Compose에서 실제 기동 검증이 별도로 필요합니다.

## 코드 위치

- `src/api.ts`: Spring API·오류·불명 응답의 키 보존
- `src/hooks.ts`: 조회 취소/주기 조회/변경 요청 수명
- `src/components/Workflows.tsx`: 목록·상세·승인·명시적 재개
- `src/components/Quarantine.tsx`: 격리·영향·조치 검증·해제
- `src/components/Experiments.tsx`: 실험 접수·쌍별 지표·내보내기
- `API_CONTRACT.md`: 실제 연결 경로와 필드

참고: [Vite 안내](https://vite.dev/guide/), [React 문서](https://react.dev/learn), [NGINX unprivileged 이미지](https://github.com/nginx/docker-nginx-unprivileged).
