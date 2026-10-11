# FINSEC FUSE

금융 멀티 AI Agent의 잘못된 판단이 후속 업무로 번지는 것을 차단하는 **모의 금융 워크플로 보안 실험실**입니다.

KYC 제안 → 독립 증거 검증 → 대출 추천 → 직원의 정확한 거래 승인 → 모의 지급 순서로 실행합니다. 실제 은행 계좌나 송금망에는 연결하지 않습니다. 모델의 출력은 권한이나 신뢰할 수 있는 증거가 아닙니다.

## 구성

- `backend/`: Java 21 · Spring Boot 4.1.1. 정책, 오케스트레이션, 승인, 지급, 격리, 복구, 감사 및 평가 API
- `agent/`: Python · FastAPI. 역할 프롬프트와 비신뢰 입력 분리, 엄격한 응답 계약, 재생/오프라인/선택적 LIVE 어댑터
- `frontend/`: React · TypeScript. 운영 현황, 승인 검토, 실행 추적, 격리·복구 및 실험 화면
- `evaluation/`: 명세에서 재구성한 공격 40건·정상 20건, 재생 및 지표 계산 도구
- `scripts/`: 로컬 모의 자격정보 생성, DB 초기화, HTTP 데모

## 로컬 실행

Docker Engine와 Compose가 필요합니다. 최초 설치에서는 DB 마이그레이션과 모의 토큰 발급을 별도 단계로 진행합니다. 저장소 루트에서 비공개 기본 설정부터 준비하세요.

```sh
./scripts/bootstrap-dev.sh
```

부트스트랩이 만든 토큰 값에는 아직 인증 권한이 없습니다. 다음 순서를 따라야 합니다.

1. 운영자가 승인한 DB 연결과 마이그레이션 절차로 `V6__durable_demo_tokens.sql`까지 적용합니다. 마이그레이션만으로 토큰이 발급되지는 않습니다.
2. [모의 토큰 초기 발급](docs/runtime-security.md#first-installation)의 독립 실행 명령으로 새 토큰을 새 비공개 파일에 발급합니다.
3. 발급 성공을 확인한 뒤 소유자가 출력 파일의 토큰을 사용할 설정으로 옮길지 검토·승인합니다. 기존 `.env`는 자동 수정되지 않습니다.
4. 설정 반영이 끝나면 `docker compose up --build`로 서비스를 시작하고 준비 상태를 확인합니다.

기존 환경에서 업그레이드할 때도 이전 토큰을 자동 가져오지 않습니다. 원래 발급·만료·폐기 이력이 없는 토큰에 새 유효기간을 부여할 수 없으므로 새 발급과 설정 교체가 필요합니다. Compose 시작·재시작은 토큰 발급이나 복구를 실행하지 않습니다. DB 연결 준비, 별도 마이그레이션, 토큰 교체는 운영자가 승인한 절차로 수행하세요.

- 운영 화면: http://localhost:5173
- 백엔드 준비 상태: http://localhost:8080/actuator/health/readiness

Python과 PostgreSQL은 기본적으로 호스트 포트를 열지 않습니다. Python 준비 상태는 컨테이너 안에서 확인합니다.

```sh
docker compose exec -T agent python -c 'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8001/ready", timeout=2).status)'
```

로컬 직접 디버깅에만 `docker compose -f compose.yaml -f compose.dev.yaml up --build`를 사용하면 Python 8001과 PostgreSQL 5432가 loopback에 열립니다. 기본 구성은 내부 네트워크 세 개로 UI·DB·Python 경계를 나누고 모든 서비스를 non-root·읽기 전용 루트로 실행하도록 설정합니다. 실제 Docker 기동·네트워크 차단 검증 여부는 [Compose 보안 설정](docs/compose-security.md)을 참고하세요.

명시적으로 발급하고 설정에 반영한 역할별 모의 토큰을 화면에 입력합니다. 고객 101~104, 승인 담당자, 보안 담당자, 개발자 토큰은 서로 다릅니다. 토큰의 역할·현재 고객 범위·발급 및 만료 시각·폐기 상태는 PostgreSQL에 유지되며 입력 JSON으로 바꿀 수 없습니다. 유효기간은 발급부터 7,200초이고 재시작으로 늘어나지 않습니다. 만료·폐기된 토큰의 기록도 유지합니다. 설정에서 토큰을 지우거나 바꾸는 것만으로 이전 토큰이 폐기되지는 않으므로 [명시적 교체·폐기 절차](docs/runtime-security.md#replacement-revocation-and-scope)를 사용하세요.

`.env`, `.secrets/`, 토큰 발급 출력 파일, 실제 API 키와 개인 데이터는 커밋하지 마세요. 부트스트랩은 기존 설정을 덮어쓰지 않습니다. DB 볼륨이 이미 존재하면 비밀번호를 파일에서 바꾸는 것만으로 DB 비밀번호가 변경되지는 않습니다. 인증 테이블·초기화 기록·설정된 토큰 기록이 없거나 DB에 접근할 수 없으면 인증 요청은 실패하고 준비 상태가 내려갑니다. 자동 재발급하지 않으므로 [복구 안내](docs/runtime-security.md#recovery-and-uncertain-results)를 확인하세요.

```sh
./scripts/run-demo.sh
```

이 스크립트는 실제 HTTP API를 통해 고객 101의 근거 없는 VERIFIED 제안을 차단하고, 고객 102의 정상 신청을 정확한 직원 승인 후 모의 지급합니다. 테스트 실패나 타임아웃을 성공으로 표시하지 않습니다.

Docker 없이도 Java 21과 Python 의존성으로 실제 HTTP 연결을 확인할 수 있습니다.

```sh
python3 -m pip install -r agent/requirements.txt
./scripts/test-fullstack.sh --experiments
```

이 독립 smoke는 임시 DB·임시 모의 토큰·빈 로컬 포트를 사용하고 종료 시 정리합니다. 기존 `.env`와 업무 DB는 사용하지 않습니다. PostgreSQL의 제한 때문에 root 계정으로는 실행하지 않습니다.

## 핵심 안전 장치

- 모델이 추천해도 Spring이 고객 소유권·증거 상태·발급자·유효기간·해시를 독립 확인
- HMAC 위임과 실제 부모 경로 검증, 세대·입력·결과에 묶인 권한
- 실행 게이트 → 워크플로 순서의 DB 잠금, 네트워크 호출은 트랜잭션 밖
- KYC 10 + Loan 25 + 지급 50의 위험 비용, 예약과 소비의 중복 합산 방지
- 거래 내용·증거·세대에 묶인 직원 승인, 지급 예약과 커밋 시 재검증
- 멱등 요청, 지급 유일 제약, 동시 실행에서도 중복 모의 지급 방지
- 실행·결과·워크플로·출처 버전·에이전트 버전별 격리, 안전한 자료로 명시적 복구
- 임대 만료와 늦은 모델 응답의 처리, 사용 비용을 되돌리지 않는 세대 전환

## 테스트

```sh
./gradlew build
python3 -m pip install -r agent/requirements-dev.txt
python3 -m pytest -q agent/tests evaluation/tests
cd frontend && npm ci && npm test && npm run build
```

백엔드 통합 테스트는 임시 PostgreSQL 16.15를 실제로 실행합니다. H2나 메모리 DB로 잠금·유일 제약을 대체하지 않습니다. 임시 DB를 초기화하는 테스트는 외부 DB 주소를 사용하지 않도록 가드가 있습니다.

## 평가 해석

재생 실험은 같은 기록된 모델 제안을 BASELINE/FUSE 양쪽에 공급하여 정책 차이를 비교합니다. 실제 LLM이 공격에 속았다는 증거는 아닙니다. 환경 오류, 미지원 사례, 공격 유도 실패는 양쪽에서 공통 제외해야 하며 보안 차단 성공으로 세지 않습니다.

실험 DB는 일반 데모 DB와 분리합니다. 각 비교 환경은 독립 스키마를 사용합니다. LIVE에는 별도 모델 설정과 자격정보가 필요하며, 기본 실행에서는 외부 유료 모델 호출을 하지 않습니다.

## 선택적 LIVE 비교

기본 설정은 REPLAY입니다. 실제 제공자를 사용하려면 모델·키를 직접 지정하고 외부 전송·과금에 별도로 동의해야 합니다. 직접 프로세스를 실행할 때는 FUSE_KYC_MODE=live와 FUSE_EXPERIMENT_LIVE_ENABLED=true가 필요합니다. Compose 기본 파일은 REPLAY로 고정되어 있어 `.env`의 모드·키만 바꾸어 LIVE가 켜지지 않습니다. Compose LIVE는 운영자가 목적지 제한을 실제 검증한 별도 네트워크를 FUSE_LIVE_EGRESS_NETWORK로 지정하고 `compose.live.yaml`을 명시적으로 추가해야 합니다. 네트워크 이름을 지정하는 것만으로 방화벽이나 목적지 제한이 만들어지지 않습니다. [LIVE egress 선행 조건](docs/compose-security.md#explicit-live-egress-prerequisite)을 먼저 확인하세요. 키를 채팅이나 Git에 올리지 마세요. 화면에서도 외부 제공자 전송·과금 가능성에 동의한 뒤 LIVE를 선택해야 합니다.

서비스·공격 프롬프트 본문은 공개 저장소에 포함하지 않습니다. LIVE에는 비공개 외부 파일 경로인 `FUSE_KYC_PROMPT_PATH`, `FUSE_PRIVATE_DOCUMENTS_PATH`도 필요합니다. REPLAY는 이 파일 없이 동작합니다. 파일 형식과 읽기 전용 컨테이너 연결은 [비공개 실행 설정](docs/private-runtime-assets.md)을 참고하세요.

LIVE는 사례별 3회, 매 회차 모델을 한 번 호출한 동일 출력을 두 환경에 재사용합니다. 모델 오류·실험 사전조건 불충족은 양쪽 공통 제외이며 방어 성공으로 세지 않습니다. 모델·프롬프트·출력 지문은 원시 결과에 보존합니다. 실제 제공자 호출을 했다는 검증 결과는 없으며, 연동 로직 시험은 가짜 제공자를 사용했습니다.

## 개발·검증 상태

모의 시제품이며 로컬 결과와 실제 GitHub CI 결과를 구분합니다. 2026-10-11 01:48 KST에 확인한 고정 검증 체크포인트는 [6162b060](https://github.com/mynolee/FINSEC-FUSE/commit/6162b060361261872a040414d03d1d6a36a9c8fd)입니다. [push CI](https://github.com/mynolee/FINSEC-FUSE/actions/runs/38068597161)와 [PR CI](https://github.com/mynolee/FINSEC-FUSE/actions/runs/38068601047)가 각각 8개 작업 모두 성공했습니다. 해당 소스 트리에서 프론트엔드 258개·Java 단위 278개·PostgreSQL 통합 285개와 실제 Compose·시작 전제조건·프로세스 장애 복구·재구성 REPLAY를 검증했습니다. 기존 Chromium 브라우저 검사 11개도 통과했지만, 새 변경 요청 응답(receipt) 검증·불확실 응답 복구 시나리오의 실제 브라우저 실행이나 로컬 네이티브 브라우저 검증은 별도로 남아 있습니다. 이 결과는 이 문서 변경을 포함할 이후 커밋이나 전체 원본 인수조건을 검증하지 않습니다. 이전 성공·실패 이력과 정확한 범위는 [검증 문서](docs/VERIFICATION.md)에 기록합니다.

브랜치·PR·커밋 운영 방식과 명세 출처는 [개발 문서](docs/DEVELOPMENT.md)를 참고하세요. 초기 평가 픽스처는 재구성한 회귀 사례입니다. 현재 목표는 v2.1이며, 확보한 원본 자료와 구현·실행 증거를 대조하고 있습니다. 이전 v2.0 자료는 이력으로 구분합니다. 기존 재구성 60개 시험 통과를 원본 60개 인수 사례 또는 전체 인수 분기의 통과로 간주하지 않습니다.
