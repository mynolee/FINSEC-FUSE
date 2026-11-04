# Agent HTTP API

Agent는 KYC 후보 제안을 반환한다. 제안은 결제 실행이나 고객 권한 부여를 수행하지 않는다.

## 요청과 오류

`POST /internal/v1/kyc/evaluations`는 평가 후보를 반환한다. `POST /internal/v1/kyc/captures`는 LIVE 후보와 메시지·출력 해시를 반환한다. 두 경로 모두 유효한 단일 `X-Fuse-Service-Token` 헤더와 `application/json` 본문이 필요하다. 요청 및 응답 필드는 `schemas/`를 따른다. 오류 본문은 `{"decision":"ERROR","reasonCode":"..."}` 형식이다.

본문 수신에는 다음 제품 정책이 적용된다.

| 조건 | 응답 |
| --- | --- |
| 본문 수신 시작부터 총 10초 초과 | HTTP 408 / `REQUEST_BODY_TIMEOUT` |
| 같은 프로세스에서 이미 4개 본문을 수신 중 | 본문을 읽지 않고 즉시 HTTP 503 / `DEPENDENCY_UNAVAILABLE` |
| 설정된 본문 바이트 상한 초과 | HTTP 413 / `REQUEST_TOO_LARGE` |

10초 제한은 청크마다 갱신되지 않는다. 수신 슬롯은 정상 완료, 시간 초과, 취소, 크기 초과 및 예외 종료 시 반환된다. 상한은 프로세스별 값이므로 여러 worker 프로세스를 사용하면 전체 상한은 worker 수에 따라 증가한다. 이 정책은 HTTP 서버가 요청을 수신하기 전의 연결 단계까지 제한하지 않는다.

모델 작업의 기존 `max_parallel`, pending 상한 `2 * max_parallel`, `model_timeout_seconds`는 별도로 유지된다. 모델 시간 제한에는 모델 대기열 대기가 포함된다. 본문 시간 제한과 모델 제한을 합친 전체 요청 deadline은 제공하지 않는다.

## 준비된 LIVE 메시지

시작 시 호출자가 승인된 제품용 system 텍스트를 `PreparedProductPrompt`로 전달한다. 요청 중 임의 prompt loader 또는 message builder를 호출하지 않는다.

```python
from agent.entrypoint import create_product_app
from agent.product_messages import PreparedProductPrompt

# config: 명시적으로 준비한 ProductSettings(mode="live")
# live_factory: 준비한 비동기 adapter를 생성하는 함수
# product_system_text: 호출자가 준비한 제품용 텍스트
app = create_product_app(
    config,
    live_factory=live_factory,
    prepared_prompt=PreparedProductPrompt(system_text=product_system_text),
)
```

`PreparedProductPrompt`는 비어 있지 않은 문자열을 보관하는 불변 데이터다. 파일·환경변수 탐색이나 다운로드를 수행하지 않는다. 레거시 `prompt_loader`와 `message_builder` 등록 인자는 경계 호환 목적으로 남아 있지만 HTTP capture의 메시지 조립에는 사용되지 않는다.

`product_messages.assemble_messages`는 매 요청에 다음 새 메시지 목록을 만든다.

1. `role="system"`: 준비된 `system_text`.
2. `role="user"`: 검증된 요청 전체를 키 정렬, 공백 없는 구분자, UTF-8 문자 보존, 비유한 숫자 금지로 JSON 직렬화한 문자열.

요청 문서 텍스트는 user 데이터에 남는다. 조립 과정에서 문서 내용을 system 메시지로 승격하지 않는다. 전체 요청에는 `inputSnapshotHash`도 포함된다.

LIVE adapter의 capture 계약은 다음과 같다.

```python
async def capture(self, body, *, messages):
    # messages를 실제 모델 입력으로 사용하고 변경하지 않는다.
    # 반환값: 검증 가능한 KycProposal, 비어 있지 않은 모델 식별 문자열
    return proposal, model_name
```

메시지는 `messages=` 키워드 인자로 전달된다. 기존 `capture(body)` 구현은 이 계약에 맞게 갱신해야 한다. 기존 adapter 연결 경계는 키워드 인자를 그대로 전달한다. 준비된 prompt 데이터는 불변이지만 매 요청의 메시지 목록과 사전은 가변 데이터이므로 adapter는 이를 수정하지 않아야 한다. `promptHash`는 adapter 호출 직전 전달 메시지의 JSON 표현에서 계산된다. 반환 후 메시지 해시가 바뀌었으면 HTTP 502 / `MODEL_OUTPUT_INVALID`로 거부한다. 이 검사는 호출 전후 변경을 탐지하며, adapter 내부의 일시 변경이나 실제 transport 사용 내용을 증명하지 않는다. 실제 transport가 해당 메시지를 사용했는지는 transport 구현과 별도 연동 검증으로 확인해야 한다.

준비된 prompt 데이터가 없거나 LIVE capture를 제공하지 않으면 capture는 HTTP 503 / `LIVE_NOT_AVAILABLE`을 반환한다. offline 모드도 동일하게 LIVE capture를 제공하지 않는다. HTTP 시작 코드와 메시지 조립 자체는 네트워크 연결이나 모델 실행을 수행하지 않는다. 실제 모델 동작은 호출자가 명시적으로 제공한 adapter에 달려 있다.

HTTP 앱 생성 시 adapter의 propose·capture 의존성과 평가용 모델 식별자를 한 번 조회하여 고정한다. 이 초기 속성 조회는 provider descriptor 코드를 실행할 수 있으므로 시작 단계에서 완료해야 한다. 요청마다 adapter 속성을 다시 조회하지 않는다. propose·capture는 async 함수 또는 async `__call__`을 가진 callable이어야 한다. 동기 callback이나 조회 실패는 해당 작업을 사용할 수 없는 것으로 처리하며 callback을 시험 호출하지 않는다. capture 미준비는 `LIVE_NOT_AVAILABLE` 503, propose 미준비는 `DEPENDENCY_UNAVAILABLE` 503이다. 평가용 모델 식별자는 시작 시 검증하고, capture의 모델 식별자는 adapter 반환값으로 계속 검증한다.

`GET /ready`는 offline 모드에서 기존 설정 유효성을 확인한다. live 모드에서는 추가로 준비된 prompt 데이터와 시작 시 확인된 async capture가 필요하다. 미준비 시 HTTP 503 / `{"ready":false}`를 반환한다. readiness와 capture 준비 확인은 고정된 의존성만 사용하며 provider descriptor·capture·모델을 호출하지 않는다. 준비 상태가 실제 transport 정상 동작을 보장하지는 않는다.

## 검증 범위

`tests/test_product_http.py`에는 절대 본문 시간 제한, 네 번째 수신 슬롯까지 허용·다섯 번째 거부, 취소 후 슬롯 회수, 준비된 메시지 전달, 레거시 prompt callback 미호출, 미준비 LIVE 거부를 확인하는 합성 테스트가 있다. 테스트 작성과 실제 실행 결과는 구분해야 한다.
