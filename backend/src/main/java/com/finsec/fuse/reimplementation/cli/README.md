# CLI 입력 계약 v1

이 패키지는 문자열 배열을 검증된 Java 값으로 바꾸는 새 파서 라이브러리다.
운영 CLI의 `main`이나 이전 운영 구현을 복구한 것이 아니다. 아래 예시는
Java 메서드 호출에 사용할 합성 입력이며 실행 명령이 아니다.

## 마이그레이션 입력

`MigrationArguments.parse(String[])`는 첫 항목으로 `fresh-init`을 받는다.
이후 `--schema NAME`, `--credential-input-fd N`, `--expect-empty`를 각각
한 번씩 반드시 지정한다. 옵션 순서는 자유롭다.

```java
MigrationArguments parsed = MigrationArguments.parse(new String[] {
    "fresh-init", "--schema", "synthetic_schema",
    "--credential-input-fd", "7", "--expect-empty"
});
```

스키마 이름은 ASCII 패턴 `[A-Za-z_][A-Za-z0-9_]{0,62}`를 따르며 대소문자를
보존한다. FD 숫자는 `0` 또는 0으로 시작하지 않는 양의 십진 정수이고
최댓값은 `2147483647`이다. 반환값은 `schema()`, `credentialInputFd()`,
`expectEmpty()`로 읽으며 마지막 값은 `true`다.

잘못된 입력은 원문이나 원인을 포함하지 않는
`IllegalArgumentException("Invalid migration arguments")`로 거부한다.
`toString()`은 `MigrationArguments[redacted]`다.

## 토큰 관리 입력

`TokenAdminArguments.parse(String[])`는 `init`, `issue`, `list` 중 하나를
첫 항목으로 받는다. 뒤에는 옵션과 값의 쌍을 순서에 관계없이 지정한다.
모든 동작에 `--schema NAME`, `--credential-input-fd N`이 필요하다.
스키마와 FD 숫자 문법은 위와 같다. `--scope` 이외 옵션은 중복할 수 없다.

| 첫 항목 | 추가 필수 옵션 | 선택 옵션 | 반환 타입 |
| --- | --- | --- | --- |
| `init` | `--registry-id UUID` | 없음 | `Init` |
| `issue` | `--actor ID`, `--role ROLE`, `--credential-output-fd N` | 반복 가능한 `--scope CUSTOMER_ID` | `Issue` |
| `list` | `--actor ID` | 없음 | `ListTokens` |

```java
TokenAdminArguments.Command parsed = TokenAdminArguments.parse(new String[] {
    "issue", "--schema", "synthetic_schema", "--credential-input-fd", "7",
    "--actor", "synthetic-actor", "--role", "CUSTOMER",
    "--credential-output-fd", "8",
    "--scope", "customer-synthetic-a", "--scope", "customer-synthetic-b"
});
```

공통 `Command` 접근자는 `schema()`, `credentialInputFd()`다. `Init`은
`registryId()`, `Issue`는 `input()`과 `credentialOutputFd()`, `ListTokens`는
`actorId()`를 추가로 제공한다. `Issue.input()`은 `TokenRegistryInput`이다.

UUID는 표준 소문자 표현이어야 한다. actor는
`[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}`, 고객 scope는
`customer-[A-Za-z0-9][A-Za-z0-9_-]{0,118}`를 따른다. role은 정확히
`CUSTOMER`, `LOAN_REVIEWER`, `SECURITY_OPERATOR`, `DEVELOPER`, `KYC_SERVICE`,
`FUSE_WORKER` 중 하나다. V6 입력 계약에 따라 scope는 최대 256개이며
문자열 비교상 엄격한 오름차순으로 중복 없이 제공한다. 빈 scope는
`CUSTOMER`를 포함한 모든 role에서 허용된다. 파서가 정렬하거나 role별
접근 정책을 결정하지 않는다.

issue의 출력 FD는 3 이상이어야 한다. 입력·출력 FD가 같은 숫자인지는
거부 조건이 아니며 서로 안전하게 분리된 채널이라는 보장은 없다.
`revoke`, 알 수 없는 옵션, 자격증명 원문·JDBC·TTL 옵션은 받지 않는다.
환경변수 기본값이나 생략 시 운영 기본값은 없다.

잘못된 토큰 관리 입력은 원문이나 원인을 포함하지 않는
`IllegalArgumentException("INVALID_TOKEN_ADMIN_ARGUMENTS")`로 거부한다.
반환 타입의 `toString()`은 `TokenAdminArguments.Init[REDACTED]`,
`TokenAdminArguments.Issue[REDACTED]`,
`TokenAdminArguments.ListTokens[REDACTED]`다.

## 적용 범위

파싱은 DB 연결, 스키마 상태 확인, 마이그레이션, 토큰 발급 또는 권한 검사를
수행하지 않는다. `--expect-empty`는 입력 계약이며 실제 DB가 비어 있음을
증명하지 않는다. FD를 읽거나 열지 않고 소유권·권한·비밀값 전달의 안전성을
검사하지도 않는다. 숫자 `0`, `1`, `2`가 문법상 허용돼도 안전한 자격증명
입력원이라는 뜻은 아니다.

스키마 이름 검증은 SQL 조합의 안전성이나 실제 스키마 접근 권한을 보장하지
않는다. DB 처리와 실제 FD·자격증명·토큰·권한 처리는 별도 호출자의 책임이다.

## 별도 토큰 선택자 입력과 저장소 통합

`TokenRevocationArguments`는 기존 `TokenAdminArguments`와 별도의 선택자 입력 파서다. `TokenRevocationInput`과 `RegistryTokenSelection`은 자격증명 원문 대신 레지스트리와 불변 선택자 ID를 나타내는 값이다. 기존 관리 파서의 `revoke` 거부 계약은 그대로다. 새 파서가 존재해도 운영 CLI 진입점, 실제 revoke 동작, DB 연결 또는 권한 검사가 연결된 것은 아니다. 선택자 UUID 자체가 자격증명이나 권한 증거가 되지 않는다.

V9 마이그레이션 소스는 토큰의 `selection_id`를 추가한다. 기존 행의 NULL은 보존하며 기본값이나 backfill을 만들지 않는다. 새 insert에는 선택자가 필요하고, 선택자는 레지스트리 범위에서 고유하며 기존 행의 선택자 변경은 금지된다. 따라서 신규 토큰 발급 writer가 선택자를 기록하도록 준비되기 전에는 이 마이그레이션을 운영 적용하면 안 된다. 소스가 추가됐다는 사실은 SQL 실행, 기존 writer 호환성 또는 운영 전환 완료를 뜻하지 않는다.
