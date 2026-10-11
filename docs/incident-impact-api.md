# Incident potential impact amount

`GET /api/v1/incidents/{id}/impact` returns an incident's recorded impact and potential downstream exposure. The incident ID is its quarantine ID. Reading this endpoint requires an authenticated `SECURITY_OPERATOR` with access to every customer required by the existing incident-target authorization checks. Partial access does not return a partially filtered total; access is denied. The endpoint accepts no query parameters.

## Potential amount response

The `potential` object includes these additional fields:

| Field | JSON type | Meaning |
| --- | --- | --- |
| `applicationCount` | integer number | Number of distinct eligible submitted applications linked to the incident |
| `totalAmountKrw` | string | Exact sum of those applications' requested amounts, in whole Korean won |
| `currency` | string | Always `KRW` |

For example, two eligible applications requesting 1,000,000 won and 2,000,000 won produce:

```json
{
  "applicationCount": 2,
  "totalAmountKrw": "3000000",
  "currency": "KRW"
}
```

These properties are always present. An empty eligible population returns `applicationCount: 0`, `totalAmountKrw: "0"`, and `currency: "KRW"`. The amount is a canonical nonnegative base-10 integer string, with no separators, sign, decimal fraction, exponent, or leading zeros except `"0"`. Consumers must preserve this string or use exact integer/decimal arithmetic rather than converting it through a floating-point number.

The existing `roles`, `maxDownstreamDepth`, `registeredCustomerCount`, `perApplicationLimitKrw`, and `missingPolicyFields` properties remain available. Neither a policy limit nor a registered-customer count is an amount to add to this total.

## Population and calculation

1. Collect the union of the incident's historical affected workflows, currently affected workflows, and explicitly recorded policy-held workflows. Recorded source consumption and run dependency lineage determine historical/current scope. Explicit policy holds can establish scope before a run has started.
2. Inspect each linked workflow's current state at read time. Include only `KYC_PENDING`, `KYC_VALIDATED`, `REVIEW_READY`, `WAIT_APPROVAL`, `APPROVED`, `PAYMENT_RESERVED`, `BLOCKED`, and `ON_HOLD`. Exclude `PAID` and `REJECTED`, even when older runs or holds remain linked to the incident.
3. Deduplicate by the stable submitted application ID (`loan_application.id`), then count those rows and sum their immutable requested `loan_application.amount_krw` values in one SQL aggregation over the same population.

Multiple runs, retries, generations, dependency edges, audit events, or policy holds for one application do not multiply its amount. Different applications requesting equal amounts each contribute separately. The workflow schema permits one workflow per application. Registry entries without a submitted application and unrelated applications for the same customer are excluded. Membership in the same document or customer registry alone does not establish incident linkage.

PostgreSQL computes `SUM(bigint)` as an exact numeric value; the API transports its decimal text. Individual applications remain subject to the existing amount constraints. This is the sum of submitted amounts that may be affected, not a projection obtained by multiplying a lending cap, and it does not represent a realized loss or a completed payment.

## Presentation

The Korean display label is **잠재 영향 금액**. Its explanation is **영향받을 수 있는 신청 금액의 합계**. Show the currency and distinguish this amount from application count, policy limits, and actual paid amounts.

## Verification

`ImpactPotentialAmountIT` uses real PostgreSQL fixtures for eligible and excluded states, current-state changes, historical/retry/hold/event deduplication, unrelated same-customer applications, registry-only entries, empty totals, source/agent policy holds before execution, aggregates above signed 32-bit range, string serialization, and authenticated role/customer-scope checks. Some reader-focused fixtures set states directly; they verify the read contract rather than state-transition authorization. Execution results must be taken from the current build's test report; the presence of these tests is not a passing result.
