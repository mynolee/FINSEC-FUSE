# Development workflow

The repository uses Java 21 / Spring Boot 4.1.1 (Jackson 3), PostgreSQL 16.15,
Python 3.12.15 and a TypeScript operator interface. These are the supplied
specification's reproducibility pins, not claims of latest versions.

## Gradle build

Run the checked-in Gradle 8.14.6 wrapper from the repository root with JDK 21:

```sh
./gradlew test              # Unit tests
./gradlew integrationTest   # Real PostgreSQL 16.15 and 60-case/120-run paired replay
./gradlew build             # Both suites and executable Spring Boot JAR
./gradlew bootJar           # Package only; does not run tests
```

On Windows, use `gradlew.bat`. PostgreSQL tests and the POSIX HTTP smoke runner
must run as a non-root user. The smoke runner accepts `--gradle` or `GRADLE_CMD`
when a local Gradle launcher is needed; the default is the checked-in wrapper.

The root build reads Java sources from `backend/src/` and produces
`backend/build/libs/finsec-fuse-0.1.0-SNAPSHOT.jar`. Unit and integration XML
reports are under `backend/build/test-results/test/` and
`backend/build/test-results/integrationTest/`; HTML reports are under
`backend/build/reports/tests/`. The full paired replay still writes
`evaluation/exported_runs/java-replay-full/raw-java-report.json`.

Gradle downloads are pinned by SHA-256 in `gradle/wrapper/gradle-wrapper.properties`.
The wrapper JAR is verified by `gradle/actions/setup-gradle` in CI. Upgrade the
wrapper only against the [official release checksums](https://gradle.org/release-checksums/),
and retain the wrapper scripts, JAR, properties, and build/settings files in Git.
Only generated caches and build outputs should be ignored. See the
[Spring Boot Gradle compatibility requirements](https://docs.spring.io/spring-boot/gradle-plugin/index.html)
and [Gradle's Java compatibility matrix](https://docs.gradle.org/current/userguide/compatibility.html).

## Specification provenance

The selected target is specification v2.1. The current verified baseline was
built before the full latest source was accessible; its v2.1 acceptance remains
pending. Earlier supplied documents describe v2.0 dated 2026-10-09.
The separate v2.0 development-contract bundle was recovered during review.
The registered 60-case paired suite was reconstructed before that recovery and
is intentionally retained as implementation regression coverage. It is not the
original 60-case acceptance suite. Source-to-implementation mapping and further
boundary/recovery tests are reviewed separately; original source assets stay
private. Original actor names and current internal role names differ. The raw
HMAC byte format is checked separately from full role/policy compatibility.

The current demo policy is FUSE-MVP-2: trusted evidence issuers are authorized
per evidence kind, not through a global issuer list. This policy identifier is
separate from the source specification version. Previously persisted workflows
are not silently relabeled to a new policy version.

## Verification honesty

Replay deliberately supplies unsafe proposals so Java policy gates can be
tested reproducibly. It is not evidence that a live LLM followed an attack.
Every reported metric needs a raw case result, common comparison denominator,
and exclusion reason. Environment failure is not a successful policy block.

