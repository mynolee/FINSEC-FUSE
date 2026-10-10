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

The selected target is specification v2.1. The supplied v2.1 source has been
recovered and is the current reconciliation target; v2.0 documents and the
earlier development-contract bundle are historical inputs, not the current
acceptance authority. Full v2.1 acceptance remains unproven.

The registered 60-case paired suite was reconstructed before the original
contract recovery and is retained as implementation regression coverage. It
is not the original 60-case acceptance suite. Original requirement branches,
source-level oracles and revision-bound execution evidence are reconciled
separately. Neither aggregate suite counts nor a green workflow establish
all original acceptance branches. Original specifications, prompts, personal
AI configuration and private reconciliation material stay outside this public
repository. Original actor names and current internal role names differ; raw
HMAC byte-format checks do not establish full role/policy compatibility.

The current demo policy is FUSE-MVP-2: trusted evidence issuers are authorized
per evidence kind, not through a global issuer list. This policy identifier is
separate from the source specification version. Previously persisted workflows
are not silently relabeled to a new policy version.

## Verification honesty

Replay deliberately supplies unsafe proposals so Java policy gates can be
tested reproducibly. It is not evidence that a live LLM followed an attack.
Every reported metric needs a raw case result, common comparison denominator,
and exclusion reason. Environment failure is not a successful policy block.


## Revision-bound CI evidence

A historical fully successful checkpoint confirmed on 2026-10-10 UTC is
[1cb6c620e64f61fc70303f44993c6fdfcb899d6c](https://github.com/mynolee/FINSEC-FUSE/commit/1cb6c620e64f61fc70303f44993c6fdfcb899d6c),
[run 38049375800](https://github.com/mynolee/FINSEC-FUSE/actions/runs/38049375800):
all seven jobs passed, including real Compose/browser verification and
PostgreSQL/process recovery. This predates the added startup-admission job.

At later head
[9c063d0f997f3c23a5e4bfd5b10ef026217ae40d](https://github.com/mynolee/FINSEC-FUSE/commit/9c063d0f997f3c23a5e4bfd5b10ef026217ae40d),
[run 38051040813](https://github.com/mynolee/FINSEC-FUSE/actions/runs/38051040813)
passed seven of eight jobs; startup admission failed with the bounded diagnostic
MISSING_KEY / RECOVERY_CLAIM / EXECUTION_FAILED. This does not establish the
remaining startup scenarios or identify every underlying cause.

The current fully successful checkpoint is the query-fix head
[0c18b4544207c3147a16a44127de00f4d0a29aa3](https://github.com/mynolee/FINSEC-FUSE/commit/0c18b4544207c3147a16a44127de00f4d0a29aa3),
tree 3d253f6cce5464754fb7a487e9fe1a3fb863ccbb.
[Push run 38051952319](https://github.com/mynolee/FINSEC-FUSE/actions/runs/38051952319)
and [PR run 38051955035](https://github.com/mynolee/FINSEC-FUSE/actions/runs/38051955035)
both completed with eight of eight jobs successful on 2026-10-10 UTC. Push
checked out the exact head; PR checked out synthetic merge
32537f6ebe84d52ad149300e57a994de78b8380c with the same tree. All 363 source
files were bound to the frozen source manifest and each run's evidence.

Both runs passed 278 unit tests, 267 PostgreSQL integration tests, 155 frontend
tests, 11 real-browser tests, all 11 startup scenarios and five process-recovery
scenarios. The two new startup claim integration methods have named passing
execution evidence. Aggregate success still does not establish every original
requirement: source-safe identity mapping remains partial (99/278 unit and
111/267 integration), REPLAY is synthetic, and full T12 acceptance is not claimed.
The previous startup failure remains historical evidence, not the current result.
These checks predate this documentation edit and do not verify later source.
See [verification scope and historical results](VERIFICATION.md).
