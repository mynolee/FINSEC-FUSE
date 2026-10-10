# Dependency advisory review — 2026-10-09

Observed resolved inventory: 122 unique Java coordinates under Spring Boot 4.1.1.
OSV returned 10 package/advisory matches. No exploitability exemption was applied.
This is a finding record, not evidence that remediation or retests have passed.

| Component observed | Advisory | Severity | Relevant affected range | First fixed patch |
|---|---|---|---|---|
| org.apache.tomcat.embed:tomcat-embed-core:11.0.24 | [GHSA-9xv2-5v5q-p794](https://github.com/advisories/GHSA-9xv2-5v5q-p794) | CRITICAL | >= 11.0.0-M1, < 11.0.25 | 11.0.25 |
| org.apache.tomcat.embed:tomcat-embed-core:11.0.24 | [GHSA-gcx9-497g-6cp6](https://github.com/advisories/GHSA-gcx9-497g-6cp6) | CRITICAL | >= 11.0.0-M1, < 11.0.25 | 11.0.25 |
| org.apache.tomcat.embed:tomcat-embed-core:11.0.24 | [GHSA-h3x4-894j-xpx5](https://github.com/advisories/GHSA-h3x4-894j-xpx5) | CRITICAL | >= 11.0.0-M1, < 11.0.25 | 11.0.25 |
| tools.jackson.core:jackson-core:3.1.5 | [GHSA-7hhh-6rmp-j9qf](https://github.com/advisories/GHSA-7hhh-6rmp-j9qf) | HIGH | >= 3.0.0, < 3.1.7 | 3.1.7 |
| tools.jackson.core:jackson-core:3.1.5 | [GHSA-p6pp-m3f8-5c89](https://github.com/advisories/GHSA-p6pp-m3f8-5c89) | HIGH | >= 3.0.0, < 3.1.7 | 3.1.7 |
| tools.jackson.core:jackson-databind:3.1.5 | [GHSA-cxp5-3px4-pw24](https://github.com/advisories/GHSA-cxp5-3px4-pw24) | HIGH | >= 3.0.0, < 3.1.7 | 3.1.7 |
| tools.jackson.core:jackson-databind:3.1.5 | [GHSA-gx83-3vf8-gh7j](https://github.com/advisories/GHSA-gx83-3vf8-gh7j) | MODERATE | >= 3.0.0, < 3.1.6 | 3.1.6 |
| tools.jackson.core:jackson-databind:3.1.5 | [GHSA-q4xh-88c3-wmh7](https://github.com/advisories/GHSA-q4xh-88c3-wmh7) | HIGH | >= 3.0.0, < 3.1.6 | 3.1.6 |
| tools.jackson.core:jackson-databind:3.1.5 | [GHSA-wjgm-6hv5-3cvf](https://github.com/advisories/GHSA-wjgm-6hv5-3cvf) | MODERATE | >= 3.0.0, < 3.1.6 | 3.1.6 |
| tools.jackson.core:jackson-databind:3.1.5 | [GHSA-wv8q-qhhj-9h54](https://github.com/advisories/GHSA-wv8q-qhhj-9h54) | HIGH | >= 3.0.0, < 3.1.7 | 3.1.7 |

## Applied coordinated remediation

- Retain the Spring Boot 4.1.1 family. Official Maven Central metadata available during this review listed only 4.1.0 and 4.1.1 stable in this minor line; no newer same-minor BOM was verified.
- Align Jackson 3 modules using tools.jackson:jackson-bom:3.1.7. All seven matched Jackson advisories have fixes on the 3.1 line.
- Align Tomcat embed core/el/websocket on 11.0.26. All three matched Critical advisories were fixed in 11.0.25; Apache documents an additional WebSocket fix in 11.0.26.
- Regenerate the resolved inventory and rerun unit, real PostgreSQL, HTTP/security and SCA checks after the change. Declared version overrides alone are not evidence of resolution or compatibility.

## Python test dependency

pytest 8.3.5 was flagged by PYSEC-2026-1845 / CVE-2025-71176. The [reviewed advisory](https://github.com/advisories/GHSA-6w46-j5rx-g56g) lists versions below 9.0.3 as affected, with 9.0.3 fixed. The dev dependency was changed to 9.0.3; rerun evidence is maintained separately.

## Primary release and registry sources

- https://tomcat.apache.org/security-11.html
- https://repo.maven.apache.org/maven2/org/springframework/boot/spring-boot-dependencies/maven-metadata.xml
- https://repo.maven.apache.org/maven2/org/apache/tomcat/embed/tomcat-embed-core/maven-metadata.xml
- https://repo.maven.apache.org/maven2/tools/jackson/jackson-bom/maven-metadata.xml
- https://github.com/FasterXML/jackson-core/security/advisories
- https://github.com/FasterXML/jackson-databind/security/advisories

Versions are observed pins and fixes for these advisory records. This does not claim all dependencies or the application are vulnerability-free.

## Verification after remediation

Resolved inventory confirmed Jackson core/databind 3.1.7 and Tomcat core/el/websocket 11.0.26. On 2026-10-09 UTC, local SCA reported zero known vulnerabilities among 122 Java, 20 Python and 153 npm resolved packages. Java 260 unit and 152 PostgreSQL integration tests, Python 219 tests, frontend 78 tests, real HTTP replay and five process/DB recovery scenarios passed. These checks do not cover container OS packages, real browser enforcement or production deployment.
