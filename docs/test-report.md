# Verification record

| Check | Expected result | Observed result | Status |
| --- | --- | --- | --- |
| Python and Git probes | Executables available | Python 3.14.4 and Git 2.53.0 | Pass |
| Python unit suite | Parser, validation, retry, pagination, CSV archive, checksum and exact source-locator assertions pass | Eleven tests passed locally and the [Python Actions run](https://github.com/SpitFiyah/CVMS/actions/runs/45436939995) passed at `8ba0287` | Pass |
| CPE Dictionary | Archive the search, retain exact entries and identify capped results | Two tests passed using mocked dictionary pages. Live dictionary access is unverified. | Pass for mocked responses |
| NVD snapshot replay | Replay five authentic records | Five retrieved, five accepted, zero rejected, 13 applicability criteria and 32 source-specific references using the bundled snapshot. Oracle import count is zero. | Pass for offline ETL |
| Terminal API | Live collector can reach NVD | Name resolution failed after retry. Independent web request returned an authentic source page. | Blocked for terminal ETL |
| SQL static inventory | Twenty report queries, five views, coherent installer paths and 11g identifier lengths | Checks passed for these structural properties | Pass for static checks |
| Docker Compose | Start local Oracle XE and make project SQL available | Compose YAML was checked locally. The sandbox could not start the Docker CLI, so a container was not started. | Pending runtime |
| Oracle installation and tests | Oracle accepts the schema and assertions pass, including rollback | Local Oracle execution was unavailable. The Oracle integration job configures the Compose database, runs SQL assertions, and verifies a CLI import, exact replay and fictional demo counts. Its hosted result is pending. | Pending |
| Import repeatability | Oracle applies first batch, then returns zero changes on replay and rejects an equal-time conflict | Publication assertions cover replay, stale revision, equal-time conflict, stable IDs, child refresh and caller rollback. No Oracle run evidence available. | Pending |
| Remote repository and GitHub CI | Target accessible and Actions status verified | `git ls-remote` failed DNS and the web lookup could not read the repository | Blocked |
| Mermaid | Diagrams render on GitHub | Local ER source and Markdown block match and entities align with DDL. Hosted run 45434640247 failed at Chromium startup. On Ubuntu 22.04 the [Mermaid run](https://github.com/SpitFiyah/CVMS/actions/runs/45436939858) passed at `8ba0287`. | Pass |

Source of the offline snapshot is documented alongside the [sample](../data/samples/README.md).
