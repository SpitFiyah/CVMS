# Verification record

| Check | Expected result | Observed result | Status |
| --- | --- | --- | --- |
| Python and Git probes | Executables available | Python 3.14.4 and Git 2.53.0 | Pass |
| Python unit suite | Parser, validation, retry, pagination, CSV archive, checksum and exact source-locator assertions pass | Eleven tests passed locally and the [Python Actions run](https://github.com/SpitFiyah/CVMS/actions/runs/45478293887) passed at `e5c049d` | Pass |
| CPE Dictionary | Archive the search, retain exact entries and identify capped results | Two tests passed using mocked dictionary pages. Live dictionary access is unverified. | Pass for mocked responses |
| NVD snapshot replay | Replay five authentic records | Five retrieved, five accepted, zero rejected, 13 applicability criteria and 32 source-specific references using the bundled snapshot. The hosted first import applied all five records. | Pass for offline ETL |
| Terminal API | Live collector can reach NVD | Name resolution failed after retry. Independent web request returned an authentic source page. | Blocked for terminal ETL |
| SQL static inventory | Twenty report queries, five views, coherent installer paths and 11g identifier lengths | Checks passed for these structural properties | Pass for static checks |
| Docker Compose | Start local Oracle XE and make project SQL available | The hosted Oracle job started a fresh Compose database. | Pass |
| Oracle installation and tests | Oracle accepts the schema and assertions pass, including rollback | The [Oracle 11g integration run](https://github.com/SpitFiyah/CVMS/actions/runs/45478293801) passed at `e5c049d`, including schema installation, SQL assertions, first import, replay and fictional demo counts. | Pass |
| Import repeatability | Oracle applies first batch, then returns zero changes on replay and rejects an equal-time conflict | The hosted run passed the publication assertions and verified that the exact replay accepted five records and applied zero changes. | Pass |
| Remote repository and GitHub CI | Target accessible and Actions status verified | The feature branch and all three successful Actions runs were confirmed from the authenticated terminal. Default-branch integration is pending. | Pass for feature branch |
| Mermaid | Diagrams render on GitHub | Local ER source and Markdown block match and entities align with DDL. Hosted run 45434640247 failed at Chromium startup. On Ubuntu 22.04 the [Mermaid run](https://github.com/SpitFiyah/CVMS/actions/runs/45478293669) passed at `e5c049d`. | Pass |

Source of the offline snapshot is documented alongside the [sample](../data/samples/README.md).
