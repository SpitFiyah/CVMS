# Verification record

| Check | Expected result | Observed result | Status |
| --- | --- | --- | --- |
| Python and Git probes | Executables available | Python 3.14.4 and Git 2.53.0 | Pass |
| Python unit suite | Parser, validation, retry, pagination, CSV archive, checksum and exact source-locator assertions pass | Eleven tests passed with `python3 -m unittest discover -s tests -v` | Pass |
| CPE Dictionary | Archive the search, retain exact entries and identify capped results | Two tests passed using mocked dictionary pages. Live dictionary access is unverified. | Pass for mocked responses |
| NVD snapshot replay | Replay five authentic records | Five retrieved, five accepted, zero rejected, 13 applicability criteria and 32 source-specific references using the bundled snapshot. Oracle import count is zero. | Pass for offline ETL |
| Terminal API | Live collector can reach NVD | Name resolution failed after retry. Independent web request returned an authentic source page. | Blocked for terminal ETL |
| SQL static inventory | Twenty report queries, five views, coherent installer paths and 11g identifier lengths | Checks passed for these structural properties | Pass for static checks |
| Oracle installation and tests | Oracle accepts the schema and assertions pass, including rollback | No Oracle client or configured connection available. DDL and tests were not executed. | Pending |
| Import repeatability | Oracle applies first batch, then returns zero changes on replay and rejects an equal-time conflict | Publication assertions cover replay, stale revision, equal-time conflict, stable IDs, child refresh and caller rollback. No Oracle run evidence available. | Pending |
| Remote repository and GitHub CI | Target accessible and Actions status verified | `git ls-remote` failed DNS and the web lookup could not read the repository | Blocked |
| Mermaid | Diagrams render on GitHub | Local ER source and Markdown block match and entities align with DDL. A local Mermaid renderer was unavailable. | Pending rendering |

Source of the offline snapshot is documented alongside the [sample](../data/samples/README.md).
