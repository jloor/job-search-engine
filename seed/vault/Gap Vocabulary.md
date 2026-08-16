# Gap Vocabulary — SEED DATA

The closed list of gap names the triage model may use. **It exists so gaps can be counted.**
Free text does not aggregate: `FHIR`, `HL7 FHIR` and `SMART on FHIR` are three strings and one
gap, and a model left to write prose produces hundreds of unique labels and no counts.

⭐ **Counting is the point.** A gap seen once is an anecdote. A gap seen forty times across a
board sweep is the next thing to build.

| column | meaning |
|---|---|
| rung | the candidate's standing today: ✅ 🟡 ❌ ❓ |
| buildable | could a personal project close it? ✅ or ❌ |

⚠️ **Some gaps are not buildable and must not absorb effort.** Commercial ownership, formal
team-lead tenure and executive exposure need a job, not a repository.

<!-- BEGIN VOCAB -->
| slug | label | rung | buildable |
|---|---|---|---|
| python-authorship | Writing production Python unaided | 🟡 | ✅ |
| kubernetes-production | Production Kubernetes administration | 🟡 | ✅ |
| iac-terraform | Infrastructure as code: Terraform | ❌ | ✅ |
| observability-instrumentation | Instrumenting an application, not reading dashboards | 🟡 | ✅ |
| identity-tenant-admin | Administering an SSO tenant | ❌ | ✅ |
| fhir | FHIR / SMART on FHIR | ❓ | ✅ |
| macos-support | Supporting macOS endpoints | ❌ | ✅ |
| device-mdm | MDM enrolment and policy | ❌ | ✅ |
| account-management | Renewals, QBRs, expansion, quota | ❌ | ❌ |
| team-lead-direct-reports | Managing direct reports | ❌ | ❌ |
| executive-exposure | Executive exposure at scale | ❌ | ❌ |
| swe-years | Formal software-engineering years | ❌ | ❌ |
<!-- END VOCAB -->

📌 The markers are load-bearing. The parser reads **only** between them, because this file has
prose tables above and a parser that grabbed any table would feed the model the wrong list.
