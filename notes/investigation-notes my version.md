# Investigation notes

## 1. Baseline and System State

The service baseline recorded the following:

| Service | State | Startup mode | Executable |
|---|---|---|---|
| `Sysmon64` | Running | Automatic | `C:\WINDOWS\Sysmon64.exe` |
| `WazuhSvc` | Running | Automatic | `C:\Program Files (x86)\ossec-agent\wazuh-agent.exe` |

The Sysmon Operational channel was enabled. One check reported 56,782 retained records and a last-write timestamp of `2026-10-15 06:02:23`. This is a point-in-time observation, not a current record count for the entire investigation.

The active configuration output reported:

- Sysmon version: `15.21`
- Service name: `Sysmon64`
- Driver name: `SysmonDrv`
- Configuration file: `C:\Tools\Sysmon\sysmonconfig.xml`
- Configuration hash: `SHA256=D429CD763B7C363A7C0FEEC5873A43906018AAA00EF95A8F9AFF26D69942DDB`
- Hash algorithms: `MD5,SHA256,IMPHASH`

## 2. Sysmon Event ID 16 — Configuration Changes

The local Sysmon Operational log contained Event ID 16 records associated with temporary configuration updates and configuration restoration.

| Local time (IST) | Record ID | Configuration file | Configuration hash |
|---|---:|---|---|
| 2026-10-15 06:26:47 | 1328374 | `sysmon-config-temporary-20261015-062640.xml` | `7C679706FD4AA8087AF0BCD4E38166EDB1C5D1AE2F462AF6E26971B3369510D91` |
| 2026-10-15 06:26:51 | 1328378 | `sysmon-config-backup-20261015-062640.xml` | `D429CD763B7C363A7C0FEEC5873A43906018AAA00EF95A8F9AFF26D69942DDB` |
| 2026-10-15 06:27:16 | 1328390 | `sysmon-config-temporary-20261015-062706.xml` | `7C679706FD4AA8087AF0BCD4E38166EDB1C5D1AE2F462AF6E26971B3369510D91` |
| 2026-10-15 06:27:19 | 1328392 | `sysmon-config-backup-20261015-062706.xml` | `D429CD763B7C363A7C0FEEC5873A43906018AAA00EF95A8F9AFF26D69942DDB` |

The records show that Sysmon accepted configuration changes referencing the temporary and backup files.

The matching hashes for the later preserved configuration files are consistent with the configuration hash reported by the active configuration output. This supports the interpretation that the configuration update was followed by reapplication of a configuration with the same hash.

An earlier backup, `sysmon-config-backup-20261015-062307.xml`, has a different SHA-256 hash: `A60AA845457406383277AFDEAD35BD90C7804572B99901239CC974841DF2528`. The reason for this difference has not been determined. The earlier file should not be assumed to be equivalent to the later preserved copies.

## 3. Sysmon Event ID 4 — Service State Change

The local investigation previously returned a Sysmon Event ID 4 record within the queried time window. However, the subsequent service restart attempt failed with an error stating that Windows could not stop the `Sysmon64` service.

A later attempt to use Sysmon's uninstall/install approach produced Windows System Event ID 7045 records for `Sysmon64` and `SysmonDrv`. Those records demonstrate service installation activity but do not establish that a new Sysmon Event ID 4 was created by the test.

The Wazuh Discover query for Event ID 4 returned no results, even though a local Event ID 4 had been observed earlier.

The following questions remain unresolved:

- Was the locally observed Event ID 4 collected by the Wazuh agent?
- Was it processed by a Wazuh rule at a non-alerting level?
- Was it absent from `wazuh-alerts-*` because no alert was generated?
- Was the Wazuh search window sufficient to include the local event?
- Does the indexed event contain the expected provider and event-ID fields?

The absence of an event in `wazuh-alerts-*` does not alone prove that the agent failed to collect it.

## 4. Windows System Event ID 7045 — Service Installation

Windows System Event ID 7045 records were observed during the subsequent Sysmon service-management attempts.

| Local time (IST) | Record ID | Service name | Service file |
|---|---:|---|---|
| 2026-10-15 06:49:44 | 49895 | `Sysmon64` | `C:\Windows\Sysmon64.exe` |
| 2026-10-15 06:49:44 | 49896 | `SysmonDrv` | `C:\Windows\SysmonDrv.sys` |
| 2026-10-15 06:53:59 | 49901 | `Sysmon64` | `C:\Windows\Sysmon64.exe` |
| 2026-10-15 06:53:59 | 49902 | `SysmonDrv` | `C:\Windows\SysmonDrv.sys` |

A Wazuh document was observed for Event ID 7045 with these attributes:

| Field | Value |
|---|---|
| Index | `wazuh-alerts-4.x-2026.10.15` |
| Agent ID | `001` |
| Agent name | `DESKTOP-9MMM37V` |
| Event ID | `7045` |
| Record ID | `49895` |
| Service name | `Sysmon64` |
| Image path | `C:\Windows\Sysmon64.exe` |
| Account | `LocalSystem` |

This confirms that at least one Windows service-installation event reached the Wazuh alerts index. It does not confirm that Sysmon Event ID 4 was collected or alerted.

## 5. Event ID 255 — Internal Sysmon Error

The supplied results do not establish an occurrence of Sysmon Event ID 255.

This event represents an internal Sysmon error and should not be treated as a routine service-state event. The lab did not deliberately corrupt Sysmon or its configuration to manufacture an internal error.

The appropriate conclusion is that Event ID 255 was not confirmed in the supplied evidence.

## 6. Event-Log Clearing Search

The investigation searched for:

- System Event ID 104.
- Security Event ID 1102.

The command produced `event-log-clear-events-none.txt`, indicating that no matching events were found in the selected collection window.

This finding is limited to the logs, event IDs, and time range examined. It does not prove that event logs were never cleared.

## 7. Troubleshooting Encountered

### Undefined `$StartTime`

The initial `Get-WinEvent` query failed because `$StartTime` was null. The query was corrected by explicitly setting:

```powershell
$StartTime = (Get-Date).AddDays(-7)
```

### Sysmon service restart failure

`Restart-Service -Name Sysmon64 -Force` failed because Windows would not stop the service. Subsequent service-management activity generated Event ID 7045 records, but no new Sysmon Event ID 4 was established by that attempt.

### Wazuh Event ID 4 query returned no results

The Discover query used the `wazuh-alerts-*` data view. A local Sysmon event did not automatically become a result in that index. The collection, rule-processing, indexing, and time-range stages still require validation.

### Configuration file path

A test command initially used the placeholder path `C:\Path\To\Sysmon64.exe` and failed. The command was corrected to use `C:\Windows\Sysmon64.exe`.

## 8. Evidence Integrity

The SHA-256 manifest was generated in `evidence-hashes.csv`. It includes configuration backups, temporary configuration files, command output, service baselines, event exports, and other evidence artifacts.

The manifest records hashes for the files at the time of collection; it does not establish by itself that the artifacts are complete or authentic. Any evidence file changed after hashing should be rehashed, and prior manifests should be retained separately if historical integrity tracking is required.

## 9. Final Assessment

### Confirmed

- Sysmon and Wazuh were running during the baseline check.
- Sysmon configuration-change events were recorded locally.
- The temporary and restored configuration files had distinct, documented hashes.
- Windows System Event ID 7045 records were created for `Sysmon64` and `SysmonDrv`.
- At least one Event ID 7045 record reached Wazuh.
- A local Event ID 4 had been observed in an earlier query.

### Not established

- Successful Wazuh alert visibility for the tested Sysmon Event ID 4.
- A new Event ID 4 caused by the later service-management attempt.
- An occurrence of Event ID 255.
- A complete explanation for the different hash of the earlier configuration backup.
- Evidence that an attacker deliberately tampered with Sysmon.

### Conclusion

The lab successfully demonstrated configuration-change telemetry and Windows service-installation events. The principal unresolved issue is why a locally observed Sysmon Event ID 4 did not appear in the Wazuh alerts query. Further diagnosis should examine event collection and rule processing before any additional service changes are attempted.
