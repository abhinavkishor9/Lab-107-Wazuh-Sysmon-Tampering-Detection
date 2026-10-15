# Lab 107 — Wazuh Sysmon Tampering Detection Timeline

## Timeline Overview

This timeline captures the baseline, configuration updates, service-management attempts, event collection, and Wazuh validation conducted on `DESKTOP-9MMM37V` on 15 October 2026.

Times are local endpoint times (IST, UTC+05:30), unless explicitly marked otherwise. Events are listed in chronological order using the timestamps visible in the supplied evidence. Where an exact time is unavailable, the event is marked as not captured.

## Timeline

| Time (IST) | Event | Evidence | Assessment |
|---|---|---|---|
| Not captured | Sysmon and Wazuh service baseline recorded | `service-baseline.csv` | Both services were reported as running with automatic startup. |
| Not captured | Active Sysmon configuration inspected | Configuration output | Active XML path was `C:\Tools\Sysmon\sysmonconfig.xml`; current configuration hash was `D429CD763B7C363A7C0FEEC5873A43906018AAA00EF95A8F9AFF26D69942DDB`. |
| 06:26:47 | Sysmon Event ID 16 | Record ID `1328374` | Sysmon recorded a configuration state change using the temporary configuration file. |
| 06:26:51 | Sysmon Event ID 16 | Record ID `1328378` | A configuration state change referenced the later preserved configuration hash. |
| 06:27:16 | Sysmon Event ID 16 | Record ID `1328390` | Another temporary configuration state change was recorded. |
| 06:27:19 | Sysmon Event ID 16 | Record ID `1328392` | A configuration state change referencing the preserved configuration was recorded. |
| Not captured | Sysmon service restart attempted | PowerShell output | `Restart-Service` failed because Windows would not stop the service. |
| 06:49:44 | Windows System Event ID 7045 | Record IDs `49895`, `49896` | Windows recorded installations for `Sysmon64` and `SysmonDrv`. |
| 06:49:45 | Wazuh received Event ID 7045 | Wazuh alert document; record ID `49895` | At least one service-installation event was visible in `wazuh-alerts-*`. |
| 06:53:59 | Windows System Event ID 7045 | Record IDs `49901`, `49902` | Additional service-installation records for `Sysmon64` and `SysmonDrv` were observed. |
| Not captured | Local Sysmon event collection | `events-4-16-255-local.csv` and timestamped event export | Collection commands and hash-manifest entries exist; the supplied summary does not contain every exported event row. |
| Not captured | Wazuh Event ID 4 search | Wazuh Discover | The tested query returned no results, even though Event ID 4 had been found locally during an earlier check. |
| Not captured | Event-log clearing search | `event-log-clear-events-none.txt` | No matching System Event ID 104 or Security Event ID 1102 was found during the collection window. |
| Not captured | Evidence hashing | `evidence-hashes.csv` | SHA-256 hashes were generated for the evidence files. |

## Configuration Hashes

| Configuration artifact | SHA-256 |
|---|---|
| Earlier backup: `sysmon-config-backup-20261015-062307.xml` | `A60AA845457406383277AFDEAD35BD90C7804572B99901239CC974841DF2528` |
| Later preserved configuration | `D429CD763B7C363A7C0FEEC5873A43906018AAA00EF95A8F9AFF26D69942DDB` |
| Temporary configuration | `7C679706FD4AA8087AF0BCD4E38166EDB1C5D1AE2F462AF6E26971B3369510D91` |

The difference in the earlier backup hash remains unexplained. The corresponding file should be retained and inspected rather than assumed to be identical to the later baseline.

## Event Visibility Summary

| Event | Local evidence | Wazuh evidence | Status |
|---|---|---|---|
| Sysmon 4 | Found in an earlier local query | No results from the tested Wazuh query | Visibility unresolved |
| Sysmon 16 | Multiple configuration-change records present | Wazuh visibility not established by the supplied output | Local generation confirmed |
| Sysmon 255 | Not established | Not established | No confirmed occurrence |
| Windows 7036 | No specific matching result supplied | Not established | Unconfirmed |
| Windows 7040 | No specific matching result supplied | Not established | Unconfirmed |
| Windows 7045 | Multiple service-installation records | At least one event indexed in `wazuh-alerts-*` | Confirmed |

## Final Assessment

The strongest confirmed results are the Sysmon Event ID 16 configuration-change records and the Windows System Event ID 7045 service-installation records. The Wazuh index contained at least one Event ID 7045 document.

The main unresolved issue is the missing Wazuh result for Sysmon Event ID 4. The event had been seen locally, but the tested alerts query returned no result. The next phase should examine Wazuh collection and rule processing, including whether the applicable rule generates an alert, before another service restart or configuration change is attempted.

Event ID 255 remains unconfirmed. The absence of that event is documented as a limitation rather than proof of successful or unsuccessful tampering detection.
