# Timeline

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

