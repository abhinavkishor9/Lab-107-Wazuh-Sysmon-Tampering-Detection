# Lab 107 — Wazuh Sysmon Tampering Detection

## Repository Description

Investigate Sysmon service-state changes, configuration updates, and Windows service-installation events using PowerShell, Sysmon, and Wazuh. Validate telemetry collection, troubleshoot missing alerts, preserve configuration evidence, and document monitoring gaps.

## Overview

Endpoint monitoring tools are valuable only when they remain operational and their telemetry reaches the monitoring platform. Changes to Sysmon's service state or configuration can affect the evidence available to a SOC analyst, while unexpected service installation and event-log clearing can warrant further investigation.

This lab investigates Sysmon service-state and configuration-change events, Windows Service Control Manager events, and Wazuh visibility. Controlled configuration updates were applied and restored, and Windows service-installation records were observed during subsequent service-management attempts.

The investigation also highlights an important distinction: an event present in the local Windows event log is not necessarily available in the Wazuh alerts index. Event generation, agent collection, rule processing, and alert indexing must be evaluated separately.

## Lab Environment

| Component | Configuration |
|---|---|
| Endpoint | `DESKTOP-9MMM37V` |
| Operating system | Windows 11 |
| Shell | PowerShell 7 |
| Sysmon version | 15.21 |
| Sysmon executable | `C:\Windows\Sysmon64.exe` |
| Active Sysmon configuration | `C:\Tools\Sysmon\sysmonconfig.xml` |
| Evidence directory | `C:\SysmonTamperingLab\Evidence` |
| Wazuh agent ID | `001` |
| Wazuh agent IP | `192.168.203.1` |
| Wazuh agent service | `WazuhSvc` |
| Sysmon service | `Sysmon64` |
| Wazuh data view | `wazuh-alerts-*` |

## Investigation Objectives

- Establish the initial state of Sysmon and Wazuh services.
- Inspect and preserve the active Sysmon configuration.
- Generate and investigate Sysmon Event ID 16 through controlled configuration updates.
- Investigate Sysmon Event ID 4 and the limitations encountered when attempting a service restart.
- Examine Windows System Event IDs 7036, 7040, and 7045.
- Investigate why locally recorded Sysmon events may not appear in Wazuh alerts.
- Search for evidence of Windows event-log clearing using Event IDs 104 and 1102.
- Preserve configuration snapshots, exported events, and SHA-256 hashes.
- Document incomplete detections and distinguish confirmed observations from unresolved questions.

## Investigation Scenario

A SOC analyst is validating whether a Windows endpoint can report changes affecting Sysmon and whether Wazuh makes those changes visible for investigation.

The analyst first confirms that Sysmon and Wazuh are running, records the service configuration, and identifies the active Sysmon XML configuration. Temporary configuration files are created so that configuration changes can be observed without permanently replacing the existing filtering rules.

Sysmon Event ID 16 records configuration-state changes during the test. Attempts to restart Sysmon through PowerShell encounter a service-control error. Subsequent service-management activity generates Windows System Event ID 7045 records for Sysmon-related components.

The analyst then checks local event logs and searches Wazuh for relevant event IDs. Event ID 7045 is visible in the Wazuh alerts index, but the attempted search for Sysmon Event ID 4 returns no results. The analyst must therefore distinguish Windows service-installation telemetry from Sysmon's own service-state events and identify where visibility is missing.

## Event IDs Investigated

| Event ID | Source | Investigation purpose |
|---|---|---|
| 4 | Sysmon Operational | Sysmon service state change |
| 16 | Sysmon Operational | Sysmon configuration state change |
| 255 | Sysmon Operational | Internal Sysmon error |
| 7036 | Windows System | Service entered a running or stopped state |
| 7040 | Windows System | Service start type changed |
| 7045 | Windows System | Service installed |
| 104 | Windows System | Event log cleared |
| 1102 | Windows Security | Security audit log cleared |

The presence or absence of an event does not independently establish malicious intent. Event IDs must be interpreted using their actual provider, channel, message, timestamp, and surrounding evidence.

## Evidence Collected

| Artifact | Purpose |
|---|---|
| `investigation-start.txt` | Records the investigation start time |
| `service-baseline.csv` | Records Sysmon and Wazuh service properties |
| `sysmon-config-before-combined-test.txt` | Records the displayed Sysmon configuration |
| `sysmon-config-preserved-*.xml` | Preserves copies of the active configuration |
| `sysmon-config-temporary-*.xml` | Stores temporary configuration variants |
| `event-16-config-change-*.txt` | Records configuration-update command output |
| `event-16-config-restore-*.txt` | Records configuration-restoration command output |
| `events-4-16-255-local.csv` | Stores locally collected Sysmon event results |
| `events-4-16-255-*.csv` | Stores results from a test-specific event collection |
| `service-control-events.csv` | Stores filtered Windows service-control events |
| `event-log-clear-events-none.txt` | Records when no matching log-clear events were found |
| `evidence-hashes.csv` | Contains SHA-256 hashes for other evidence files |

The directory contains multiple timestamped configuration files from different test attempts. Each file should be retained and interpreted using its filename, contents, and hash rather than assuming that every copy represents a different active configuration.

## Findings

- The service baseline showed `Sysmon64` and `WazuhSvc` running with automatic startup.
- The active Sysmon configuration was reported as `C:\Tools\Sysmon\sysmonconfig.xml`.
- The current configuration output reported hashing algorithms `MD5,SHA256,IMPHASH`.
- Local Sysmon Event ID 16 records documented temporary configuration changes and subsequent configuration updates using files with different SHA-256 configuration hashes.
- An attempt to restart Sysmon using `Restart-Service` failed because Windows would not stop the service.
- Subsequent service-management activity produced Windows System Event ID 7045 records for `Sysmon64` and `SysmonDrv`.
- A Wazuh document for Event ID 7045 was observed in `wazuh-alerts-4.x-2026.10.15`.
- The attempted Wazuh query for Sysmon Event ID 4 returned no results, although Event ID 4 had been observed in the local log during an earlier check.
- No Event ID 255 was established by the supplied results.
- The event-log clearing search produced no matching results during the examined collection window.
- A SHA-256 manifest was generated for the evidence files.

## Investigation Limitations

The evidence does not yet establish why the local Sysmon Event ID 4 was absent from the Wazuh search. Potential causes include event collection, rule processing, indexing, the selected time range, or query-field matching. These possibilities require separate validation.

Windows System Event ID 7045 records a service installation. It is not equivalent to Sysmon Event ID 4 and cannot substitute for it in the investigation.

Event ID 255 represents an internal Sysmon error. The test did not establish a genuine occurrence of this event, and no claim is made that it was generated.

The evidence directory contains an earlier configuration backup with SHA-256 hash `A60AA845457406383277AFDEAD35BD90C7804572B99901239CC974841DF2528`. Later preserved configuration copies have hash `D429CD763B7C363A7C0FEEC5873A43906018AAA00EF95A8F9AFF26D69942DDB`, while temporary configurations have hash `7C679706FD4AA8087AF0BCD4E38166EDB1C5D1AE2F462AF6E26971B3369510D91`. The reason for the earlier hash difference has not been established.

## Conclusion

The lab demonstrated Sysmon configuration-change telemetry and Windows service-installation events. It also exposed a visibility gap between a locally observed Sysmon Event ID 4 and the Wazuh alerts search.

The next step is to confirm the active configuration, inspect the applicable Wazuh collection and rule-processing path, and determine whether the event is collected but intentionally not alerted on. Event ID 255 remains unconfirmed.

## Key Learning

**A monitoring event generated locally, an event collected by Wazuh, and an alert indexed by Wazuh are different stages.** A defensible detection investigation verifies each stage before concluding that a monitoring component was tampered with or that a detection failed.
