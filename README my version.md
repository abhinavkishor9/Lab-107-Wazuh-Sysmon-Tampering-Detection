# Lab-107-Wazuh-Sysmon-Tampering-Detection
## Overview
Sysmon tampering detection focuses on identifying changes that weaken or interrupt endpoint visibility. An attacker who disables Sysmon, changes its configuration, alters its service settings, or clears relevant event logs may create gaps in the evidence available to a SOC analyst.

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

## Lab Objectives
The objective of this lab is to evaluate the visibility of Sysmon service-state changes and configuration updates across local Windows event logs and Wazuh, identify telemetry gaps, and document the limitations of the available evidence.
- **Establish the monitoring baseline:** Record the service state, startup mode, executable path, and availability of Sysmon and the Wazuh agent before beginning the investigation.
- **Inspect the active Sysmon configuration:** Identify the active configuration file, document its hashing algorithms and configuration hash, and preserve configuration copies for comparison.
- **Generate and investigate configuration-change events:** Apply a controlled temporary Sysmon configuration update, restore the original configuration, and examine Event ID 16 records to validate the observed configuration transitions.
- **Investigate Sysmon service-state telemetry:** Examine Event ID 4 locally and assess the limitations encountered when attempting to restart the Sysmon service through PowerShell.
- **Analyze Windows service-management events:** Investigate System Event IDs 7036, 7040, and 7045 to distinguish service state changes, startup-type modifications, and service installations from Sysmon-specific events.
- **Validate local-to-SIEM event visibility:** Compare locally recorded events with Wazuh search results to determine whether the available evidence supports successful collection, processing, and alert indexing.
- **Investigate missing alerts:** Examine possible time-range, field-mapping, collection, and rule-level explanations when a locally observed Sysmon event does not appear in the Wazuh alerts index.
- **Assess internal-error telemetry:** Search for Sysmon Event ID 255 and document its presence or absence without deliberately causing an internal monitoring failure.
- **Check for event-log clearing indicators:** Search Windows System Event ID 104 and Security Event ID 1102 within a defined collection window and document the limits of negative findings.
- **Preserve investigation evidence:** Export relevant event records, retain configuration versions, compare SHA-256 hashes, and regenerate the evidence manifest after artifact changes.
- **Document troubleshooting outcomes:** Record command failures, configuration-update results, service-management errors, and missing telemetry while preserving the distinction between observed behavior and possible explanations.
- **Develop a defensible conclusion:** Determine which events were confirmed locally, which reached Wazuh, which remain unverified, and whether the evidence establishes actual Sysmon tampering.
  
## Lab Scenario
A SOC analyst is validating the integrity of endpoint monitoring on a Windows 11 system. Sysmon collects security-relevant activity, while the Wazuh agent forwards selected Windows telemetry for centralized investigation. If Sysmon's configuration changes unexpectedly or its service becomes unavailable, the resulting visibility gap may affect the analyst's ability to investigate endpoint activity.
The investigation begins by checking the state of the `Sysmon64` and `WazuhSvc` services and identifying the active Sysmon configuration at `C:\Tools\Sysmon\sysmonconfig.xml`. The analyst preserves configuration copies and their SHA-256 hashes before performing controlled configuration updates. Local Sysmon Event ID 16 records capture changes involving temporary configuration files and subsequent restoration operations.
The analyst then attempts to investigate Sysmon service-state changes. A PowerShell restart attempt fails because Windows refuses to stop the service. Subsequent service-management activity produces Windows System Event ID 7045 records for `Sysmon64` and `SysmonDrv`. At least one of these service-installation events is also visible in Wazuh, providing evidence that Windows service telemetry is reaching the SIEM.
However, a Sysmon Event ID 4 previously observed in the local event log does not appear in the tested Wazuh alerts search. The analyst must determine whether the discrepancy is related to event collection, rule processing, alert generation, indexing, or the search configuration. The absence of a result must not automatically be interpreted as evidence that Sysmon failed or that an attacker interfered with monitoring.
The investigation also searches for Sysmon Event ID 255 and Windows event-log clearing indicators. The supplied results do not establish a confirmed Event ID 255 occurrence, and the log-clearing search returns no matching events for the examined collection window. These outcomes are documented as limited observations rather than proof that such activity never occurred.
### Investigation Tasks
- Establish the current state of Sysmon and Wazuh and document the active configuration.
- Correlate local Sysmon Event ID 16 records with the temporary and restored configuration files.
- Investigate the failed Sysmon service restart and distinguish it from the later Windows Event ID 7045 service-installation records.
- Compare locally observed Sysmon events with the corresponding Wazuh search results.
- Examine whether rule-level behavior or collection and indexing gaps explain the missing Event ID 4 result.
- Search for Event ID 255 and event-log clearing indicators without deliberately disrupting monitoring or manufacturing internal errors.
- Preserve event exports, configuration versions, troubleshooting output, and SHA-256 hashes.
### Expected Outcome
The analyst should produce a defensible assessment of Sysmon configuration changes, service-management activity, and event visibility across the endpoint and Wazuh. The final report must distinguish confirmed local events, events observed in Wazuh, and unresolved telemetry gaps. It should not claim malicious tampering without corroborating evidence linking the observed changes to unauthorized activity.

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

