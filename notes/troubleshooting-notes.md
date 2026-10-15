# Lab 107 — Wazuh Sysmon Tampering Detection Troubleshooting Notes

## 1. `Get-WinEvent` Failed Because `$StartTime` Was Null

### Observed behavior

The command returned:

`A null value was encountered in the StartTime hash table key. Null values are not permitted.`

### Cause

`$StartTime` had not been defined in the current PowerShell session, or its value had been lost between commands.

### Corrected command

```powershell
$LabPath = "C:\SysmonTamperingLab\Evidence"
$StartTime = (Get-Date).AddDays(-7)

$ServiceEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = "System"
        Id        = 7036, 7040, 7045
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match "Sysmon|Wazuh" }
)

if ($ServiceEvents.Count -gt 0) {
    $ServiceEvents |
        Select-Object TimeCreated, Id, RecordId, ProviderName, Message |
        Export-Csv (Join-Path $LabPath "service-control-events.csv") `
            -NoTypeInformation

    $ServiceEvents |
        Select-Object TimeCreated, Id, ProviderName, Message |
        Format-List
} else {
    Write-Host "No matching service events found."
}
```

The corrected query searches the preceding seven days and filters returned messages for Sysmon or Wazuh. If it returns no results, the conclusion is limited to the specified IDs, time range, and message filter.

## 2. `Restart-Service Sysmon64` Failed

### Observed behavior

PowerShell reported that the `Sysmon64` service could not be stopped.

### Investigation response

The service restart was not successful. Subsequent service-management activity produced Windows System Event ID 7045 records for `Sysmon64` and `SysmonDrv`.

### Recommended handling

- Confirm that Sysmon is running before continuing.
- Preserve the command output and related System log events.
- Avoid repeating failed service-stop attempts or using forceful removal options to manufacture an event.
- Verify service and driver states after any approved Sysmon maintenance.
- Keep Windows service event IDs separate from Sysmon event IDs.

A Windows System Event ID 7045 demonstrates service installation; it is not a substitute for Sysmon Event ID 4.

## 3. Local Sysmon Event ID 4 Is Missing from Wazuh

### Observed behavior

A local Sysmon Event ID 4 was visible during an earlier query, but the corresponding search in the `wazuh-alerts-*` view returned no results.

### Step 1 — Confirm that the agent is visible

```text
agent.id:"001"
```

### Step 2 — Search for Sysmon Event ID 4

```text
agent.id:"001" AND data.win.system.providerName:"Microsoft-Windows-Sysmon" AND data.win.system.eventID:4
```

Set the time range to cover the local event's exact timestamp. If the query returns no results, inspect the complete JSON of a known Sysmon event and verify the actual field names.

### Step 3 — Understand the alert-index limitation

The Wazuh alerts index contains events that generate alerts. A locally collected event may not appear in `wazuh-alerts-*` if its Wazuh rule is configured at a non-alerting level.

Check the Wazuh manager's rule-processing behavior and whether the applicable built-in rule ignores or suppresses Event ID 4. Do not assume that the agent failed merely because no alert document exists.

If custom detection is required, use a custom rule in `local_rules.xml`, validate the rule configuration, and test with a newly generated event. Preserve default rule files.

## 4. Event ID 16 Was Generated, but Configuration Files Have Different Hashes

### Observed behavior

The local Sysmon log recorded Event ID 16 for temporary and backup configuration files.

The observed configuration hashes included:

- Temporary configuration: `7C679706FD4AA8087AF0BCD4E38166EDB1C5D1AE2F462AF6E26971B3369510D91`
- Later preserved configuration: `D429CD763B7C363A7C0FEEC5873A43906018AAA00EF95A8F9AFF26D69942DDB`
- An earlier backup: `A60AA845457406383277AFDEAD35BD90C7804572B99901239CC974841DF2528`

### Interpretation

The temporary and later preserved files differ, as expected for the test. However, the earlier backup has a third hash that has not been explained.

### Troubleshooting

Inspect the file timestamps and configuration contents:

```powershell
$LabPath = "C:\SysmonTamperingLab\Evidence"

Get-ChildItem -LiteralPath $LabPath -Filter "sysmon-config-*.xml" |
    Select-Object Name, Length, LastWriteTime

Get-FileHash -LiteralPath `
    "$LabPath\sysmon-config-backup-20261015-062307.xml", `
    "$LabPath\sysmon-config-backup-20261015-062640.xml", `
    "$LabPath\sysmon-config-backup-20261015-062706.xml" `
    -Algorithm SHA256
```

Do not assume that files with similar names represent identical versions of the configuration. Preserve each version and document the hash differences.

## 5. Event ID 16 Configuration Update and Restoration

The local log showed Event ID 16 records for the temporary configuration and the subsequent backup configuration. These records support the conclusion that Sysmon accepted configuration-state changes.

The configuration currently reported by Sysmon was `C:\Tools\Sysmon\sysmonconfig.xml`, with the hash reported in the active-configuration output.

Verify the final service state:

```powershell
Get-Service Sysmon64, WazuhSvc |
    Format-Table Name, Status, StartType -AutoSize

& "C:\Windows\Sysmon64.exe" -c
```

Compare the current configuration hash and settings with the preserved baseline. Do not make further configuration changes until any unexplained difference is understood.

## 6. Event ID 255 Was Not Found

Event ID 255 represents an internal Sysmon error. The supplied evidence does not establish that the event occurred.

Use this read-only query to check retained local records:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id      = 255
} -MaxEvents 20 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, RecordId, Message |
    Format-List
```

If no events appear, record that no matching Event ID 255 was found. Do not corrupt the configuration, disable the driver, or intentionally cause a service failure just to generate an internal error.

## 7. Windows Event ID 7045 Appeared Instead of Event ID 4

### Observed behavior

Windows System Event ID 7045 recorded the installation of:

- `Sysmon64` at `C:\Windows\Sysmon64.exe`
- `SysmonDrv` at `C:\Windows\SysmonDrv.sys`

The Wazuh alerts index contained at least one corresponding Event ID 7045 document.

### Interpretation

Event ID 7045 belongs to Windows Service Control Manager and records service installation. It does not establish that Sysmon generated Event ID 4.

### Troubleshooting

Inspect the local Sysmon Operational channel for Event ID 4, and separately inspect the Windows System channel for Event IDs 7036, 7040, and 7045. Correlate the records by timestamp and service name without treating them as interchangeable.

## 8. Event-Log Clearing Search Returned No Results

The lab searched the Windows System log for Event ID 104 and the Security log for Event ID 1102. The recorded output stated that no matching events were found during the selected window.

This means no matching events were observed in the examined results. It does not establish that logs were never cleared or that all retained logs were complete.

## 9. Evidence Hashing

The evidence manifest is stored in `evidence-hashes.csv`. It excludes the manifest itself from the hashing operation.

After modifying or adding evidence files, regenerate the manifest. If a historical record is needed, preserve the previous manifest under a separate filename rather than silently overwriting it.

## 10. Final Validation Checklist

- [ ] Verify that `Sysmon64` and `WazuhSvc` are running.
- [ ] Inspect the current Sysmon configuration and hash.
- [ ] Confirm the local Event ID 16 records for temporary and restored configurations.
- [ ] Inspect the full local Event ID 4 record.
- [ ] Verify the applicable Wazuh rule behavior for Event ID 4.
- [ ] Check the Wazuh agent and alert time range.
- [ ] Keep Windows Event ID 7045 separate from Sysmon Event ID 4.
- [ ] Document the absence of Event ID 255 without manufacturing an internal failure.
- [ ] Preserve the unexplained earlier configuration hash as an open question.
- [ ] Generate and review the SHA-256 manifest after any evidence changes.
