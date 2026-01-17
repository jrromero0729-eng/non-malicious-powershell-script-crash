# Unhandled PowerShell Script Crash (Azure Guest Agent Degradation)

<img width="1400" alt="Unhandled PowerShell Script Crash Diagram" src="https://github.com/user-attachments/assets/e0370a48-91e1-4853-b521-bf0e8dd7f72c" />

---

## Report Information

**Analyst:** Albert Romero  
**Date Completed:** January 06, 2026  
**Environment Investigated:** LOG(N) Pacific Cyber Range  
**Host Investigated:** `windows-target-1`  
**User Context:** SYSTEM — Scheduled PowerShell execution and automated Azure recovery  
**Tools & Data Sources:** Microsoft Azure, Microsoft Defender for Endpoint, Azure Log Analytics, KQL (Kusto Query Language)  
**Scope:** SYSTEM-level script execution analysis, crash correlation, Azure Guest Agent and extension behavior, recovery telemetry validation, and control-plane remediation behavior

---

## Table of Contents

- [Report Information](#report-information)
- [Executive Summary](#executive-summary)
- [Investigation](#investigation)
  - [_pwncrypt.ps1_ Stops Unexpectedly](#pwncryptps1-stops-unexpectedly)
  - [Windows Error Reporting Detects Crash](#windows-error-reporting-detects-crash)
  - [Azure MMA Heartbeat Service Installed](#azure-mma-heartbeat-service-installed)
  - [Guest Configuration Compliance Checks (_gc_worker.exe_)](#guest-configuration-compliance-checks-gc_workerexe)
  - [Restarting the VM Did Not Restore Functionality](#restarting-the-vm-did-not-restore-functionality)
  - [Why Redeploying Worked](#why-redeploying-worked)
- [Analyst Assessment](#analyst-assessment)
- [Recommended Actions](#recommended-actions)
- [Conclusion](#conclusion)

---

## Executive Summary

The virtual machine `windows-target-1`, a purpose-built attack simulation and security telemetry generation host within the LOG(N) Pacific Cyber Range, was identified as offline and non-functional for approximately six weeks following a SYSTEM-level unhandled PowerShell exception. The failure resulted in a critical crash recorded by WerFault.exe, after which scheduled attack simulation scripts stopped executing and expected security telemetry was no longer generated.

Because this system was designed to operate autonomously, the outage initially appeared consistent with either an availability failure or a potential compromise. However, detailed investigation revealed no evidence of malicious persistence or attacker activity. Instead, telemetry showed a cascading failure originating from a SYSTEM-level script crash that disrupted the Azure Guest Agent trust relationship, leaving the virtual machine in a degraded but non-compromised state.

Azure initiated multiple automated recovery attempts, including:
- Guest configuration compliance checks  
- Extension repair and reinstallation attempts  
- Health and heartbeat service recovery  

Despite these actions, the VM never fully re-established control-plane trust. Credential resets, script execution, and automated attack simulation continued to fail until the VM was redeployed, which restored full functionality by rebuilding the Azure management-plane relationship rather than simply rebooting the operating system.

This investigation demonstrates how non-malicious automation failures at the SYSTEM level can closely resemble compromise conditions and highlights the importance of understanding Azure guest agent behavior, telemetry buffering, and recovery mechanisms when performing cloud-based incident analysis.

### Notable Events

- `windows-target-1` offline for approximately 42 days  
- Multiple WerFault.exe events observed at time of failure  
- Automated attack simulation halted  
- ARM-based credential reset attempts failed post-reboot  

---

## Investigation

### _pwncrypt.ps1_ Stops Unexpectedly

Multiple PowerShell-based attack simulation scripts were configured to run on `windows-target-1` under the SYSTEM context. These scripts were designed to execute on a schedule and generate telemetry for detection validation and security testing.

The scheduled script **pwncrypt.ps1** terminated unexpectedly at:

`2025-11-24T04:12:59.7367393Z`

After this timestamp, no additional scheduled attack simulation scripts executed, indicating a failure that impacted all subsequent automation on the host.

```kql
DeviceProcessEvents
| where DeviceName == "windows-target-1"
| where ProcessCommandLine contains "pwncrypt"
| where TimeGenerated > ago(50d)
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

<img width="1115" height="262" alt="pwncrypt script execution timeline" src="https://github.com/user-attachments/assets/eb27289c-4dbc-427c-8f65-6446548b8901" /> ```

---

### Windows Error Reporting Detects Crash

Telemetry from Microsoft Defender for Endpoint shows that **WerFault.exe** activity directly correlates with the unexpected termination of `pwncrypt.ps1`. The crash was recorded within seconds of the script’s final execution, indicating an unhandled exception rather than a controlled shutdown.

Process-level telemetry confirms:
- The final execution of `pwncrypt.ps1` occurred at `2025-11-24T04:12:59.7367393Z`
- A WerFault.exe process was launched immediately after, associated with ProcessId `6500`
- Some PowerShell command events appear after the WerFault entry due to buffered logging behavior
- Process start and stop events confirm the script executed **before** the crash, not after

This sequencing rules out delayed or post-crash execution and supports the conclusion that the script failure directly triggered the system-level exception.

```kql
let crash = todatetime('2025-11-24T04:12:50');
DeviceProcessEvents
| where DeviceName == "windows-target-1"
| where TimeGenerated between (crash - 10m .. crash + 10m)
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated desc
```

<img width="1136" height="296" alt="WerFault crash correlation" src="https://github.com/user-attachments/assets/be751198-5396-4e43-bbf5-1ad8cdd074a6" /> ```

---

### Azure MMA Heartbeat Service Installed

Following the SYSTEM-level crash, Azure detected abnormal guest agent behavior on `windows-target-1` and initiated automated recovery actions. One of the first observable responses was the repair or reinstallation of the **Microsoft Monitoring Agent (MMA) Heartbeat Service**.

The MMA Heartbeat Service is responsible for sending periodic health signals from the guest operating system to Azure. These signals confirm that the VM is alive, responsive, and capable of communicating with the Azure control plane. When these signals degrade or stop, Azure interprets the VM as unhealthy and initiates remediation.

Key observations include:
- Azure repaired or reinstalled the MMA Heartbeat Service shortly after the crash
- Multiple heartbeat-related events share identical timestamps (for example, `2025-11-24T04:13:04.160` and `2025-11-24T04:13:04.162`)
- These identical timestamps indicate buffered telemetry flushes rather than real-time execution
- This buffering behavior explains why some PowerShell and service events appear to occur after the crash despite originating earlier

This activity represents the first clear indication of **Azure control-plane intervention** rather than attacker-driven behavior.

```kql
let crash = todatetime('2025-11-24T04:10:00');
DeviceEvents
| where DeviceName == "windows-target-1"
| where TimeGenerated between (crash - 20m .. crash + 20m)
| project TimeGenerated, FileName, ActionType, AdditionalFields, DeviceName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

<img width="1279" height="417" alt="MMA heartbeat recovery attempts" src="https://github.com/user-attachments/assets/54cd2a48-49bf-4243-b860-71b0b49f17c2" /> ```

---

### Guest Configuration Compliance Checks (_gc_worker.exe_)

After the MMA Heartbeat Service recovery attempts, Azure initiated repeated **Guest Configuration compliance checks** using the process `gc_worker.exe`. These checks are used by Azure to validate the integrity, configuration state, and trust relationship of the virtual machine following detected instability.

Observations during this phase include:
- Azure repeatedly executed `gc_worker.exe` in an attempt to re-establish trust with the guest
- Several compliance checks returned **NonCompliant**, indicating the VM was operating in a partial or degraded state
- Despite multiple retries, the VM never fully re-established control-plane trust
- As a result, ARM-based operations, including SYSTEM-level script execution and credential operations, continued to fail

This behavior indicates that while the operating system remained accessible, the Azure management plane no longer considered the guest fully reliable or compliant.

```kql
let crash = todatetime('2025-11-24T04:10:00');
DeviceEvents
| where DeviceName == "windows-target-1"
| where TimeGenerated between (crash - 20m .. crash + 20m)
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

<img width="1140" height="319" alt="Guest configuration compliance attempts" src="https://github.com/user-attachments/assets/8011828a-7ad1-44a5-933a-b4bd6d93261c" /> ```

---

### Restarting the VM Did Not Restore Functionality

A reboot of `windows-target-1` was performed in an attempt to restore normal operation. While the reboot successfully restarted the operating system, it did not resolve the underlying issue impacting Azure-based management and automation.

Key observations include:
- Restarting the VM only reset the guest operating system
- The Azure Guest Agent trust relationship remained degraded
- ARM API operations continued to fail or time out
- SYSTEM-level automation dependent on Azure control-plane access could not execute

Because the attack simulation framework relies on SYSTEM-level commands delivered through Azure, the loss of control-plane trust prevented all automated activity from resuming, even though the VM appeared online and reachable.

<img width="1400" alt="VM reboot ineffective" src="https://github.com/user-attachments/assets/840e4bc3-8267-4e31-aa6c-581f52fef7c2" />

---

### Why Redeploying Worked

Redeploying `windows-target-1` restored functionality because it addressed the underlying **Azure management-plane trust failure**, not just the guest operating system state. Unlike a reboot, redeployment rebuilds the relationship between the Azure control plane and the virtual machine.

During redeployment, Azure performed the following actions:
- Moved the VM to a new physical host
- Reinstalled the Azure Guest Agent
- Re-registered all VM extensions
- Re-established authentication and trust between ARM and the guest operating system

This process effectively reset the **management-plane connection**, allowing SYSTEM-level commands, credential operations, and automation to function again. Once redeployed, attack simulation scripts resumed execution and security telemetry generation returned to normal.

This distinction between OS-level recovery and management-plane recovery is critical in cloud environments and was central to resolving this incident.

<img width="1400" alt="VM redeployment restores functionality" src="https://github.com/user-attachments/assets/ec51200b-4da1-4270-b898-8c0d5f24436d" />

---

## Analyst Assessment

This incident demonstrates how SYSTEM-level automation failures in cloud-hosted environments can closely resemble indicators of compromise without involving malicious activity. The unhandled PowerShell exception disrupted Azure Guest Agent integrity, triggering repeated platform-driven recovery behavior that could be misinterpreted as persistence or adversary tampering when viewed in isolation.

Accurate assessment required correlating endpoint crash telemetry, buffered log artifacts, guest agent health signals, and Azure control-plane recovery actions across multiple data sources. The presence of WerFault.exe activity, repeated heartbeat service repairs, and recurring guest configuration checks reflected Azure attempting to recover trust with a degraded virtual machine rather than responding to attacker behavior.

A key takeaway from this investigation is the distinction between operating system availability and management-plane trust. Although the VM remained accessible at the OS level, Azure could no longer reliably authenticate to or manage the guest. Understanding this separation was essential to determining why reboots failed and why redeployment was the only effective remediation.

This case highlights the importance of cloud platform awareness in modern incident response and reinforces the need to validate agent health and control-plane connectivity before concluding malicious activity.

---

## Recommended Actions

While this event appears to be a non-malicious automation failure, the following actions are recommended to maintain reliable operation and improve detection of similar issues in the future.

### Immediate Recovery Actions
- Redeploy affected virtual machines when Azure Guest Agent trust is degraded
- Verify Azure Guest Agent and VM extension health following recovery
- Confirm SYSTEM-level automation and scheduled tasks execute successfully
- Validate that security telemetry generation has resumed as expected

### Investigation Actions Already Taken
- Reviewed endpoint crash telemetry and process execution timelines
- Confirmed no malicious artifacts were present during or after the SYSTEM-level script crash
- Documented the full sequence of events, including WerFault activity, heartbeat service recovery, guest configuration checks, and HealthService behavior

### Monitoring and Prevention Actions
- Implement alerting for SYSTEM-level script crashes and unhandled exceptions
- Monitor Azure Guest Agent and heartbeat service health continuously
- Track repeated guest configuration compliance failures as indicators of degraded trust
- Periodically validate control-plane connectivity and VM extension status
- Log and visualize Azure recovery and remediation events for faster triage

---

## Conclusion

This investigation confirms that long-running, fully automated systems are vulnerable to environmental and execution-level failures that are not inherently malicious. In this case, a SYSTEM-level PowerShell script encountered an unhandled exception that disrupted Azure Guest Agent integrity, triggering platform-driven recovery behavior rather than attacker activity.

Although the virtual machine remained accessible at the operating system level, Azure control-plane trust was degraded, preventing SYSTEM-level automation, credential operations, and attack simulation from functioning correctly. Standard recovery actions, such as rebooting the VM, were insufficient because they did not address the underlying management-plane failure.

Redeploying the virtual machine restored functionality by rebuilding the Azure Guest Agent and re-establishing trust between the guest and the Azure control plane. This outcome highlights the importance of understanding cloud platform mechanics, telemetry timing, and agent health when performing incident response in cloud environments.

Distinguishing between malicious behavior and platform-driven recovery is critical to accurate analysis. This case demonstrates the value of correlating endpoint telemetry with cloud control-plane signals to reach the correct conclusion and apply the appropriate remediation.
