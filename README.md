# CyberTrace AI

## From Isolated Events to Explainable Attack Intelligence

CyberTrace AI is an AI-powered Cyber Threat Intelligence system designed to correlate isolated security events across users, devices, IP addresses, applications and resources.

Instead of treating every suspicious event as a separate alert, CyberTrace analyzes related events in chronological order and reconstructs them into an explainable attack chain.

The system is designed to help security teams understand:

- Who was involved
- Which device was involved
- Which IP address was associated with the event
- What resource or application was accessed
- What happened and in what order
- Why the activity is considered suspicious
- What evidence supports each attack stage
- What level of risk is associated with the activity
- What response should be considered


## Problem Statement

Security systems can generate a very large number of logs from user logins, computers, applications and networks.

An individual event may appear normal or only slightly suspicious. However, multiple events occurring across the same user, device, IP address, application and resource can reveal a coordinated attack.

For example:

1. A user logs in from an unusual location.
2. The same user accesses a resource they have never accessed before.
3. A USB device is connected.
4. Sensitive data is copied to the USB device.

Each event individually may not be enough to declare an attack.

When these events are correlated and reconstructed in the correct chronological order, they can form a much stronger attack story.

CyberTrace AI focuses on identifying these relationships while reducing unnecessary false positives.


## Solution

CyberTrace AI works as a centralized security intelligence layer.

Security logs from multiple users, devices, servers and applications can be collected and passed into the system.

The processing flow is:

Security Logs
    ↓
Log Normalization
    ↓
Feature Extraction
    ↓
Anomaly Detection
    ↓
Event Correlation
    ↓
Attack Chain Reconstruction
    ↓
Timeline + Attack Graph
    ↓
Evidence
    ↓
Risk Assessment
    ↓
AI Explanation
    ↓
Recommended Response


## Key Features

### 1. Event Correlation

CyberTrace connects related security events using meaningful relationships such as:

- User
- Device
- IP address
- Application
- Resource
- Action
- Timestamp

Time proximity alone is not treated as sufficient evidence.

### 2. Attack Chain Reconstruction

Related events are ordered using their event timestamps to reconstruct a possible attack sequence.

Example:

10:01 - Unusual login

10:08 - Previously unseen resource accessed

10:12 - USB device connected

10:14 - Sensitive file copied

The system combines these events into one explainable attack chain.

### 3. Evidence-Based Detection

Every attack stage must have supporting evidence.

Evidence can include:

- Event timestamp
- User
- Device
- IP address
- Application
- Resource
- Action
- Source event identifier

The system should not claim an attack stage when supporting evidence is unavailable.

### 4. False-Positive Control

A single unusual event does not automatically become a high-confidence attack.

CyberTrace increases confidence when multiple related events support the same attack story.

For example:

Unusual login
    ↓
Unusual resource access
    ↓
USB connection
    ↓
File copy

The combined evidence is stronger than any single event.

### 5. Explainable Risk

The risk assessment is based on observed evidence and contributing factors rather than an unexplained random score.

The dashboard shows why the risk level was assigned.

### 6. AI-Assisted Explanation

The AI explanation layer converts structured detection results into an understandable security explanation.

The AI receives the evidence produced by the detection and correlation engine rather than inventing users, IP addresses, timestamps or attack stages.

A deterministic fallback can be used when the AI service is unavailable.


## Organization-Wide Use

CyberTrace AI is designed as a centralized security intelligence layer rather than an application that must be installed separately for every user.

A possible college deployment could look like:

Users / Student Systems / Faculty Systems / Labs / Servers
                         ↓
                  Security Logs
                         ↓
                  CyberTrace AI
                         ↓
                 Central Dashboard
                         ↓
                  IT / Security Team

For an organization with 1,000+ users, the architecture can receive events from multiple systems and correlate them centrally.

The current hackathon prototype demonstrates the core correlation and attack-reconstruction capability using synthetic security logs. It does not claim production-scale deployment for thousands or millions of real-world events.


## Data Pipeline

The prototype uses security events containing fields such as:

- Timestamp
- User
- Device
- IP address
- Application
- Resource
- Action
- Event type

Example:

| Timestamp | User | Device | IP | Event | Resource |
|-----------|------|--------|----|-------|----------|
| 10:01 | student123 | LAB-PC-27 | 10.10.5.27 | login | portal |
| 10:08 | student123 | LAB-PC-27 | 10.10.5.27 | file_access | sensitive_file |
| 10:12 | student123 | LAB-PC-27 | 10.10.5.27 | usb_connected | USB-4421 |
| 10:14 | student123 | LAB-PC-27 | 10.10.5.27 | file_copy | sensitive_file |

The events are normalized and analyzed before being correlated into an attack chain.


## Sample Attack Scenario

### Scenario: Coordinated Data Exfiltration

A synthetic user account performs the following sequence:

1. Login from an unusual IP/location
2. Access to a previously unseen resource
3. Connection of a removable USB device
4. Copying of sensitive data

CyberTrace correlates the events because they share meaningful identifiers and occur in a relevant chronological sequence.

### Expected Output

HIGH-CONFIDENCE ATTACK

Attack Type:
Coordinated Data Exfiltration

Timeline:
10:01 → Unusual Login
10:08 → Unusual Resource Access
10:12 → USB Connected
10:14 → Sensitive File Copy

Evidence:
- Unusual authentication event
- Previously unseen resource access
- New removable device
- File-copy activity

Risk:
HIGH

Explanation:
Multiple related events involving the same user and device form a coordinated sequence consistent with data exfiltration.


## Benign Scenario

CyberTrace is also tested with clean or benign logs.

Example:

Normal login
    ↓
Normal application access
    ↓
Normal resource usage

Expected output:

NO COORDINATED ATTACK DETECTED

The system should remain quiet when there is insufficient correlated evidence to declare an attack.


## Core Reasoning

The core detection process follows these stages:

1. Normalize incoming security events.
2. Identify suspicious or anomalous events.
3. Extract relevant entities and relationships.
4. Correlate events using user, device, IP, application, resource and timestamp.
5. Order events chronologically.
6. Construct a possible attack chain.
7. Attach source evidence to every stage.
8. Calculate an explainable risk level.
9. Generate an analyst-friendly explanation.
10. Present the result through the dashboard.


## Technologies

Frontend:
- React
- TypeScript
- Tailwind CSS

Backend:
- Python
- FastAPI

Data Processing:
- Pandas
- NumPy

Database:
- SQLite

Visualization:
- React-based timeline and attack graph visualization

AI:
- Gemini API through a secure backend integration

The core detection and correlation logic is designed to operate independently of the AI explanation layer.


## Project Structure

```text
cybertrace-ai/
│
├── frontend/
│   ├── src/
│   └── ...
│
├── backend/
│   ├── ...
│
├── data/
│   ├── attack_logs/
│   └── benign_logs/
│
├── README.md
├── requirements.txt
├── package.json
└── ...
