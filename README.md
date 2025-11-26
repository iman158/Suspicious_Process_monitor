🛡️ Suspicious Process Detector (Real-Time GUI Monitoring Tool)

A powerful, real-time system security & monitoring tool built in Python.
Designed for cybersecurity researchers, malware analysts, sysadmins, and power-users who want deep visibility into process spikes, network activity, and suspicious system behavior — all from an intuitive live GUI.

🚀 Key Features
🔍 Real-Time Process Monitoring

Tracks CPU usage, memory consumption, and process creation rates.

Detects spikes via moving-window statistical baselines.

Highlights abnormal system activity in real time.

🌐 Per-Process Network Visibility

Displays live outbound/inbound network connections per process.

Identify suspicious remote IPs, ports, and unexpected ESTABLISHED sessions.

Simple click on a process → instantly view all its connections.

⚠️ Suspicious Activity Detection Engine

Automatically detects:

High CPU/memory processes

Rapid process creation

Processes with excessive children

Unexpected outbound connections

Network anomalies based on heuristics

System-wide CPU/memory overload

All alerts are:

Logged to file

Displayed live in the GUI

🖥️ Built-In GUI (Tkinter)

Live refreshing process table

Real-time alert log window

Dedicated pane for network connections

Clean and responsive layout

Automatic refresh intervals

🔒 Runs With Elevated Privileges

Attempts automatic sudo relaunch on Linux/macOS.

Windows users get admin privilege warnings.

Higher privilege = more detailed process/network visibility.

📦 Lightweight & Cross-Platform

Works on Windows, macOS, Linux

Depends only on:

psutil

tkinter

Standard Library

📁 What This Tool Helps You Do

Detect suspicious processes instantly

Monitor malware-like behavior (CPU/memory spikes, botnet callbacks)

Inspect unknown executables and their network activity

Analyze system performance anomalies

Maintain a real-time security dashboard

Assist in incident response and forensic triage

🛠️ Technologies Used

Python 3

psutil (system & process information)

Tkinter (GUI)

Threading (non-blocking real-time updates)

📜 Logging & Alerting

Alerts are written to suspicious_process_detector.log

GUI displays alerts as they occur

Includes readable timestamped messages

Fully extensible to send:

Webhooks

Email notifications

Push alerts

Custom scripts

🧩 Extensibility

The code is well-structured and hackable. You can easily add:

Whitelisting rules

Blacklist-based killing or sandboxing

Integration with SIEM/log servers

Machine-learning based anomaly scoring

Exporting to JSON dashboards

Packet-level inspection
