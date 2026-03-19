# Secure File Transfer Monitoring System

## Overview
This project was developed as an internship practical assessment. It is a Python-based defensive monitoring toolkit designed to ensure data confidentiality and track file movement across a system. 

## Features
* **File System Monitoring:** Tracks copy, move, delete, upload, and download events in real-time using `watchdog`.
* **Tamper Detection:** Implements cryptographic hash-based integrity checking (SHA-256) via the `hashlib` module to detect unauthorized modifications.
* **Alerting & Auditing:** Generates comprehensive audit logs detailing timestamps, source/destination paths, and security alerts for suspicious movements.

## Technologies Used
* Python 3.x
* `watchdog` (Filesystem event monitoring)
* `hashlib` (Integrity verification)

## Usage
Run the script to begin monitoring the designated sensitive directory. Press `Ctrl+C` to terminate the process and save the final `security_audit.log`.
