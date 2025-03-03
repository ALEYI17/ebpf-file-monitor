# eBPF File Monitor

## Overview
This project is an **eBPF-based file monitoring tool** that captures system calls such as `openat`, `read`, and `write`. It logs them in a structured and readable format using **Go** in user space and **eBPF** in kernel space.

## Features
- **Real-time system call logging** for file-related operations.
- **Customizable log formatting** using `lipgloss` for better readability.
- **Efficient eBPF integration** for low-overhead system monitoring.
- **Pretty logging** using `charmbracelet/log` and `lipgloss`.
- **Uses `cilium/ebpf` for eBPF program management in user space.**

## Technologies Used
### Kernel Space
- **eBPF**: Used to attach probes to system calls and capture events efficiently.
- **Linux Kernel**: The project runs on Linux and utilizes kernel tracing mechanisms.

### User Space
- **Go**: The primary programming language used for log processing.
- **Lipgloss**: Used for styling log messages with colors.
- **charmbracelet/log**: For structured logging.
- **cilium/ebpf**: Used to interact with eBPF programs in user space.

## Installation & Usage
### Prerequisites
- Linux system with **eBPF** support.
- Go installed (`go version` should return a valid version).

### Steps to Run
1. **Clone the repository:**
   ```sh
   git clone https://github.com/ALEYI17/ebpf-file-monitor.git
   cd ebpf-file-monitor
   ```
2. **Build and Run the Project:**
   ```sh
   go build -o ebpf_file_monitor
   sudo ./ebpf_file_monitor
   ```

## How It Works
- The eBPF program hooks into system calls tracepoints(`openat`, `read`, `write`) to capture events.
- Events are passed from **kernel space** to **user space** via a ring buffer.
- The **Go application** processes and formats logs for readability.
