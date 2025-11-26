#!/usr/bin/env python3

import os
import sys
import time
import logging
import threading
import traceback
from collections import deque, defaultdict
import platform
import queue
import psutil
import socket
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# ---------------------------
# CONFIG RANGE COMMENT BLOCK
# (tweak these in the config section below)
# ---------------------------
# SAMPLE_INTERVAL: range 0.5 - 10.0 seconds (float)
# MOVING_WINDOW_SECONDS: range 10 - 600 (seconds)
# CPU_SPIKE_FACTOR: range 1.5 - 10.0 (multiplier)
# MEMORY_SPIKE_FACTOR: range 1.5 - 10.0 (multiplier)
# ABS_CPU_THRESHOLD: range 2.0 - 100.0 (%)
# ABS_MEM_BYTES: range 1*1024**2 (1MB) - 10*1024**3 (10GB)
# SYSTEM_CPU_THRESHOLD: range 50 - 100 (%)
# SYSTEM_MEM_PERCENT: range 50 - 100 (%)
# NEW_PROC_RATE_THRESHOLD: range 1 - 100 (count in moving window)
# ---------------------------

# -------------------------------
# CONFIGURATION (tweak as needed)
# -------------------------------
SAMPLE_INTERVAL = 2.0          # seconds between samples
MOVING_WINDOW_SECONDS = 60     # baseline window length for averages (seconds)
WINDOW_SAMPLES = max(3, int(MOVING_WINDOW_SECONDS / SAMPLE_INTERVAL))

CPU_SPIKE_FACTOR = 4.0         # CPU% spike factor over moving average to flag (e.g., 4x)
MEMORY_SPIKE_FACTOR = 4.0      # RSS spike factor over moving average to flag
ABS_CPU_THRESHOLD = 50.0       # absolute per-process CPU% threshold to flag immediately
ABS_MEM_BYTES = 200 * 1024**2  # absolute per-process RAM threshold to flag (200 MB)
SYSTEM_CPU_THRESHOLD = 85.0    # overall system CPU% threshold to flag
SYSTEM_MEM_PERCENT = 85.0      # system memory used percent threshold to flag
NEW_PROC_RATE_THRESHOLD = 5    # new processes in MOVING_WINDOW_SECONDS considered suspicious
LOG_FILE = "suspicious_process_detector.log"
ALERT_COMMAND = None           # optional shell command to run on alert (e.g. send notification)
MAX_TRACKED_PIDS = 2000        # cap memory usage of tracker

# Heuristic for network check:
NETWORK_REMOTE_PORT_THRESHOLD = 1024
NETWORK_WHITELIST_IPS = {"127.0.0.1", "::1"}  # Add trusted remote IPs here if desired
PROCESS_WHITELIST = {"System", "systemd", "init", "svchost.exe", "explorer.exe", "python.exe"}  # Example names

# -------------------------------
# Logging setup
# -------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

# Thread-safe queue for GUI alerts
gui_alert_queue = queue.Queue(maxsize=1000)

# -------------------------------
# Internal tracking data structures
# -------------------------------
process_cpu_history = defaultdict(lambda: deque(maxlen=WINDOW_SAMPLES))
process_mem_history = defaultdict(lambda: deque(maxlen=WINDOW_SAMPLES))
process_name_cache = {}   # pid -> name for nicer messages
recent_new_pids = deque(maxlen=WINDOW_SAMPLES)
process_conn_cache = defaultdict(list)  # pid -> list of readable connection strings

# -------------------------------
# Utilities
# -------------------------------
def readable_bytes(n):
    for unit in ['B','KB','MB','GB','TB']:
        if n < 1024.0:
            return f"{n:3.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}PB"

def alert(message):
    """Central alert: log it and push to GUI queue"""
    timestamped = f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}"
    logging.warning(message)
    try:
        gui_alert_queue.put_nowait(timestamped)
    except queue.Full:
        logging.warning("GUI alert queue full, dropping alert")
    if ALERT_COMMAND:
        try:
            os.system(ALERT_COMMAND)
        except Exception as e:
            logging.error("Failed to run alert command: %s", e)

def moving_average(deq):
    if not deq:
        return 0.0
    return sum(deq) / len(deq)

def format_conn(conn):
    """Return a human-readable string for a psutil connection object."""
    try:
        laddr = None
        raddr = None
        if hasattr(conn, 'laddr') and conn.laddr:
            try:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if hasattr(conn.laddr, 'ip') else f"{conn.laddr[0]}:{conn.laddr[1]}"
            except Exception:
                laddr = str(conn.laddr)
        if hasattr(conn, 'raddr') and conn.raddr:
            try:
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if hasattr(conn.raddr, 'ip') else f"{conn.raddr[0]}:{conn.raddr[1]}"
            except Exception:
                raddr = str(conn.raddr)
        status = getattr(conn, 'status', '') or ''
        return f"{status} | local={laddr or '<unnamed>'} -> remote={raddr or '<none>'} | fd={getattr(conn,'fd', '?')}"
    except Exception:
        return "<unparseable-connection>"

# -------------------------------
# Network heuristics
# -------------------------------
def is_suspicious_connection(conn):
    """
    Return True if connection looks suspicious:
    - has a remote address
    - remote IP not in whitelist
    - remote port > NETWORK_REMOTE_PORT_THRESHOLD
    - status is ESTABLISHED (or similar)
    """
    try:
        if not conn.raddr:
            return False
        # raddr could be an addr tuple or an object with ip/port
        raddr_val = None
        rport = None
        if hasattr(conn.raddr, 'ip'):
            raddr_val = conn.raddr.ip
            rport = conn.raddr.port
        else:
            # assume tuple
            raddr_val = conn.raddr[0]
            rport = conn.raddr[1]
        if raddr_val in NETWORK_WHITELIST_IPS:
            return False
        if str(raddr_val).startswith('127.') or str(raddr_val) == '::1':
            return False
        status = getattr(conn, 'status', '') or ''
        if rport >= NETWORK_REMOTE_PORT_THRESHOLD and status.upper() in ("ESTABLISHED", "SYN_SENT", "SYN_RECV"):
            return True
        if status.upper() == "ESTABLISHED":
            return True
    except Exception:
        return True
    return False

# -------------------------------
# Monitor loop running in a background thread
# -------------------------------
def safe_proc_info(p):
    """Return tuple (pid, name, cpu_percent, rss_bytes, connections) or None on access error."""
    try:
        pid = p.pid
        name = p.name()
        cpu = p.cpu_percent(interval=None)
        rss = p.memory_info().rss
        try:
            conns = p.connections(kind='inet')
        except (psutil.AccessDenied, NotImplementedError):
            conns = []
        return pid, name, cpu, rss, conns
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None
    except Exception:
        logging.debug("Unexpected error getting proc info: %s", traceback.format_exc())
        return None


def cleanup_old_pids(current_pids_set):
    """Remove memory for PIDs that have disappeared to avoid unbounded growth."""
    tracked = list(process_cpu_history.keys())
    for pid in tracked:
        if pid not in current_pids_set:
            process_cpu_history.pop(pid, None)
            process_mem_history.pop(pid, None)
            process_name_cache.pop(pid, None)
            process_conn_cache.pop(pid, None)
    if len(process_cpu_history) > MAX_TRACKED_PIDS:
        for pid in list(process_cpu_history.keys())[:len(process_cpu_history)-MAX_TRACKED_PIDS]:
            process_cpu_history.pop(pid, None)
            process_mem_history.pop(pid, None)
            process_name_cache.pop(pid, None)
            process_conn_cache.pop(pid, None)


def monitor_loop(stop_event):
    logging.info("Starting Suspicious Process Detector on %s", platform.platform())
    for p in psutil.process_iter():
        try:
            p.cpu_percent(interval=None)
        except Exception:
            pass

    while not stop_event.is_set():
        try:
            start_time = time.time()
            current_procs = list(psutil.process_iter())
            current_pids = set(p.pid for p in current_procs)

            new_pids_this_round = []
            for p in current_procs:
                if p.pid not in process_cpu_history:
                    new_pids_this_round.append(p.pid)
            for new_pid in new_pids_this_round:
                recent_new_pids.append(new_pid)

            system_cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            system_mem_pct = mem.percent

            if system_cpu >= SYSTEM_CPU_THRESHOLD:
                alert(f"High system CPU usage: {system_cpu:.1f}% >= {SYSTEM_CPU_THRESHOLD}%")
            if system_mem_pct >= SYSTEM_MEM_PERCENT:
                alert(f"High system memory usage: {system_mem_pct:.1f}% >= {SYSTEM_MEM_PERCENT}%")

            for p in current_procs:
                info = safe_proc_info(p)
                if not info:
                    continue
                pid, name, cpu_percent, rss, conns = info
                process_name_cache[pid] = name
                process_cpu_history[pid].append(cpu_percent)
                process_mem_history[pid].append(rss)

                # Store readable connections in cache for GUI
                conn_strings = []
                for c in conns:
                    try:
                        conn_strings.append(format_conn(c))
                    except Exception:
                        conn_strings.append('<unparseable-conn>')
                process_conn_cache[pid] = conn_strings

                if cpu_percent >= ABS_CPU_THRESHOLD and name not in PROCESS_WHITELIST:
                    alert(f"PID {pid} ({name}) high CPU: {cpu_percent:.1f}% (>= {ABS_CPU_THRESHOLD}%)")

                if rss >= ABS_MEM_BYTES and name not in PROCESS_WHITELIST:
                    alert(f"PID {pid} ({name}) high memory: {readable_bytes(rss)} (>= {readable_bytes(ABS_MEM_BYTES)})")

                cpu_hist = process_cpu_history[pid]
                mem_hist = process_mem_history[pid]

                if len(cpu_hist) >= 2:
                    avg_cpu = moving_average(list(cpu_hist)[:-1])
                    last_cpu = cpu_hist[-1]
                    baseline_cpu = max(avg_cpu, 0.01)
                    if last_cpu >= baseline_cpu * CPU_SPIKE_FACTOR and last_cpu >= 5.0 and name not in PROCESS_WHITELIST:
                        alert(f"CPU spike: PID {pid} ({name}) CPU {last_cpu:.1f}% vs baseline {avg_cpu:.2f}%")

                if len(mem_hist) >= 2:
                    avg_mem = moving_average(list(mem_hist)[:-1])
                    last_mem = mem_hist[-1]
                    baseline_mem = max(avg_mem, 1)
                    if last_mem >= baseline_mem * MEMORY_SPIKE_FACTOR and (last_mem - baseline_mem) >= (10*1024**2) and name not in PROCESS_WHITELIST:
                        alert(f"Memory spike: PID {pid} ({name}) memory {readable_bytes(last_mem)} vs baseline {readable_bytes(int(avg_mem))}")

                # network checks
                for conn in conns:
                    try:
                        if is_suspicious_connection(conn) and name not in PROCESS_WHITELIST:
                            try:
                                rinfo = conn.raddr
                                if rinfo:
                                    raddr = f"{rinfo.ip}:{rinfo.port}" if hasattr(rinfo, 'ip') else f"{rinfo[0]}:{rinfo[1]}"
                                else:
                                    raddr = "<no-remote>"
                            except Exception:
                                raddr = "<unknown>"
                            alert(f"Network outbound socket: PID {pid} ({name}) -> {raddr} status={getattr(conn,'status','?')}")
                    except Exception:
                        logging.debug("Error checking connection: %s", traceback.format_exc())

                try:
                    num_children = len(p.children())
                    if num_children > 10 and name not in PROCESS_WHITELIST:
                        alert(f"PID {pid} ({name}) has many child processes: {num_children}")
                except Exception:
                    pass

            if len(recent_new_pids) >= NEW_PROC_RATE_THRESHOLD:
                alert(f"High process creation rate: {len(recent_new_pids)} new processes in last {MOVING_WINDOW_SECONDS} seconds")

            cleanup_old_pids(current_pids)

            elapsed = time.time() - start_time
            sleep_for = max(0.1, SAMPLE_INTERVAL - elapsed)
            stop_event.wait(timeout=sleep_for)

        except Exception:
            logging.error("Error in monitor loop: %s", traceback.format_exc())
            stop_event.wait(timeout=max(0.5, SAMPLE_INTERVAL))

# -------------------------------
# Simple Tkinter GUI with connection view
# -------------------------------
class DetectorGUI:
    def __init__(self, root, stop_event):
        self.root = root
        self.stop_event = stop_event
        root.title("Suspicious Process Detector (GUI)")
        root.geometry("1200x700")

        # Top frame: controls
        top_frame = ttk.Frame(root)
        top_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        self.status_var = tk.StringVar(value="Starting...")
        ttk.Label(top_frame, text="Status:").pack(side=tk.LEFT)
        ttk.Label(top_frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=(2,10))

        ttk.Button(top_frame, text="Clear Alerts", command=self.clear_alerts).pack(side=tk.RIGHT)
        ttk.Button(top_frame, text="Quit", command=self.on_quit).pack(side=tk.RIGHT, padx=(5,0))

        # Main panes: processes and alerts+connections
        main_pane = ttk.Panedwindow(root, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left: process tree / table
        left_frame = ttk.Frame(main_pane)
        main_pane.add(left_frame, weight=3)
        ttk.Label(left_frame, text="Processes (live)").pack(anchor=tk.W)

        columns = ("pid", "name", "cpu", "mem")
        self.proc_tree = ttk.Treeview(left_frame, columns=columns, show="headings", selectmode="browse")
        for col in columns:
            self.proc_tree.heading(col, text=col.upper())
            if col in ("name",):
                self.proc_tree.column(col, width=420, anchor=tk.W)
            else:
                self.proc_tree.column(col, width=100, anchor=tk.E)
        self.proc_tree.pack(fill=tk.BOTH, expand=True)
        self.proc_tree.bind('<<TreeviewSelect>>', self.on_proc_select)

        # Right: alerts log and connections (stacked vertically)
        right_outer = ttk.Frame(main_pane)
        main_pane.add(right_outer, weight=2)

        # Alerts on top
        alerts_frame = ttk.Frame(right_outer)
        alerts_frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(alerts_frame, text="Alerts (real-time)").pack(anchor=tk.W)
        self.alert_text = scrolledtext.ScrolledText(alerts_frame, state="disabled", height=12)
        self.alert_text.pack(fill=tk.BOTH, expand=True)

        # Connections pane below
        conn_frame = ttk.Frame(right_outer)
        conn_frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(conn_frame, text="Selected Process Connections").pack(anchor=tk.W)
        self.conn_text = scrolledtext.ScrolledText(conn_frame, state="disabled", height=12)
        self.conn_text.pack(fill=tk.BOTH, expand=True)

        # bottom: summary
        bottom_frame = ttk.Frame(root)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)
        self.last_update_var = tk.StringVar(value="Never")
        ttk.Label(bottom_frame, text="Last update:").pack(side=tk.LEFT)
        ttk.Label(bottom_frame, textvariable=self.last_update_var).pack(side=tk.LEFT, padx=(2,10))

        # Start periodic GUI updates
        self.root.after(1000, self.refresh_gui)

    def refresh_gui(self):
        """Fetch latest process stats (from global trackers) and update widgets."""
        try:
            proc_items = []
            for pid, name in list(process_name_cache.items()):
                cpu_hist = process_cpu_history.get(pid)
                mem_hist = process_mem_history.get(pid)
                if cpu_hist:
                    cpu = cpu_hist[-1] if len(cpu_hist) else 0.0
                else:
                    cpu = 0.0
                if mem_hist:
                    mem = mem_hist[-1]
                else:
                    mem = 0
                proc_items.append((pid, name, cpu, mem))
            proc_items.sort(key=lambda x: (x[2], x[3]), reverse=True)

            # refresh tree
            for it in self.proc_tree.get_children():
                self.proc_tree.delete(it)
            for pid, name, cpu, mem in proc_items[:800]:
                self.proc_tree.insert("", "end", values=(pid, name, f"{cpu:.1f}%", readable_bytes(mem)))

            self.status_var.set(f"Monitoring — processes tracked: {len(process_name_cache)}")
            self.last_update_var.set(time.strftime("%Y-%m-%d %H:%M:%S"))

            # Drain GUI alert queue
            while True:
                try:
                    a = gui_alert_queue.get_nowait()
                    self.append_alert(a)
                except queue.Empty:
                    break

        except Exception:
            logging.debug("Error refreshing GUI: %s", traceback.format_exc())
        finally:
            if not self.stop_event.is_set():
                self.root.after(int(max(500, SAMPLE_INTERVAL * 1000)), self.refresh_gui)

    def append_alert(self, text_line):
        self.alert_text.configure(state="normal")
        self.alert_text.insert(tk.END, text_line + "\n")
        self.alert_text.configure(state="disabled")
        self.alert_text.see(tk.END)

    def clear_alerts(self):
        self.alert_text.configure(state="normal")
        self.alert_text.delete("1.0", tk.END)
        self.alert_text.configure(state="disabled")

    def on_proc_select(self, event):
        """When a process is selected in the tree, show its cached connections."""
        try:
            sel = self.proc_tree.selection()
            if not sel:
                return
            item = sel[0]
            vals = self.proc_tree.item(item, 'values')
            if not vals:
                return
            pid = int(vals[0])
            # Fetch connection strings from cache
            conns = process_conn_cache.get(pid, [])
            self.conn_text.configure(state="normal")
            self.conn_text.delete('1.0', tk.END)
            if not conns:
                self.conn_text.insert(tk.END, "No inet connections or access denied / none seen.\n")
            else:
                for c in conns:
                    self.conn_text.insert(tk.END, c + "\n")
            self.conn_text.configure(state="disabled")
            self.conn_text.see(tk.END)
        except Exception:
            logging.debug("Error in on_proc_select: %s", traceback.format_exc())

    def on_quit(self):
        if messagebox.askokcancel("Quit", "Stop monitoring and quit?"):
            self.stop_event.set()
            self.root.quit()

# -------------------------------
# Privilege helpers
# -------------------------------
def is_root():
    if os.name == 'nt':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0

def relaunch_as_root_unix():
    try:
        python = sys.executable or 'python3'
        args = [python] + sys.argv
        if os.getenv("SUDO_UID") is None:
            os.execvp("sudo", ["sudo"] + args)
    except Exception as e:
        logging.error("Failed to relaunch via sudo: %s", e)

# -------------------------------
# Main entry
# -------------------------------
def main():
    if not is_root():
        if os.name != 'nt':
            logging.info("Script not running as root. Attempting to relaunch with sudo...")
            try:
                relaunch_as_root_unix()
            except Exception:
                logging.exception("Relaunch attempt failed.")
        else:
            logging.warning("Script is not running with Administrator privileges. Some process info may be limited on Windows. Run as Administrator for best results.")

    stop_event = threading.Event()

    monitor_thread = threading.Thread(target=monitor_loop, args=(stop_event,), daemon=True)
    monitor_thread.start()

    root = tk.Tk()
    gui = DetectorGUI(root, stop_event)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        logging.info("Shutting down, waiting for monitor thread to stop...")
        stop_event.set()
        monitor_thread.join(timeout=2.0)
        logging.info("Exited.")

if __name__ == "__main__":
    try:
        logging.info("Configuration ranges (commented in file). SAMPLE_INTERVAL=%s, WINDOW=%s sec (%d samples)",
                     SAMPLE_INTERVAL, MOVING_WINDOW_SECONDS, WINDOW_SAMPLES)
        main()
    except Exception:
        logging.error("Fatal error in main: %s", traceback.format_exc())
