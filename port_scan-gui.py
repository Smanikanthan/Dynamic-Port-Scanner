#!/usr/bin/env python3
"""
Port Scanner with Tkinter GUI and color-coded severity + progress bar.

Run: python3 port_scanner_gui.py
"""

import socket
import concurrent.futures
import threading
import queue
import time
import csv
import sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ---------------------------
# CONFIG: default service hints and severity rules
# ---------------------------
COMMON_SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-alt", 445: "SMB",
    1433: "MSSQL", 1521: "Oracle", 6379: "Redis", 27017: "MongoDB"
}

SEVERITY_RULES = {
    "red":  {23, 445, 3389, 5900, 1433, 3306, 1521},
    "orange": {21, 139, 137, 135, 3306, 6379, 27017},
    "yellow": {25, 110, 143, 69, 161, 3306},
    "green": {22, 53, 80, 443, 123}
}

# ---------------------------
# Scanner functions (same logic as CLI)
# ---------------------------
def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def get_banner(sock, timeout):
    sock.settimeout(timeout)
    try:
        data = sock.recv(1024)
        if data:
            return data.decode(errors="ignore").strip()
    except Exception:
        pass
    return ""

def scan_port(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            res = s.connect_ex((ip, port))
            if res == 0:
                banner = get_banner(s, timeout)
                return (port, True, banner)
            else:
                return (port, False, "")
    except Exception:
        return (port, False, "")

def decide_severity(port, banner):
    if port in SEVERITY_RULES.get("red", set()):
        return "red"
    if port in SEVERITY_RULES.get("orange", set()):
        return "orange"
    if port in SEVERITY_RULES.get("green", set()):
        return "green"
    if port in SEVERITY_RULES.get("yellow", set()):
        return "yellow"
    low = banner.lower() if banner else ""
    if any(k in low for k in ("admin", "unauthorized", "vulnerable", "open", "root")):
        return "orange"
    if port < 1024:
        return "yellow"
    return "orange"

# ---------------------------
# GUI Class
# ---------------------------
class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner — GUI")
        self.root.geometry("950x560")
        self.queue = queue.Queue()
        self.executor = None
        self.stop_scan = threading.Event()
        self.total_ports = 0
        self.completed_ports = 0
        self.start_time = None

        self._build_widgets()
        self._setup_tree_styles()
        self._update_ui_loop()

    def _build_widgets(self):
        frm_top = ttk.Frame(self.root, padding=8)
        frm_top.pack(side="top", fill="x")

        ttk.Label(frm_top, text="Target (IP or hostname):").grid(row=0, column=0, sticky="w")
        self.entry_target = ttk.Entry(frm_top, width=30)
        self.entry_target.grid(row=0, column=1, padx=6, pady=2)
        self.entry_target.insert(0, "127.0.0.1")

        ttk.Label(frm_top, text="Start port:").grid(row=0, column=2, sticky="w")
        self.entry_start = ttk.Entry(frm_top, width=7)
        self.entry_start.grid(row=0, column=3, padx=6)
        self.entry_start.insert(0, "1")

        ttk.Label(frm_top, text="End port:").grid(row=0, column=4, sticky="w")
        self.entry_end = ttk.Entry(frm_top, width=7)
        self.entry_end.grid(row=0, column=5, padx=6)
        self.entry_end.insert(0, "1024")

        ttk.Label(frm_top, text="Threads:").grid(row=1, column=0, sticky="w", pady=4)
        self.entry_threads = ttk.Entry(frm_top, width=10)
        self.entry_threads.grid(row=1, column=1, sticky="w", padx=6)
        self.entry_threads.insert(0, "100")

        ttk.Label(frm_top, text="Timeout (s):").grid(row=1, column=2, sticky="w")
        self.entry_timeout = ttk.Entry(frm_top, width=10)
        self.entry_timeout.grid(row=1, column=3, sticky="w", padx=6)
        self.entry_timeout.insert(0, "0.5")

        self.btn_start = ttk.Button(frm_top, text="Start Scan", command=self.start_scan)
        self.btn_start.grid(row=1, column=4, padx=6)

        self.btn_stop = ttk.Button(frm_top, text="Stop Scan", command=self.stop_scan_now, state="disabled")
        self.btn_stop.grid(row=1, column=5, padx=6)

        # Progress frame
        frm_progress = ttk.Frame(self.root, padding=(8, 0))
        frm_progress.pack(side="top", fill="x")

        self.progress = ttk.Progressbar(frm_progress, orient="horizontal", length=600, mode="determinate")
        self.progress.pack(side="left", padx=6, pady=6)

        self.lbl_progress = ttk.Label(frm_progress, text="0/0 (0%)")
        self.lbl_progress.pack(side="left", padx=8)

        self.lbl_elapsed = ttk.Label(frm_progress, text="Elapsed: 0.0s")
        self.lbl_elapsed.pack(side="left", padx=8)

        # Tree view for results
        columns = ("port", "service", "banner", "severity")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", height=18)
        self.tree.heading("port", text="Port")
        self.tree.heading("service", text="Service")
        self.tree.heading("banner", text="Banner")
        self.tree.heading("severity", text="Severity")
        self.tree.column("port", width=80, anchor="center")
        self.tree.column("service", width=140, anchor="w")
        self.tree.column("banner", width=540, anchor="w")
        self.tree.column("severity", width=100, anchor="center")
        self.tree.pack(side="top", fill="both", expand=True, padx=8, pady=8)

        # Buttons bottom
        frm_bot = ttk.Frame(self.root)
        frm_bot.pack(side="bottom", fill="x", padx=8, pady=6)
        self.lbl_status = ttk.Label(frm_bot, text="Ready")
        self.lbl_status.pack(side="left")

        self.btn_save = ttk.Button(frm_bot, text="Save CSV", command=self.save_csv, state="disabled")
        self.btn_save.pack(side="right", padx=6)

        self.btn_clear = ttk.Button(frm_bot, text="Clear", command=self.clear_results)
        self.btn_clear.pack(side="right", padx=6)

        # color legend
        legend = ttk.Frame(self.root)
        legend.pack(side="bottom", fill="x", padx=8)
        ttk.Label(legend, text="Legend:").pack(side="left")
        for color, text in (("green", "Expected / Necessary"),
                            ("yellow", "Warning / Optional"),
                            ("orange", "Risky / Review"),
                            ("red", "Harmful / High risk")):
            lbl = tk.Label(legend, text="   " + text + "   ", bg=color, fg="black")
            lbl.pack(side="left", padx=6, pady=4)

    def _setup_tree_styles(self):
        self.tree.tag_configure("red", background="#FF6B6B")
        self.tree.tag_configure("orange", background="#FFB86B")
        self.tree.tag_configure("yellow", background="#FFF59D")
        self.tree.tag_configure("green", background="#B9F6CA")

    def start_scan(self):
        target = self.entry_target.get().strip()
        try:
            start = int(self.entry_start.get().strip())
            end = int(self.entry_end.get().strip())
            threads = int(self.entry_threads.get().strip())
            timeout = float(self.entry_timeout.get().strip())
        except Exception:
            messagebox.showerror("Input error", "Please enter valid numeric values.")
            return

        if start < 1 or end > 65535 or start > end:
            messagebox.showerror("Input error", "Port range invalid (1-65535 and start <= end).")
            return
        ip = resolve_target(target)
        if not ip:
            messagebox.showerror("Resolve error", f"Unable to resolve target '{target}'.")
            return

        # UI state
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.btn_save.config(state="disabled")
        self.stop_scan.clear()
        self.lbl_status.config(text=f"Scanning {target} -> {ip} ({start}-{end})")

        # clear previous items
        self.clear_results()

        # set up progress
        self.total_ports = (end - start) + 1
        self.completed_ports = 0
        self.progress["maximum"] = self.total_ports
        self.progress["value"] = 0
        self.lbl_progress.config(text=f"0/{self.total_ports} (0%)")
        self.start_time = time.time()

        # start background scanner
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=threads)
        self.scan_thread = threading.Thread(target=self._run_scan, args=(ip, start, end, timeout), daemon=True)
        self.scan_thread.start()

        # start elapsed timer update
        self._update_elapsed()

    def _run_scan(self, ip, start_port, end_port, timeout):
        ports = range(start_port, end_port + 1)
        futures = {}
        try:
            for port in ports:
                if self.stop_scan.is_set():
                    break
                fut = self.executor.submit(scan_port, ip, port, timeout)
                futures[fut] = port

            # gather results as they complete
            for fut in concurrent.futures.as_completed(futures):
                if self.stop_scan.is_set():
                    break
                try:
                    port, is_open, banner = fut.result()
                except Exception:
                    port, is_open, banner = futures.get(fut, -1), False, ""
                # update progress count (total ports processed)
                self.queue.put(("progress", 1))
                if is_open:
                    service = COMMON_SERVICES.get(port, "-")
                    severity = decide_severity(port, banner)
                    self.queue.put(("open", port, service, banner, severity))
            # done
            self.queue.put(("done",))
        finally:
            if self.executor:
                try:
                    self.executor.shutdown(wait=False)
                except Exception:
                    pass

    def stop_scan_now(self):
        if messagebox.askyesno("Stop scan", "Do you want to stop the current scan?"):
            self.stop_scan.set()
            self.lbl_status.config(text="Stopping scan...")
            self.btn_stop.config(state="disabled")

    def _update_elapsed(self):
        if self.start_time and not self.stop_scan.is_set():
            elapsed = time.time() - self.start_time
            self.lbl_elapsed.config(text=f"Elapsed: {elapsed:.1f}s")
            # schedule next update
            self.root.after(300, self._update_elapsed)
        else:
            # final update when stopped/done
            if self.start_time:
                elapsed = time.time() - self.start_time
                self.lbl_elapsed.config(text=f"Elapsed: {elapsed:.1f}s")

    def _update_ui_loop(self):
        # Called periodically in the mainloop to process queue
        try:
            while True:
                item = self.queue.get_nowait()
                if not item:
                    continue
                tag = item[0]
                if tag == "open":
                    _, port, service, banner, severity = item
                    self._add_result_row(port, service, banner, severity)
                elif tag == "progress":
                    _, delta = item
                    self.completed_ports += delta
                    # update progress bar + label
                    self.progress["value"] = self.completed_ports
                    pct = int((self.completed_ports / self.total_ports) * 100) if self.total_ports else 0
                    self.lbl_progress.config(text=f"{self.completed_ports}/{self.total_ports} ({pct}%)")
                elif tag == "done":
                    self.lbl_status.config(text="Scan finished")
                    self.btn_start.config(state="normal")
                    self.btn_stop.config(state="disabled")
                    self.btn_save.config(state="normal")
                    # ensure final elapsed update
                    if self.start_time:
                        elapsed = time.time() - self.start_time
                        self.lbl_elapsed.config(text=f"Elapsed: {elapsed:.1f}s")
        except queue.Empty:
            pass
        # schedule next poll
        self.root.after(150, self._update_ui_loop)

    def _add_result_row(self, port, service, banner, severity):
        self.tree.insert("", "end", values=(port, service, banner, severity.upper()), tags=(severity,))

    def clear_results(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.lbl_status.config(text="Ready")
        self.btn_save.config(state="disabled")
        self.progress["value"] = 0
        self.lbl_progress.config(text="0/0 (0%)")
        self.lbl_elapsed.config(text="Elapsed: 0.0s")
        self.total_ports = 0
        self.completed_ports = 0
        self.start_time = None

    def save_csv(self):
        items = []
        for iid in self.tree.get_children():
            port, service, banner, severity = self.tree.item(iid, "values")
            items.append((port, service, banner, severity))
        if not items:
            messagebox.showinfo("No data", "No results to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv"), ("All files","*.*")])
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Port","Service","Banner","Severity"])
                for row in items:
                    writer.writerow(row)
            messagebox.showinfo("Saved", f"Results saved to {path}")
        except Exception as e:
            messagebox.showerror("Save error", f"Failed to save: {e}")

# ---------------------------
# Run the GUI
# ---------------------------
def main():
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
