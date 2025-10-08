from __future__ import annotations

import json
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Dict, List, Optional

from .engine import ScanConfig, Scanner


class BypassGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("403 Bypass Scanner")
        self.geometry("1100x700")
        self._scanner_thread: Optional[threading.Thread] = None
        self._scanner: Optional[Scanner] = None
        self._results: List[dict] = []
        self._build_widgets()

    def _build_widgets(self) -> None:
        frm = ttk.Frame(self)
        frm.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        config_frame = ttk.LabelFrame(frm, text="Configuration")
        config_frame.pack(fill=tk.X, padx=4, pady=4)

        ttk.Label(config_frame, text="Target URL").grid(row=0, column=0, sticky=tk.W, padx=4, pady=4)
        self.entry_url = ttk.Entry(config_frame, width=80)
        self.entry_url.grid(row=0, column=1, sticky=tk.W, padx=4, pady=4)

        ttk.Label(config_frame, text="Headers (key: value per line)").grid(row=1, column=0, sticky=tk.NW, padx=4, pady=4)
        self.text_headers = tk.Text(config_frame, height=6, width=60)
        self.text_headers.grid(row=1, column=1, sticky=tk.W, padx=4, pady=4)

        ttk.Label(config_frame, text="Cookies (Cookie header value)").grid(row=2, column=0, sticky=tk.W, padx=4, pady=4)
        self.entry_cookies = ttk.Entry(config_frame, width=80)
        self.entry_cookies.grid(row=2, column=1, sticky=tk.W, padx=4, pady=4)

        ttk.Label(config_frame, text="Proxy (e.g. http://127.0.0.1:8080)").grid(row=3, column=0, sticky=tk.W, padx=4, pady=4)
        self.entry_proxy = ttk.Entry(config_frame, width=80)
        self.entry_proxy.grid(row=3, column=1, sticky=tk.W, padx=4, pady=4)

        ttk.Label(config_frame, text="User-Agent").grid(row=4, column=0, sticky=tk.W, padx=4, pady=4)
        self.entry_ua = ttk.Entry(config_frame, width=80)
        self.entry_ua.grid(row=4, column=1, sticky=tk.W, padx=4, pady=4)

        ttk.Label(config_frame, text="Threads").grid(row=0, column=2, sticky=tk.W, padx=4, pady=4)
        self.spin_threads = tk.Spinbox(config_frame, from_=1, to=64, width=5)
        self.spin_threads.delete(0, tk.END)
        self.spin_threads.insert(0, "16")
        self.spin_threads.grid(row=0, column=3, sticky=tk.W, padx=4, pady=4)

        ttk.Label(config_frame, text="Timeout (s)").grid(row=1, column=2, sticky=tk.W, padx=4, pady=4)
        self.spin_timeout = tk.Spinbox(config_frame, from_=1, to=120, width=5)
        self.spin_timeout.delete(0, tk.END)
        self.spin_timeout.insert(0, "15")
        self.spin_timeout.grid(row=1, column=3, sticky=tk.W, padx=4, pady=4)

        ttk.Label(config_frame, text="Delay (ms)").grid(row=2, column=2, sticky=tk.W, padx=4, pady=4)
        self.spin_delay = tk.Spinbox(config_frame, from_=0, to=2000, width=5)
        self.spin_delay.delete(0, tk.END)
        self.spin_delay.insert(0, "0")
        self.spin_delay.grid(row=2, column=3, sticky=tk.W, padx=4, pady=4)

        self.var_methods_all = tk.BooleanVar(value=False)
        chk_methods = ttk.Checkbutton(
            config_frame,
            text="Include non-idempotent methods (POST/PUT/DELETE/PATCH)",
            variable=self.var_methods_all,
        )
        chk_methods.grid(row=3, column=2, columnspan=2, sticky=tk.W, padx=4, pady=4)

        ttk.Label(config_frame, text="Extra query payloads (one per line)").grid(row=5, column=0, sticky=tk.NW, padx=4, pady=4)
        self.text_queries = tk.Text(config_frame, height=4, width=60)
        self.text_queries.grid(row=5, column=1, sticky=tk.W, padx=4, pady=4)

        btn_frame = ttk.Frame(config_frame)
        btn_frame.grid(row=6, column=0, columnspan=4, sticky=tk.W, padx=4, pady=4)

        self.btn_start = ttk.Button(btn_frame, text="Start Scan", command=self.start_scan)
        self.btn_start.pack(side=tk.LEFT, padx=4)
        self.btn_stop = ttk.Button(btn_frame, text="Stop", command=self.stop_scan, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=4)

        self.btn_export_csv = ttk.Button(btn_frame, text="Export CSV", command=lambda: self.export_results("csv"))
        self.btn_export_csv.pack(side=tk.LEFT, padx=4)
        self.btn_export_json = ttk.Button(btn_frame, text="Export JSON", command=lambda: self.export_results("json"))
        self.btn_export_json.pack(side=tk.LEFT, padx=4)

        table_frame = ttk.LabelFrame(frm, text="Results")
        table_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        columns = ("method", "status", "length", "time", "url", "desc")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        self.tree.heading("method", text="Method")
        self.tree.heading("status", text="Status")
        self.tree.heading("length", text="Length")
        self.tree.heading("time", text="Time (ms)")
        self.tree.heading("url", text="URL")
        self.tree.heading("desc", text="Description")

        self.tree.column("method", width=80, anchor=tk.W)
        self.tree.column("status", width=80, anchor=tk.W)
        self.tree.column("length", width=80, anchor=tk.W)
        self.tree.column("time", width=100, anchor=tk.W)
        self.tree.column("url", width=500, anchor=tk.W)
        self.tree.column("desc", width=400, anchor=tk.W)

        self.tree.pack(fill=tk.BOTH, expand=True)

        filter_frame = ttk.Frame(table_frame)
        filter_frame.pack(fill=tk.X)
        ttk.Label(filter_frame, text="Filter status (e.g. 200)").pack(side=tk.LEFT, padx=4)
        self.entry_filter_status = ttk.Entry(filter_frame, width=8)
        self.entry_filter_status.pack(side=tk.LEFT, padx=4)
        ttk.Button(filter_frame, text="Apply Filter", command=self.apply_filter).pack(side=tk.LEFT, padx=4)
        ttk.Button(filter_frame, text="Clear Filter", command=self.clear_filter).pack(side=tk.LEFT, padx=4)

    def _parse_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        raw = self.text_headers.get("1.0", tk.END).strip()
        for line in raw.splitlines():
            if not line.strip():
                continue
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
        return headers

    def _parse_query_payloads(self) -> List[str]:
        raw = self.text_queries.get("1.0", tk.END).strip()
        payloads = [line.strip() for line in raw.splitlines() if line.strip()]
        return payloads

    def start_scan(self) -> None:
        url = self.entry_url.get().strip()
        if not url:
            messagebox.showerror("Error", "Target URL is required.")
            return

        proxies = None
        proxy_val = self.entry_proxy.get().strip()
        if proxy_val:
            proxies = {"http": proxy_val, "https": proxy_val}

        config = ScanConfig(
            target_url=url,
            headers=self._parse_headers(),
            proxies=proxies,
            timeout_seconds=float(self.spin_timeout.get()),
            max_workers=int(self.spin_threads.get()),
            delay_between_requests_ms=int(self.spin_delay.get()),
            include_non_idempotent=self.var_methods_all.get(),
            query_payloads=self._parse_query_payloads(),
            user_agent=self.entry_ua.get().strip() or None,
            cookies=self.entry_cookies.get().strip() or None,
        )

        self._scanner = Scanner(config)
        self._results = []
        for i in self.tree.get_children():
            self.tree.delete(i)

        self.btn_start.configure(state=tk.DISABLED)
        self.btn_stop.configure(state=tk.NORMAL)

        def worker() -> None:
            assert self._scanner is not None
            try:
                for res in self._scanner.run():
                    row = {
                        "method": res.method,
                        "status": res.status_code,
                        "length": res.content_length,
                        "time": res.elapsed_ms,
                        "url": res.url,
                        "desc": res.description,
                    }
                    self._results.append(row)
                    self.tree.insert(
                        "",
                        tk.END,
                        values=(
                            row["method"],
                            row["status"],
                            row["length"],
                            row["time"],
                            row["url"],
                            row["desc"],
                        ),
                    )
            finally:
                self.btn_start.configure(state=tk.NORMAL)
                self.btn_stop.configure(state=tk.DISABLED)

        self._scanner_thread = threading.Thread(target=worker, daemon=True)
        self._scanner_thread.start()

    def stop_scan(self) -> None:
        if self._scanner:
            self._scanner.stop()

    def export_results(self, fmt: str) -> None:
        if not self._results:
            messagebox.showinfo("Info", "No results to export.")
            return
        if fmt == "csv":
            path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", ".csv")])
            if not path:
                return
            import csv

            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f, fieldnames=["method", "status", "length", "time", "url", "desc"]
                )
                writer.writeheader()
                writer.writerows(self._results)
        elif fmt == "json":
            path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", ".json")])
            if not path:
                return
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._results, f, ensure_ascii=False, indent=2)
        else:
            messagebox.showerror("Error", f"Unknown export format: {fmt}")

    def apply_filter(self) -> None:
        value = self.entry_filter_status.get().strip()
        for i in self.tree.get_children():
            self.tree.delete(i)
        if not value:
            for row in self._results:
                self.tree.insert(
                    "",
                    tk.END,
                    values=(
                        row["method"],
                        row["status"],
                        row["length"],
                        row["time"],
                        row["url"],
                        row["desc"],
                    ),
                )
            return
        try:
            status = int(value)
        except ValueError:
            messagebox.showerror("Error", "Status must be an integer.")
            return
        for row in self._results:
            if row["status"] == status:
                self.tree.insert(
                    "",
                    tk.END,
                    values=(
                        row["method"],
                        row["status"],
                        row["length"],
                        row["time"],
                        row["url"],
                        row["desc"],
                    ),
                )

    def clear_filter(self) -> None:
        self.entry_filter_status.delete(0, tk.END)
        self.apply_filter()


def main() -> None:
    app = BypassGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
