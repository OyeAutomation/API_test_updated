from __future__ import annotations
import json
import logging
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from pathlib import Path
from typing import Optional

from src.models import Settings, TestResult
from src.curl_parser import parse_curl
from src.test_engine import run_suite
from src.report_generator import generate_report


class APITestGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("API Security & Validation Testing Framework")
        self.root.geometry("850x700")

        # Style
        style = ttk.Style()
        available = style.theme_names()
        if "clam" in available:
            style.theme_use("clam")

        self._cancel_event = threading.Event()

        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Vertical paned window for resizable log
        paned = ttk.PanedWindow(main_frame, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)

        top_frame = ttk.Frame(paned)
        paned.add(top_frame, weight=0)

        # Title
        title = ttk.Label(top_frame, text="API Test Suite", font=("Segoe UI", 16, "bold"))
        title.pack(anchor=tk.W, pady=(0, 10))

        # --- Curl input ---
        curl_frame = ttk.LabelFrame(top_frame, text="Curl Command", padding="5")
        curl_frame.pack(fill=tk.X, pady=5)

        self.curl_mode = tk.StringVar(value="single")
        mode_row = ttk.Frame(curl_frame)
        mode_row.pack(fill=tk.X, pady=(0, 3))
        ttk.Radiobutton(mode_row, text="Single curl", variable=self.curl_mode, value="single", command=self._toggle_curl_mode).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(mode_row, text="Batch (directory)", variable=self.curl_mode, value="batch", command=self._toggle_curl_mode).pack(side=tk.LEFT)

        self.curl_single_frame = ttk.Frame(curl_frame)
        self.curl_single_frame.pack(fill=tk.X)
        curl_row = ttk.Frame(self.curl_single_frame)
        curl_row.pack(fill=tk.X)
        self.curl_text = scrolledtext.ScrolledText(curl_row, height=5, wrap=tk.WORD, font=("Consolas", 9))
        self.curl_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        curl_btn_frame = ttk.Frame(curl_row)
        curl_btn_frame.pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(curl_btn_frame, text="Browse...", command=self._browse_curl).pack(fill=tk.X, pady=2)
        ttk.Button(curl_btn_frame, text="Reset", command=self._reset_curl).pack(fill=tk.X, pady=2)
        ttk.Button(curl_btn_frame, text="Validate", command=self._validate_curl).pack(fill=tk.X, pady=2)

        self.curl_batch_frame = ttk.Frame(curl_frame)
        self.curl_batch_frame.pack(fill=tk.X)
        batch_row = ttk.Frame(self.curl_batch_frame)
        batch_row.pack(fill=tk.X)
        ttk.Label(batch_row, text="Curl Directory:").pack(side=tk.LEFT)
        self.curl_dir_var = tk.StringVar()
        ttk.Entry(batch_row, textvariable=self.curl_dir_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 5))
        ttk.Button(batch_row, text="Browse Dir...", command=self._browse_curl_dir).pack(side=tk.LEFT)
        self.batch_file_count = ttk.Label(batch_row, text="")
        self.batch_file_count.pack(side=tk.LEFT, padx=(10, 0))
        self.curl_batch_frame.pack_forget()

        # --- Files frame ---
        files_frame = ttk.LabelFrame(top_frame, text="Configuration Files", padding="5")
        files_frame.pack(fill=tk.X, pady=5)

        def make_file_row(parent, label, default=""):
            row = ttk.Frame(parent)
            row.pack(fill=tk.X, pady=2)
            ttk.Label(row, text=label, width=18, anchor=tk.W).pack(side=tk.LEFT)
            var = tk.StringVar(value=default)
            entry = ttk.Entry(row, textvariable=var)
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
            return var, entry

        self.crypto_file_var, _ = make_file_row(files_frame, "Crypto Profile:")
        crypto_btn_frame = ttk.Frame(files_frame)
        crypto_btn_frame.pack(fill=tk.X, pady=2)
        ttk.Label(crypto_btn_frame, text="", width=18, anchor=tk.W).pack(side=tk.LEFT)
        ttk.Button(crypto_btn_frame, text="Browse Crypto...", command=lambda: self._browse_file(self.crypto_file_var)).pack(side=tk.LEFT)
        ttk.Label(crypto_btn_frame, text=" Profile Name:").pack(side=tk.LEFT, padx=(10, 0))
        self.profile_name_var = tk.StringVar(value="default")
        self.profile_name_entry = ttk.Entry(crypto_btn_frame, textvariable=self.profile_name_var, width=15)
        self.profile_name_entry.pack(side=tk.LEFT, padx=(5, 0))

        # Separate response decryption profile
        resp_frame = ttk.Frame(files_frame)
        resp_frame.pack(fill=tk.X, pady=2)
        ttk.Label(resp_frame, text="", width=18, anchor=tk.W).pack(side=tk.LEFT)
        self.use_response_profile_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(resp_frame, text="Separate response decryption profile",
                        variable=self.use_response_profile_var).pack(side=tk.LEFT)
        self.response_profile_name_var = tk.StringVar(value="cryptojs-response")
        self.response_profile_entry = ttk.Entry(resp_frame, textvariable=self.response_profile_name_var, width=15, state=tk.DISABLED)
        self.response_profile_entry.pack(side=tk.LEFT, padx=(10, 0))
        ttk.Label(resp_frame, text="(profile name)").pack(side=tk.LEFT, padx=(3, 0))
        self.use_response_profile_var.trace_add("write",
            lambda *a: self.response_profile_entry.config(
                state=tk.NORMAL if self.use_response_profile_var.get() else tk.DISABLED))

        # Benepik Insights split-GCM preset
        insights_frame = ttk.Frame(files_frame)
        insights_frame.pack(fill=tk.X, pady=2)
        ttk.Label(insights_frame, text="", width=18, anchor=tk.W).pack(side=tk.LEFT)
        self.insights_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(insights_frame, text="Benepik Insights split-GCM",
                        variable=self.insights_var).pack(side=tk.LEFT)
        ttk.Label(insights_frame, text="(data/nonce/tag wrapper, AES-128-GCM)").pack(side=tk.LEFT, padx=(3, 0))
        self.insights_var.trace_add("write", self._on_insights_toggle)

        # Test cases dir
        self.test_cases_var, _ = make_file_row(files_frame, "Test Cases:")
        ttk.Button(files_frame, text="Browse...", command=lambda: self._browse_file(self.test_cases_var)).pack(padx=(18, 0))

        # --- Output ---
        output_frame = ttk.LabelFrame(top_frame, text="Output", padding="5")
        output_frame.pack(fill=tk.X, pady=5)

        self.output_var = tk.StringVar(value="reports/report.xlsx")
        out_row = ttk.Frame(output_frame)
        out_row.pack(fill=tk.X)
        ttk.Label(out_row, text="Report Path:", width=18, anchor=tk.W).pack(side=tk.LEFT)
        ttk.Entry(out_row, textvariable=self.output_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(out_row, text="Browse...", command=lambda: self._browse_file(self.output_var, save=True)).pack(side=tk.LEFT)

        # --- Settings ---
        settings_frame = ttk.LabelFrame(top_frame, text="Settings", padding="5")
        settings_frame.pack(fill=tk.X, pady=5)

        delay_row = ttk.Frame(settings_frame)
        delay_row.pack(fill=tk.X)
        ttk.Label(delay_row, text="Delay (ms):").pack(side=tk.LEFT)
        self.delay_var = tk.IntVar(value=50)
        ttk.Spinbox(delay_row, from_=0, to=5000, textvariable=self.delay_var, width=8).pack(side=tk.LEFT, padx=(5, 20))
        ttk.Label(delay_row, text="Timeout (s):").pack(side=tk.LEFT, padx=(10, 0))
        self.timeout_var = tk.IntVar(value=30)
        ttk.Spinbox(delay_row, from_=1, to=300, textvariable=self.timeout_var, width=8).pack(side=tk.LEFT, padx=(5, 0))
        self.include_non_mandatory_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(delay_row, text="Include non-mandatory keys",
                        variable=self.include_non_mandatory_var).pack(side=tk.LEFT, padx=(20, 0))

        # --- Run / Cancel buttons ---
        action_frame = ttk.Frame(top_frame)
        action_frame.pack(fill=tk.X, pady=10)
        self.run_btn = ttk.Button(action_frame, text="Run Test Suite", command=self._run_tests)
        self.run_btn.pack(side=tk.LEFT, padx=(0, 10))
        self.cancel_btn = ttk.Button(action_frame, text="Cancel", command=self._cancel_tests, state=tk.DISABLED)
        self.cancel_btn.pack(side=tk.LEFT, padx=(0, 10))
        self.seed_btn = ttk.Button(action_frame, text="Seed Test Cases", command=self._seed_test_cases)
        self.seed_btn.pack(side=tk.LEFT, padx=(0, 10))
        self.status_label = ttk.Label(action_frame, text="Ready", font=("Segoe UI", 9, "italic"))
        self.status_label.pack(side=tk.LEFT, padx=(10, 0))

        progress_frame = ttk.Frame(top_frame)
        progress_frame.pack(fill=tk.X, pady=(0, 5))
        self.progress = ttk.Progressbar(progress_frame, mode="indeterminate")
        self.progress.pack(fill=tk.X)

        # --- Log output ---
        log_frame = ttk.LabelFrame(paned, text="Log", padding="5")
        paned.add(log_frame, weight=1)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=12, wrap=tk.WORD, font=("Consolas", 9), bg="#1e1e1e", fg="#d4d4d4")
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.insert(tk.END, "Ready. Paste a curl command and click Run.\n")
        self.log_text.see(tk.END)

        # Bind text color tags
        self.log_text.tag_configure("info", foreground="#d4d4d4")
        self.log_text.tag_configure("ok", foreground="#4ec94e")
        self.log_text.tag_configure("warn", foreground="#e6db74")
        self.log_text.tag_configure("error", foreground="#f44747")
        self.log_text.tag_configure("bold", font=("Consolas", 9, "bold"))

    def log(self, msg, tag="info"):
        self.log_text.insert(tk.END, msg + "\n", tag)
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def _browse_file(self, var, save=False):
        if save:
            path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel", "*.xlsx")])
        else:
            path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if path:
            var.set(path)

    def _toggle_curl_mode(self):
        if self.curl_mode.get() == "single":
            self.curl_single_frame.pack(fill=tk.X)
            self.curl_batch_frame.pack_forget()
        else:
            self.curl_single_frame.pack_forget()
            self.curl_batch_frame.pack(fill=tk.X)

    def _on_insights_toggle(self, *args):
        if self.insights_var.get():
            self._saved_profile_name = self.profile_name_var.get()
            self._saved_response_profile_name = self.response_profile_name_var.get()
            self.profile_name_var.set("insights-payload")
            self.use_response_profile_var.set(True)
            self.response_profile_name_var.set("insights-response")
            self.response_profile_entry.config(state=tk.DISABLED)
            self.profile_name_entry.config(state=tk.DISABLED)
        else:
            self.profile_name_var.set(getattr(self, "_saved_profile_name", "default"))
            self.response_profile_name_var.set(getattr(self, "_saved_response_profile_name", "cryptojs-response"))
            self.response_profile_entry.config(state=tk.NORMAL)
            self.profile_name_entry.config(state=tk.NORMAL)

    def _browse_curl_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.curl_dir_var.set(path)
            files = sorted(Path(path).glob("*.curl"))
            self.batch_file_count.config(text=f"{len(files)} .curl files found" if files else "No .curl files")

    def _browse_curl(self):
        path = filedialog.askopenfilename(filetypes=[("Curl files", "*.curl"), ("All files", "*.*")])
        if path:
            with open(path, "r", encoding="utf-8") as f:
                self.curl_text.delete("1.0", tk.END)
                self.curl_text.insert("1.0", f.read())

    def _reset_curl(self):
        self.curl_text.delete("1.0", tk.END)

    def _validate_curl(self):
        cmd = self.curl_text.get("1.0", tk.END).strip()
        if not cmd:
            messagebox.showwarning("No curl", "Enter a curl command first.")
            return
        try:
            parsed = parse_curl(cmd)
            info = (
                f"Method: {parsed.method.value}\n"
                f"URL: {parsed.url}\n"
                f"Headers: {json.dumps(parsed.headers, indent=2) if parsed.headers else '(none)'}\n"
                f"Body: {json.dumps(parsed.body_json, indent=2) if parsed.body_json else '(none)'}\n"
                f"Cookies: {json.dumps(parsed.cookies, indent=2) if parsed.cookies else '(none)'}"
            )
            messagebox.showinfo("Parsed Request", info)
        except Exception as e:
            messagebox.showerror("Parse Error", str(e))

    def _cancel_tests(self):
        self._cancel_event.set()
        self.log("Cancelling... (will stop after current request)", "warn")
        self.cancel_btn.config(state=tk.DISABLED)

    def _seed_test_cases(self):
        def task():
            self.run_btn.config(state=tk.DISABLED)
            self.seed_btn.config(state=tk.DISABLED)
            self.progress.start()
            self.status_label.config(text="Seeding test cases...")
            self.log("Seeding default test cases...", "info")
            try:
                from scripts.seed_test_cases import create_test_cases_xlsx
                output_path = Path(__file__).parent.parent / "test_cases" / "default_test_cases.xlsx"
                create_test_cases_xlsx(str(output_path))
                self.log("Done - test cases created.", "ok")
                messagebox.showinfo("Success", f"Created: {output_path}")
            except Exception as e:
                self.log(f"Error: {e}", "error")
                messagebox.showerror("Error", str(e))
            finally:
                self.progress.stop()
                self.status_label.config(text="Ready")
                self.run_btn.config(state=tk.NORMAL)
                self.seed_btn.config(state=tk.NORMAL)
        threading.Thread(target=task, daemon=True).start()

    def _run_tests(self):
        def task():
            self._cancel_event.clear()
            self.run_btn.config(state=tk.DISABLED)
            self.seed_btn.config(state=tk.DISABLED)
            self.cancel_btn.config(state=tk.NORMAL)
            self.progress.start()
            self.log("=" * 50, "bold")
            self.log("Starting test run...", "bold")
            self.status_label.config(text="Running...")

            try:
                # Load crypto profile
                crypto_config = None
                response_crypto_config = None
                crypto_path = self.crypto_file_var.get().strip()
                if crypto_path:
                    import yaml
                    from src.models import CryptoProfile
                    profile_name = self.profile_name_var.get().strip()
                    with open(crypto_path, "r", encoding="utf-8") as f:
                        config = yaml.safe_load(f)
                    profiles = config.get("profiles", [config])

                    def _find_profile(name):
                        for p in profiles:
                            if p.get("name") == name:
                                return p
                        return None

                    # Main profile for request payload
                    if profile_name:
                        crypto_config = _find_profile(profile_name)
                        if not crypto_config:
                            raise ValueError(f"Profile '{profile_name}' not found in {crypto_path}")
                    else:
                        raise ValueError("Enter a profile name for request payload encryption")

                    required = {"algorithm", "key"}
                    missing = required - set(crypto_config.keys())
                    if missing:
                        raise ValueError(
                            f"'{crypto_path}' profile '{profile_name}' is invalid "
                            f"(missing fields: {', '.join(sorted(missing))})."
                        )
                    CryptoProfile(**crypto_config)
                    self.log(f"  Payload profile: {crypto_config.get('algorithm', 'N/A')} ({profile_name})", "ok")

                    # Optional separate response decryption profile
                    if self.use_response_profile_var.get():
                        resp_name = self.response_profile_name_var.get().strip()
                        if resp_name:
                            response_crypto_config = _find_profile(resp_name)
                            if not response_crypto_config:
                                raise ValueError(f"Response profile '{resp_name}' not found in {crypto_path}")
                            CryptoProfile(**response_crypto_config)
                            self.log(f"  Response profile: {response_crypto_config.get('algorithm', 'N/A')} ({resp_name})", "ok")

                # Resolve test cases
                test_cases_path = self.test_cases_var.get().strip()
                if not test_cases_path:
                    default = Path(__file__).parent.parent / "test_cases" / "default_test_cases.xlsx"
                    if default.exists():
                        test_cases_path = str(default)
                        self.log(f"  Using default test cases: {default}", "info")

                settings = Settings(
                    request_delay_ms=self.delay_var.get(),
                    timeout_seconds=self.timeout_var.get(),
                    include_non_mandatory=self.include_non_mandatory_var.get(),
                )

                all_results = []
                count = 0

                if self.curl_mode.get() == "batch":
                    # Batch mode
                    curl_dir = self.curl_dir_var.get().strip()
                    if not curl_dir:
                        raise ValueError("Select a curl directory for batch mode.")
                    curl_files = sorted(Path(curl_dir).glob("*.curl"))
                    if not curl_files:
                        raise ValueError(f"No .curl files found in {curl_dir}")
                    self.log(f"Batch mode: {len(curl_files)} curl files", "bold")
                    output_dir = Path(self.output_var.get().strip() or "reports")
                    output_dir.mkdir(parents=True, exist_ok=True)
                    for cf in curl_files:
                        if self._cancel_event.is_set():
                            self.log("  Batch cancelled", "warn")
                            break
                        cmd = cf.read_text(encoding="utf-8").strip()
                        if not cmd:
                            continue
                        count += 1
                        self.log(f"  [{count}/{len(curl_files)}] Processing: {cf.name}", "info")
                        try:
                            parsed = parse_curl(cmd)
                            self.log(f"    API: {parsed.method} {parsed.url}", "ok")
                            if not parsed.body_json:
                                self.log(f"    No JSON body — header/global tests only", "warn")
                            results = run_suite(cmd, crypto_config, test_cases_path, settings, self._cancel_event,
                                                response_crypto_config=response_crypto_config)
                            # Generate individual report per curl file
                            grouped = {parsed.url: results}
                            report_path = output_dir / f"{cf.stem}.xlsx"
                            generate_report(grouped, str(report_path))
                            self.log(f"    -> {len(results)} tests -> {report_path.name}", "ok")
                            all_results.extend(results)
                        except Exception as e:
                            self.log(f"    FAILED: {e}", "error")
                else:
                    # Single mode
                    curl_command = self.curl_text.get("1.0", tk.END).strip()
                    if not curl_command:
                        raise ValueError("Enter a curl command or switch to batch mode.")
                    self.log("Parsing curl command...", "info")
                    parsed = parse_curl(curl_command)
                    self.log(f"  API: {parsed.method} {parsed.url}", "ok")
                    if not parsed.body_json:
                        self.log(f"  No JSON body — only header/global tests will run", "warn")
                    self.log("Running test suite...", "bold")
                    all_results = run_suite(curl_command, crypto_config, test_cases_path, settings, self._cancel_event,
                                            response_crypto_config=response_crypto_config)

                # Group & generate combined report (single mode only)
                if self.curl_mode.get() != "batch":
                    grouped = {}
                    for r in all_results:
                        grouped.setdefault(r.api, []).append(r)
                    output_path = self.output_var.get().strip() or "reports/report.xlsx"
                    self.log(f"Generating report: {output_path}", "info")
                    generate_report(grouped, output_path)
                    self.log(f"Report written to {output_path}", "ok")
                    output_str = output_path
                else:
                    output_str = str(output_dir)
                    self.log(f"Reports written to {output_str}/", "ok")

                # Summary
                total = len(all_results)
                vuln_accepted = sum(
                    1 for r in all_results
                    if r.test_case_type == "Vulnerability" and 0 < r.status_code < 400
                )
                errors = sum(1 for r in all_results if r.test_case_type == "Error")

                self.log("", "info")
                self.log(f"Results: {total} total", "bold")
                if vuln_accepted:
                    self.log(f"  {vuln_accepted} vulnerabilities accepted (check report!)", "warn")
                else:
                    self.log(f"  0 vulnerabilities accepted", "ok")
                self.log(f"  {errors} errors", "warn" if errors else "info")

                self.status_label.config(text=f"Done - {total} tests")
                batch_note = f"\nReports: {output_str}" if self.curl_mode.get() == "batch" else ""
                messagebox.showinfo("Complete", f"{total} tests, {vuln_accepted} vulns accepted, {errors} errors{batch_note}")

            except Exception as e:
                self.log(f"ERROR: {e}", "error")
                self.status_label.config(text="Failed")
                messagebox.showerror("Error", str(e))
            finally:
                self._cancel_event.clear()
                self.progress.stop()
                self.cancel_btn.config(state=tk.DISABLED)
                self.run_btn.config(state=tk.NORMAL)
                self.seed_btn.config(state=tk.NORMAL)

        threading.Thread(target=task, daemon=True).start()

    def run(self):
        self.root.mainloop()


def main():
    app = APITestGUI()
    app.run()


if __name__ == "__main__":
    main()
