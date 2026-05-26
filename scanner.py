import socket
import random
import json
import os
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    import winsound
except ImportError:
    winsound = None

from framework_mapper import calculate_risk_level, map_findings
from pentest_module import run_pentest_simulation
from port_scanner import scan_ports
from report_generator import (
    create_scan_record,
    generate_text_report,
    save_json_report,
    save_text_report,
)
from vulnerability_scanner import normalize_host, run_vulnerability_scan


COLORS = {
    "bg": "#020617",
    "panel": "#071426",
    "panel_alt": "#0b1f33",
    "primary": "#0891b2",
    "primary_dark": "#0e7490",
    "accent": "#38bdf8",
    "text": "#e5f4ff",
    "muted": "#9fb4c7",
    "border": "#1e3a56",
    "high": "#ff6b6b",
    "medium": "#fbbf24",
    "low": "#34d399",
}


HISTORY_FILE = "scan_history.json"


class StarBackground:
    """Animated starfield for the scanner background."""

    def __init__(self, root, star_count=120):
        self.root = root
        self.star_count = star_count
        self.canvas = tk.Canvas(root, bg=COLORS["bg"], highlightthickness=0)
        self.canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self.stars = []
        self.root.bind("<Configure>", self._reset_stars)
        self._reset_stars()
        self.animate()

    def _reset_stars(self, event=None):
        width = max(self.root.winfo_width(), 900)
        height = max(self.root.winfo_height(), 620)
        self.canvas.delete("star")
        self.stars = []

        for _ in range(self.star_count):
            size = random.choice([1, 1, 2, 2, 3])
            brightness = random.randint(80, 210)
            star = {
                "x": random.randint(0, width),
                "y": random.randint(0, height),
                "size": size,
                "brightness": brightness,
                "direction": random.choice([-1, 1]),
                "speed": random.uniform(4, 11),
                "drift": random.uniform(0.05, 0.28),
            }
            star["id"] = self.canvas.create_oval(
                star["x"],
                star["y"],
                star["x"] + size,
                star["y"] + size,
                fill=self._star_color(brightness),
                outline="",
                tags="star",
            )
            self.stars.append(star)

    def _star_color(self, brightness):
        brightness = max(40, min(255, int(brightness)))
        blue = min(255, brightness + 30)
        return "#%02x%02x%02x" % (brightness, brightness, blue)

    def animate(self):
        width = max(self.root.winfo_width(), 900)
        for star in self.stars:
            star["brightness"] += star["direction"] * star["speed"]
            if star["brightness"] >= 245:
                star["brightness"] = 245
                star["direction"] = -1
            elif star["brightness"] <= 45:
                star["brightness"] = 45
                star["direction"] = 1

            self.canvas.move(star["id"], star["drift"], 0)
            coords = self.canvas.coords(star["id"])
            if coords and coords[0] > width:
                self.canvas.move(star["id"], -width - 8, 0)

            x, y = self.canvas.coords(star["id"])[:2]
            glow_size = star["size"] + (1 if star["brightness"] > 190 else 0)
            self.canvas.coords(star["id"], x, y, x + glow_size, y + glow_size)
            self.canvas.itemconfig(star["id"], fill=self._star_color(star["brightness"]))

        self.root.after(80, self.animate)


class CyberScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Cyber Security Scanner")
        self.root.geometry("1020x720")
        self.root.minsize(900, 620)
        self.root.configure(bg=COLORS["bg"])
        self.star_background = StarBackground(self.root)

        self.scan_data = None
        self.scan_thread = None
        self.history = self.load_history()
        self.risk_animation_job = None
        self.risk_pulse_step = 0
        self.risk_meter_job = None
        self.risk_meter_value = 0
        self.risk_meter_target = 0
        self.title_animation_job = None
        self.title_animation_step = 0

        self._build_styles()
        self._build_layout()

    def _build_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Primary.TButton",
            background=COLORS["primary"],
            foreground="#ffffff",
            borderwidth=0,
            padding=(14, 9),
            font=("Segoe UI", 10, "bold"),
        )
        style.map("Primary.TButton", background=[("active", COLORS["primary_dark"])])
        style.configure(
            "Secondary.TButton",
            background="#102b44",
            foreground=COLORS["text"],
            borderwidth=0,
            padding=(14, 9),
            font=("Segoe UI", 10, "bold"),
        )
        style.map("Secondary.TButton", background=[("active", "#163a5c")])
        style.configure(
            "TEntry",
            padding=8,
            fieldbackground="#eaf6ff",
            foreground="#071426",
            insertcolor=COLORS["primary_dark"],
        )

    def _build_layout(self):
        header = tk.Frame(self.root, bg="#061d31", height=96, highlightbackground=COLORS["border"], highlightthickness=1)
        header.pack(fill="x")
        header.pack_propagate(False)

        self.title_canvas = tk.Canvas(
            header,
            bg="#061d31",
            width=780,
            height=54,
            highlightthickness=0,
        )
        self.title_canvas.pack(anchor="w", padx=28, pady=(8, 0))
        self.animate_project_title()

        tk.Label(
            header,
            text="Vulnerability Assessment | Pentesting Simulation | Audit Report | Framework Mapping",
            bg="#061d31",
            fg="#a7e7ff",
            font=("Segoe UI", 10),
        ).pack(anchor="w", padx=30, pady=(4, 0))

        main = tk.Frame(self.root, bg=COLORS["bg"])
        main.pack(fill="both", expand=True, padx=22, pady=18)
        self.body_stars = StarBackground(main, star_count=90)

        controls = tk.Frame(main, bg=COLORS["panel"], highlightbackground=COLORS["border"], highlightthickness=1)
        controls.pack(fill="x")

        tk.Label(
            controls,
            text="Target Host or URL",
            bg=COLORS["panel"],
            fg=COLORS["text"],
            font=("Segoe UI", 11, "bold"),
        ).grid(row=0, column=0, sticky="w", padx=18, pady=(16, 4))

        self.target_var = tk.StringVar(value="example.com")
        self.target_entry = ttk.Entry(controls, textvariable=self.target_var, font=("Segoe UI", 11))
        self.target_entry.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 16))

        self.scan_button = ttk.Button(
            controls,
            text="Start Scan",
            style="Primary.TButton",
            command=self.start_scan,
        )
        self.scan_button.grid(row=1, column=1, padx=(0, 10), pady=(0, 16))

        self.download_button = ttk.Button(
            controls,
            text="Download Report",
            style="Secondary.TButton",
            command=self.download_report,
            state="disabled",
        )
        self.download_button.grid(row=1, column=2, padx=(0, 10), pady=(0, 16))

        self.json_button = ttk.Button(
            controls,
            text="Export JSON",
            style="Secondary.TButton",
            command=self.export_json,
            state="disabled",
        )
        self.json_button.grid(row=1, column=3, padx=(0, 18), pady=(0, 16))

        self.history_button = ttk.Button(
            controls,
            text=self.history_button_text(),
            style="Secondary.TButton",
            command=self.show_history,
        )
        self.history_button.grid(row=1, column=4, padx=(0, 18), pady=(0, 16))

        controls.columnconfigure(0, weight=1)

        checklist = tk.Frame(main, bg=COLORS["panel_alt"], highlightbackground=COLORS["border"], highlightthickness=1)
        checklist.pack(fill="x", pady=(14, 14))

        tk.Label(
            checklist,
            text="Projects to Complete",
            bg=COLORS["panel_alt"],
            fg=COLORS["text"],
            font=("Segoe UI", 10, "bold"),
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 8))

        items = [
            ("Security Audit Report", 0, 0),
            ("Vulnerability Assessment", 0, 1),
            ("Penetration Test", 1, 0),
            ("Security Framework", 1, 1),
        ]
        for label, row, col in items:
            tk.Label(
                checklist,
                text="[OK]  " + label,
                bg=COLORS["panel_alt"],
                fg=COLORS["accent"],
                font=("Segoe UI", 10),
            ).grid(row=row + 1, column=col, sticky="w", padx=16, pady=(0, 8))

        checklist.columnconfigure(0, weight=1)
        checklist.columnconfigure(1, weight=1)

        self.risk_meter_frame = tk.Frame(
            main,
            bg="#04111f",
            highlightbackground=COLORS["border"],
            highlightthickness=1,
            height=112,
        )
        self.risk_meter_frame.pack(fill="x", pady=(0, 14))
        self.risk_meter_frame.pack_propagate(False)

        self.risk_percent_var = tk.StringVar(value="0%")
        self.risk_percent_label = tk.Label(
            self.risk_meter_frame,
            textvariable=self.risk_percent_var,
            bg="#04111f",
            fg=COLORS["accent"],
            font=("Segoe UI", 38, "bold"),
        )
        self.risk_percent_label.pack(side="left", padx=(26, 12), pady=12)

        self.risk_word_canvas = tk.Canvas(
            self.risk_meter_frame,
            bg="#04111f",
            width=360,
            height=96,
            highlightthickness=0,
        )
        self.risk_word_canvas.pack(side="left", padx=12, pady=8)
        self.draw_animated_risk_word("Risk", COLORS["accent"], 0, "#04111f")

        self.risk_detail_var = tk.StringVar(value="Run a scan to calculate risk intensity")
        tk.Label(
            self.risk_meter_frame,
            textvariable=self.risk_detail_var,
            bg="#04111f",
            fg=COLORS["muted"],
            font=("Segoe UI", 10, "bold"),
        ).pack(side="right", padx=24)

        status_row = tk.Frame(main, bg=COLORS["bg"])
        status_row.pack(fill="x", pady=(0, 8))

        self.status_var = tk.StringVar(value="[INFO] Ready to scan.")
        tk.Label(
            status_row,
            textvariable=self.status_var,
            bg=COLORS["bg"],
            fg=COLORS["muted"],
            font=("Segoe UI", 10, "bold"),
        ).pack(side="left")

        self.risk_animation_var = tk.StringVar(value="")
        self.risk_animation_label = tk.Label(
            status_row,
            textvariable=self.risk_animation_var,
            bg=COLORS["bg"],
            fg=COLORS["accent"],
            font=("Segoe UI", 14, "bold"),
        )
        self.risk_animation_label.pack(side="left", padx=24)

        self.risk_var = tk.StringVar(value="Risk: N/A")
        self.risk_label = tk.Label(
            status_row,
            textvariable=self.risk_var,
            bg=COLORS["bg"],
            fg=COLORS["muted"],
            font=("Segoe UI", 10, "bold"),
        )
        self.risk_label.pack(side="right")

        result_frame = tk.Frame(main, bg=COLORS["panel"], highlightbackground=COLORS["border"], highlightthickness=1)
        result_frame.pack(fill="both", expand=True)

        self.results_text = tk.Text(
            result_frame,
            wrap="word",
            bg="#030b16",
            fg=COLORS["text"],
            insertbackground=COLORS["accent"],
            relief="flat",
            padx=14,
            pady=12,
            font=("Consolas", 10),
        )
        self.results_text.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(result_frame, command=self.results_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.results_text.configure(yscrollcommand=scrollbar.set)

        self._configure_text_tags()

    def load_history(self):
        if not os.path.exists(HISTORY_FILE):
            return []

        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as history_file:
                history = json.load(history_file)
            if isinstance(history, list):
                return history
        except (OSError, json.JSONDecodeError):
            return []

        return []

    def save_history(self):
        with open(HISTORY_FILE, "w", encoding="utf-8") as history_file:
            json.dump(self.history, history_file, indent=2)

    def history_button_text(self):
        return "History (%s)" % len(self.history)

    def add_scan_to_history(self):
        if not self.scan_data:
            return

        port_scan = self.scan_data.get("port_scan", {})
        entry = {
            "timestamp": self.scan_data.get("timestamp", ""),
            "target": self.scan_data.get("target", ""),
            "ip": port_scan.get("ip") or "N/A",
            "risk_level": self.scan_data.get("risk_level", "LOW"),
            "open_ports": [item.get("port") for item in port_scan.get("open_ports", [])],
            "vulnerability_count": len(self.scan_data.get("vulnerabilities", [])),
            "pentest_count": len(self.scan_data.get("pentest_results", [])),
        }

        self.history.append(entry)
        self.save_history()
        self.history_button.configure(text=self.history_button_text())

    def show_history(self):
        history_window = tk.Toplevel(self.root)
        history_window.title("Scan History")
        history_window.geometry("860x430")
        history_window.configure(bg=COLORS["bg"])

        unique_targets = sorted({item.get("target", "") for item in self.history if item.get("target")})

        tk.Label(
            history_window,
            text="Scan History",
            bg=COLORS["bg"],
            fg=COLORS["text"],
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor="w", padx=18, pady=(16, 4))

        tk.Label(
            history_window,
            text="Total scans: %s    Unique URLs tested: %s" % (len(self.history), len(unique_targets)),
            bg=COLORS["bg"],
            fg=COLORS["accent"],
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w", padx=18, pady=(0, 12))

        table_frame = tk.Frame(history_window, bg=COLORS["panel"], highlightbackground=COLORS["border"], highlightthickness=1)
        table_frame.pack(fill="both", expand=True, padx=18, pady=(0, 16))

        columns = ("time", "target", "risk", "ports", "findings")
        tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=12)
        tree.heading("time", text="Time")
        tree.heading("target", text="Target URL")
        tree.heading("risk", text="Risk")
        tree.heading("ports", text="Open Ports")
        tree.heading("findings", text="Findings")

        tree.column("time", width=140, anchor="w")
        tree.column("target", width=360, anchor="w")
        tree.column("risk", width=80, anchor="center")
        tree.column("ports", width=110, anchor="center")
        tree.column("findings", width=80, anchor="center")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        for entry in reversed(self.history):
            ports = entry.get("open_ports", [])
            tree.insert(
                "",
                "end",
                values=(
                    entry.get("timestamp", ""),
                    entry.get("target", ""),
                    entry.get("risk_level", ""),
                    ", ".join(str(port) for port in ports) if ports else "None",
                    entry.get("vulnerability_count", 0),
                ),
            )

        action_row = tk.Frame(history_window, bg=COLORS["bg"])
        action_row.pack(fill="x", padx=18, pady=(0, 16))

        ttk.Button(
            action_row,
            text="Close",
            style="Secondary.TButton",
            command=history_window.destroy,
        ).pack(side="right")

    def _configure_text_tags(self):
        self.results_text.tag_configure("HIGH", foreground=COLORS["high"], font=("Consolas", 10, "bold"))
        self.results_text.tag_configure("MEDIUM", foreground=COLORS["medium"], font=("Consolas", 10, "bold"))
        self.results_text.tag_configure("LOW", foreground=COLORS["low"], font=("Consolas", 10, "bold"))
        self.results_text.tag_configure("INFO", foreground=COLORS["primary_dark"])
        self.results_text.tag_configure("ERROR", foreground=COLORS["high"], font=("Consolas", 10, "bold"))

    def _append_result(self, text):
        tag = None
        if "[HIGH RISK]" in text or "[HIGH]" in text:
            tag = "HIGH"
        elif "[MEDIUM RISK]" in text or "[MEDIUM]" in text:
            tag = "MEDIUM"
        elif "[LOW RISK]" in text or "[LOW]" in text:
            tag = "LOW"
        elif "[ERROR]" in text:
            tag = "ERROR"
        elif "[INFO]" in text or "[OPEN]" in text or "[WARNING]" in text:
            tag = "INFO"

        self.results_text.insert("end", text + "\n", tag)
        self.results_text.see("end")

    def reset_risk_animation(self):
        if self.risk_animation_job:
            self.root.after_cancel(self.risk_animation_job)
            self.risk_animation_job = None
        if self.risk_meter_job:
            self.root.after_cancel(self.risk_meter_job)
            self.risk_meter_job = None
        self.risk_animation_var.set("")
        self.risk_pulse_step = 0
        self.risk_meter_value = 0
        self.risk_meter_target = 0
        self.risk_percent_var.set("0%")
        self.risk_detail_var.set("Scanning target...")
        self.risk_meter_frame.configure(bg="#04111f", highlightbackground=COLORS["border"])
        self.risk_percent_label.configure(bg="#04111f", fg=COLORS["accent"])
        self.risk_word_canvas.configure(bg="#04111f")
        self.draw_animated_risk_word("Risk", COLORS["accent"], 0, "#04111f")

    def get_visual_risk(self):
        if not self.scan_data:
            return "LOW"

        has_open_ports = bool(self.scan_data.get("port_scan", {}).get("open_ports", []))
        has_vulnerabilities = bool(self.scan_data.get("vulnerabilities", []))
        has_pentest_warning = any(
            item.get("possible_vulnerability") for item in self.scan_data.get("pentest_results", [])
        )

        if not has_open_ports and not has_vulnerabilities and not has_pentest_warning:
            return "NO RISK"
        return self.scan_data.get("risk_level", "LOW")

    def risk_percent_for(self, visual_risk):
        values = {
            "HIGH": 100,
            "MEDIUM": 60,
            "LOW": 25,
            "NO RISK": 0,
        }
        return values.get(visual_risk, 25)

    def play_risk_sound(self, visual_risk):
        if winsound is None:
            self.root.bell()
            return

        sounds = {
            "HIGH": winsound.MB_ICONHAND,
            "MEDIUM": winsound.MB_ICONEXCLAMATION,
            "LOW": winsound.MB_ICONASTERISK,
            "NO RISK": winsound.MB_OK,
        }
        winsound.MessageBeep(sounds.get(visual_risk, winsound.MB_OK))
        if visual_risk == "MEDIUM":
            self.root.after(180, lambda: winsound.MessageBeep(winsound.MB_ICONEXCLAMATION))

    def speak_risk_message(self, visual_risk):
        messages = {
            "HIGH": "There is a high risk.",
            "MEDIUM": "There is a medium risk.",
            "LOW": "There is a low risk.",
            "NO RISK": "There is no risk.",
        }
        message = messages.get(visual_risk, "Scan completed.")

        def speak():
            command = (
                "Add-Type -AssemblyName System.Speech; "
                "$speaker = New-Object System.Speech.Synthesis.SpeechSynthesizer; "
                "$speaker.Rate = 0; "
                "$speaker.Volume = 100; "
                "$speaker.Speak('%s');"
            ) % message.replace("'", "''")

            try:
                subprocess.Popen(
                    ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", command],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            except (OSError, AttributeError):
                self.root.bell()

        threading.Thread(target=speak, daemon=True).start()

    def start_risk_animation(self, visual_risk):
        self.reset_risk_animation()

        styles = {
            "HIGH": {"text": "⚠️ HIGH RISK", "color": COLORS["high"]},
            "MEDIUM": {"text": "❕❗ MEDIUM RISK", "color": COLORS["medium"]},
            "LOW": {"text": "✅ LOW RISK", "color": COLORS["low"]},
            "NO RISK": {"text": "💫 NO RISK", "color": COLORS["accent"]},
        }
        style = styles.get(visual_risk, styles["LOW"])
        self.risk_animation_label.configure(fg=style["color"])
        self.play_risk_sound(visual_risk)
        self.speak_risk_message(visual_risk)
        self._pulse_risk_indicator(style["text"])
        self.start_risk_meter(visual_risk)

    def _pulse_risk_indicator(self, text):
        frames = [text, "  " + text + "  ", "    " + text + "    ", "  " + text + "  "]
        self.risk_animation_var.set(frames[self.risk_pulse_step % len(frames)])
        self.risk_pulse_step += 1
        self.risk_animation_job = self.root.after(260, lambda: self._pulse_risk_indicator(text))

    def draw_animated_risk_word(self, word, base_color, frame, bg_color):
        self.risk_word_canvas.delete("risk_word")
        self.risk_word_canvas.configure(bg=bg_color)

        palettes = {
            "HIGH": ["#ff3b30", "#ff7a18", "#ffd166", "#ffffff"],
            "MEDIUM": ["#ffcf33", "#ff9f1c", "#ffee99", "#ffffff"],
            "LOW": ["#2dd4bf", "#22c55e", "#a7f3d0", "#ffffff"],
            "NO": ["#38bdf8", "#a78bfa", "#f0abfc", "#ffffff"],
        }
        if base_color == COLORS["high"]:
            palette = palettes["HIGH"]
        elif base_color == COLORS["medium"]:
            palette = palettes["MEDIUM"]
        elif base_color == COLORS["low"]:
            palette = palettes["LOW"]
        else:
            palette = palettes["NO"]

        letters = list(word.upper())
        font_size = 42 if len(letters) <= 5 else 34
        start_x = 18
        gap = 36 if font_size == 42 else 30
        y_base = 50

        for index, letter in enumerate(letters):
            x = start_x + (index * gap)
            y = y_base + (4 if (frame + index) % 2 == 0 else -3)
            fill = palette[(frame + index) % len(palette)]

            if letter == " ":
                continue

            # Draw a thick black shadow first, then the bright animated letter.
            for dx, dy in [(-3, 0), (3, 0), (0, -3), (0, 3), (-2, -2), (2, 2)]:
                self.risk_word_canvas.create_text(
                    x + dx,
                    y + dy,
                    text=letter,
                    fill="#020617",
                    font=("Segoe UI", font_size, "bold"),
                    anchor="center",
                    tags="risk_word",
                )

            self.risk_word_canvas.create_text(
                x,
                y,
                text=letter,
                fill=fill,
                font=("Segoe UI", font_size, "bold"),
                anchor="center",
                tags="risk_word",
            )

            self.risk_word_canvas.create_text(
                x,
                y + font_size - 8,
                text="_",
                fill=fill,
                font=("Segoe UI", font_size, "bold"),
                anchor="center",
                tags="risk_word",
            )

    def animate_project_title(self):
        phrase = "Advanced Cyber Security Scanner"
        palette = ["#facc15", "#a3e635", "#34d399", "#38bdf8", "#818cf8", "#c084fc"]
        self.title_canvas.delete("title_word")

        x = 18
        y_base = 30
        for index, letter in enumerate(phrase):
            if letter == " ":
                x += 14
                continue

            y = y_base + (2 if (self.title_animation_step + index) % 2 == 0 else -2)
            fill = palette[(self.title_animation_step + index) % len(palette)]

            for dx, dy in [(-2, 0), (2, 0), (0, -2), (0, 2), (-1, -1), (1, 1)]:
                self.title_canvas.create_text(
                    x + dx,
                    y + dy,
                    text=letter,
                    fill="#020617",
                    font=("Segoe UI", 24, "bold"),
                    anchor="center",
                    tags="title_word",
                )

            self.title_canvas.create_text(
                x,
                y,
                text=letter,
                fill=fill,
                font=("Segoe UI", 24, "bold"),
                anchor="center",
                tags="title_word",
            )
            x += 19

        self.title_animation_step += 1
        self.title_animation_job = self.root.after(240, self.animate_project_title)

    def start_risk_meter(self, visual_risk):
        colors = {
            "HIGH": COLORS["high"],
            "MEDIUM": COLORS["medium"],
            "LOW": COLORS["low"],
            "NO RISK": COLORS["accent"],
        }
        descriptions = {
            "HIGH": "Critical attention needed",
            "MEDIUM": "Review recommended",
            "LOW": "Minor hardening suggested",
            "NO RISK": "No configured issue detected",
        }

        self.risk_meter_target = self.risk_percent_for(visual_risk)
        self.risk_meter_value = 0
        color = colors.get(visual_risk, COLORS["accent"])
        self.risk_detail_var.set(descriptions.get(visual_risk, "Risk calculated"))
        self.risk_percent_label.configure(fg=color)
        self.risk_meter_frame.configure(highlightbackground=color)
        self._animate_risk_meter(color, visual_risk)

    def _animate_risk_meter(self, color, visual_risk):
        if self.risk_meter_value < self.risk_meter_target:
            step = 4 if self.risk_meter_target >= 60 else 2
            self.risk_meter_value = min(self.risk_meter_target, self.risk_meter_value + step)

        glow_frames = ["#04111f", "#061a2b", "#08253c", "#061a2b"]
        frame = self.risk_pulse_step % len(glow_frames)

        if visual_risk == "NO RISK":
            word = "No Risk"
        else:
            word = "Risk"

        self.risk_percent_var.set("%s%%" % self.risk_meter_value)
        self.risk_meter_frame.configure(bg=glow_frames[frame])
        self.risk_percent_label.configure(bg=glow_frames[frame])
        self.draw_animated_risk_word(word, color, self.risk_pulse_step, glow_frames[frame])

        delay = 38 if self.risk_meter_value < self.risk_meter_target else 260
        self.risk_meter_job = self.root.after(
            delay, lambda: self._animate_risk_meter(color, visual_risk)
        )

    def _set_busy(self, busy):
        self.scan_button.configure(state="disabled" if busy else "normal")
        self.target_entry.configure(state="disabled" if busy else "normal")
        if busy:
            self.download_button.configure(state="disabled")
            self.json_button.configure(state="disabled")

    def validate_target(self, value):
        if not value:
            return None, "Target cannot be empty."
        if any(part in value for part in [" ", "\\", "<", ">", "\""]):
            return None, "Target contains invalid characters."
        return normalize_host(value), None

    def start_scan(self):
        raw_target = self.target_var.get().strip()
        host, error = self.validate_target(raw_target)
        if error:
            messagebox.showerror("Invalid Target", error)
            self.status_var.set("[ERROR] " + error)
            return

        self.results_text.delete("1.0", "end")
        self.risk_var.set("Risk: Scanning...")
        self.status_var.set("[INFO] Scan running. Please wait.")
        self.reset_risk_animation()
        self._set_busy(True)

        self.scan_thread = threading.Thread(target=self._run_scan, args=(raw_target, host), daemon=True)
        self.scan_thread.start()

    def _run_scan(self, raw_target, host):
        try:
            self.root.after(0, self._append_result, "[INFO] Starting assessment for %s" % raw_target)

            port_scan = scan_ports(host)
            if port_scan.get("error"):
                raise ValueError(port_scan["error"])

            self.root.after(0, self._append_result, "[INFO] Resolved target IP: %s" % port_scan.get("ip"))
            if port_scan["open_ports"]:
                for item in port_scan["open_ports"]:
                    self.root.after(
                        0,
                        self._append_result,
                        "[OPEN] Port %s (%s) detected" % (item["port"], item["service"]),
                    )
            else:
                self.root.after(0, self._append_result, "[INFO] No configured ports detected as open.")

            vulnerabilities = run_vulnerability_scan(raw_target, port_scan)
            for finding in vulnerabilities:
                self.root.after(
                    0,
                    self._append_result,
                    "[%s RISK] %s" % (finding["severity"], finding["title"]),
                )

            pentest_results = run_pentest_simulation(raw_target)
            for result in pentest_results:
                tag = "WARNING" if result["possible_vulnerability"] else "INFO"
                self.root.after(
                    0,
                    self._append_result,
                    "[%s] %s - %s" % (tag, result["test"], result["evidence"]),
                )

            mappings = map_findings(vulnerabilities, pentest_results)
            risk_level = calculate_risk_level(vulnerabilities, pentest_results)

            self.scan_data = create_scan_record(
                raw_target, port_scan, vulnerabilities, pentest_results, mappings, risk_level
            )
            save_text_report(self.scan_data, "report.txt")

            self.root.after(0, self._finish_scan_success, risk_level)
        except (ValueError, socket.gaierror) as exc:
            self.root.after(0, self._finish_scan_error, str(exc))
        except Exception as exc:
            self.root.after(0, self._finish_scan_error, "Unexpected scan error: %s" % exc)

    def _finish_scan_success(self, risk_level):
        self._append_result("")
        self._append_result("[INFO] Framework mapping completed.")
        self._append_result("[%s RISK] Final risk level: %s" % (risk_level, risk_level))
        self._append_result("[INFO] Default report saved as report.txt")
        self.results_text.insert("end", "\n" + generate_text_report(self.scan_data))
        self.add_scan_to_history()

        self.status_var.set("[INFO] Scan completed successfully.")
        visual_risk = self.get_visual_risk()
        self.risk_var.set("Risk: " + visual_risk)
        self.risk_label.configure(fg=COLORS.get(visual_risk.lower().replace(" ", "_"), COLORS["accent"]))
        if visual_risk in ("HIGH", "MEDIUM", "LOW"):
            self.risk_label.configure(fg=COLORS[visual_risk.lower()])
        self.start_risk_animation(visual_risk)
        self.download_button.configure(state="normal")
        self.json_button.configure(state="normal")
        self._set_busy(False)

    def _finish_scan_error(self, error):
        self._append_result("[ERROR] " + error)
        self.status_var.set("[ERROR] Scan failed.")
        self.risk_var.set("Risk: N/A")
        self.risk_label.configure(fg=COLORS["muted"])
        self.reset_risk_animation()
        self._set_busy(False)
        messagebox.showerror("Scan Error", error)

    def download_report(self):
        if not self.scan_data:
            messagebox.showinfo("No Report", "Run a scan before downloading a report.")
            return

        path = filedialog.asksaveasfilename(
            title="Save Security Audit Report",
            defaultextension=".txt",
            filetypes=[("Text Report", "*.txt"), ("All Files", "*.*")],
            initialfile="report.txt",
        )
        if path:
            save_text_report(self.scan_data, path)
            self.status_var.set("[INFO] Report saved to %s" % path)

    def export_json(self):
        if not self.scan_data:
            messagebox.showinfo("No Report", "Run a scan before exporting JSON.")
            return

        path = filedialog.asksaveasfilename(
            title="Export JSON Report",
            defaultextension=".json",
            filetypes=[("JSON Report", "*.json"), ("All Files", "*.*")],
            initialfile="report.json",
        )
        if path:
            save_json_report(self.scan_data, path)
            self.status_var.set("[INFO] JSON report saved to %s" % path)


def main():
    root = tk.Tk()
    CyberScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
