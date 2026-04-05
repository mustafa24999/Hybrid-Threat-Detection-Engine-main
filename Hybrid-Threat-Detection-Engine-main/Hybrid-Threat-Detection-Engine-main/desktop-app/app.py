# desktop-app/app.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import requests
import threading
import json
import time
import os
from datetime import datetime
from pathlib import Path

# --- ZENITH V4 ADVANCED DESIGN SYSTEM ---
BG_PURE = "#010409"      # True Dark
BG_SIDEBAR = "#000000"   # Sidebar Black
BG_CARD = "#0d1117"      # GitHub Dark Card
BG_INPUT = "#010409"     # Input Background
BORDER = "#30363d"       # Enterprise Border
ACCENT = "#2f81f7"       # Electric Blue
ACCENT_DIM = "#1f6feb"
FG_PRIMARY = "#f0f6fc"   # Primary Text
FG_MUTED = "#8b949e"     # Muted Text
FG_DIM = "#484f58"       # Dim/Icon Text
GREEN = "#238636"
YELLOW = "#d29922"
RED = "#da3633"

BACKEND_URL = "http://127.0.0.1:8000"
ZENITH_AUTH_KEY = "zenith_default_dev_key"
HEADERS = {"X-Zenith-Auth": ZENITH_AUTH_KEY}

class ModernButton(tk.Button):
    """A custom high-tech button with hover effects."""
    def __init__(self, master, text, command=None, bg=ACCENT, **kwargs):
        super().__init__(master, text=text, command=command, 
                         relief="flat", bg=bg, fg="white",
                         activebackground=ACCENT_DIM, activeforeground="white",
                         font=("Inter", 10, "bold"), cursor="hand2",
                         padx=20, pady=8, **kwargs)
        self.bind("<Enter>", lambda e: self.config(bg=ACCENT_DIM))
        self.bind("<Leave>", lambda e: self.config(bg=bg))

class HybridThreatDetectorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ZENITH | Enterprise Threat Detection Engine")
        self.geometry("1200x800")
        self.configure(bg=BG_PURE)
        
        self.selected_file_path = None
        self.current_scan_id = None
        self.is_online = False
        
        self.setup_styles()
        self.create_layout()
        
        # Initial status and data load
        self.poll_backend_health()
        self.load_history()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        
        # Modern Treeview (History Table)
        style.configure("Treeview", 
                        background=BG_CARD, 
                        foreground=FG_PRIMARY, 
                        fieldbackground=BG_CARD, 
                        rowheight=40, 
                        borderwidth=0, 
                        font=("Inter", 10))
        style.map("Treeview", 
                  background=[("selected", "#1c212c")], 
                  foreground=[("selected", ACCENT)])
        style.configure("Treeview.Heading", 
                        background=BG_SIDEBAR, 
                        foreground=FG_MUTED, 
                        relief="flat", 
                        font=("Inter", 10, "bold"))
        
        # Progress Bar
        style.configure("TProgressbar", thickness=4, background=ACCENT, troughcolor=BG_PURE, borderwidth=0)

    def create_layout(self):
        # --- Sidebar ---
        self.sidebar = tk.Frame(self, bg=BG_SIDEBAR, width=240)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Sidebar Branding
        brand_frame = tk.Frame(self.sidebar, bg=BG_SIDEBAR, pady=40)
        brand_frame.pack(fill="x")
        tk.Label(brand_frame, text="ZENITH", bg=BG_SIDEBAR, fg=ACCENT, font=("Inter", 24, "bold")).pack()
        tk.Label(brand_frame, text="V4 ENTERPRISE", bg=BG_SIDEBAR, fg=FG_DIM, font=("Inter", 8, "bold")).pack()

        # Sidebar Navigation
        self.nav_frame = tk.Frame(self.sidebar, bg=BG_SIDEBAR)
        self.nav_frame.pack(fill="both", expand=True, padx=10)

        self.btn_scanner = self.create_nav_item("🛡  Threat Scanner", self.show_scanner)
        self.btn_history = self.create_nav_item("📜  Scan History", self.show_history)
        self.btn_settings = self.create_nav_item("⚙  System Config", self.show_settings)

        # Sidebar Status
        self.status_area = tk.Frame(self.sidebar, bg=BG_SIDEBAR, pady=20)
        self.status_area.pack(side="bottom", fill="x")
        
        status_line = tk.Frame(self.status_area, bg=BG_SIDEBAR)
        status_line.pack()
        
        self.status_dot = tk.Canvas(status_line, width=8, height=8, bg=BG_SIDEBAR, highlightthickness=0)
        self.status_dot.pack(side="left", padx=5)
        self.status_dot.create_oval(0, 0, 8, 8, fill="grey", tags="dot")
        
        self.status_text = tk.Label(status_line, text="DISCONNECTED", bg=BG_SIDEBAR, fg=FG_DIM, font=("Inter", 8, "bold"))
        self.status_text.pack(side="left")

        # --- Main Stage ---
        self.stage = tk.Frame(self, bg=BG_PURE)
        self.stage.pack(side="left", fill="both", expand=True)

        self.show_scanner()

    def create_nav_item(self, text, command):
        btn = tk.Button(self.nav_frame, text=text, bg=BG_SIDEBAR, fg=FG_MUTED, 
                        font=("Inter", 11), relief="flat", anchor="w", padx=20, 
                        pady=15, cursor="hand2", activebackground=BG_CARD,
                        activeforeground=ACCENT, command=command)
        btn.pack(fill="x", pady=2)
        btn.bind("<Enter>", lambda e: btn.config(fg=FG_PRIMARY) if btn.cget("fg") != ACCENT else None)
        btn.bind("<Leave>", lambda e: btn.config(fg=FG_MUTED) if btn.cget("fg") != ACCENT else None)
        return btn

    def set_active_nav(self, active_btn):
        for btn in [self.btn_scanner, self.btn_history, self.btn_settings]:
            btn.config(fg=FG_MUTED, bg=BG_SIDEBAR)
        active_btn.config(fg=ACCENT, bg=BG_CARD)

    def clear_stage(self):
        for widget in self.stage.winfo_children():
            widget.destroy()

    # --- VIEW: SCANNER ---
    def show_scanner(self):
        self.clear_stage()
        self.set_active_nav(self.btn_scanner)
        
        container = tk.Frame(self.stage, bg=BG_PURE, padx=50, pady=40)
        container.pack(fill="both", expand=True)

        # Header
        tk.Label(container, text="Advanced Threat Scanner", bg=BG_PURE, fg=FG_PRIMARY, font=("Inter", 24, "bold")).pack(anchor="w")
        tk.Label(container, text="Hybrid static analysis and intelligence correlation for links and binaries.", 
                 bg=BG_PURE, fg=FG_MUTED, font=("Inter", 11)).pack(anchor="w", pady=(5, 40))

        # Cards Row
        cards = tk.Frame(container, bg=BG_PURE)
        cards.pack(fill="x")

        # URL Analysis Card
        url_card = self.create_card(cards, "URL SECURITY AUDIT")
        url_card.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        tk.Label(url_card, text="Target URL", bg=BG_CARD, fg=FG_MUTED, font=("Inter", 9, "bold")).pack(anchor="w", padx=25, pady=(20, 5))
        self.url_entry = tk.Entry(url_card, bg=BG_INPUT, fg=FG_PRIMARY, insertbackground=ACCENT, 
                                  relief="flat", font=("Inter", 11), borderwidth=15)
        self.url_entry.pack(fill="x", padx=25, pady=(0, 20))
        self.url_entry.insert(0, "https://")
        
        ModernButton(url_card, text="🔍 SCAN URL", command=self.start_url_scan).pack(anchor="e", padx=25, pady=(0, 25))

        # File Analysis Card
        file_card = self.create_card(cards, "BINARY INSPECTION")
        file_card.pack(side="left", fill="both", expand=True, padx=(10, 0))
        
        tk.Label(file_card, text="Select Local File", bg=BG_CARD, fg=FG_MUTED, font=("Inter", 9, "bold")).pack(anchor="w", padx=25, pady=(20, 5))
        
        f_row = tk.Frame(file_card, bg=BG_CARD)
        f_row.pack(fill="x", padx=25)
        
        ModernButton(f_row, text="📁 BROWSE", bg=FG_DIM, command=self.browse_file).pack(side="left")
        self.file_label = tk.Label(f_row, text="No binary selected", bg=BG_CARD, fg=FG_DIM, font=("Inter", 10))
        self.file_label.pack(side="left", padx=15)
        
        self.file_scan_btn = ModernButton(file_card, text="🛡 SCAN FILE", state="disabled", command=self.start_file_scan)
        self.file_scan_btn.pack(anchor="e", padx=25, pady=(15, 25))

        # Results Panel
        tk.Label(container, text="ANALYSIS REPORT", bg=BG_PURE, fg=FG_DIM, font=("Inter", 9, "bold"), pady=20).pack(anchor="w")
        self.result_area = tk.Frame(container, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        self.result_area.pack(fill="both", expand=True)
        self.show_idle_state()

    def create_card(self, parent, title):
        # Wrapper to handle margins manually
        outer = tk.Frame(parent, bg=BG_PURE)
        card = tk.Frame(outer, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="both", expand=True, padx=0, pady=0)
        
        # Header in card
        tk.Label(card, text=title, bg=BG_CARD, fg=ACCENT, font=("Inter", 10, "bold")).pack(anchor="w", padx=25, pady=(20, 0))
        return outer

    # --- VIEW: HISTORY ---
    def show_history(self):
        self.clear_stage()
        self.set_active_nav(self.btn_history)
        
        container = tk.Frame(self.stage, bg=BG_PURE, padx=50, pady=40)
        container.pack(fill="both", expand=True)

        tk.Label(container, text="Intelligence History", bg=BG_PURE, fg=FG_PRIMARY, font=("Inter", 24, "bold")).pack(anchor="w")
        tk.Label(container, text="Audit logs of all previous URL and file analysis results.", 
                 bg=BG_PURE, fg=FG_MUTED, font=("Inter", 11)).pack(anchor="w", pady=(5, 30))

        # Table Card
        table_card = tk.Frame(container, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        table_card.pack(fill="both", expand=True)

        cols = ("Time", "Type", "Target", "Classification", "Risk Score")
        self.history_tree = ttk.Treeview(table_card, columns=cols, show="headings")
        for col in cols:
            self.history_tree.heading(col, text=col.upper())
            self.history_tree.column(col, width=100, anchor="center")
        self.history_tree.column("Target", width=450, anchor="w")
        self.history_tree.pack(side="left", fill="both", expand=True)

        sb = ttk.Scrollbar(table_card, orient="vertical", command=self.history_tree.yview)
        sb.pack(side="right", fill="y")
        self.history_tree.configure(yscrollcommand=sb.set)

        self.history_tree.bind("<<TreeviewSelect>>", self.on_history_click)
        
        # Context Menu
        self.history_menu = tk.Menu(self, tearoff=0, bg=BG_CARD, fg=FG_PRIMARY, activebackground=ACCENT)
        self.history_menu.add_command(label="📄 View Report", command=self.view_selected_history)
        self.history_menu.add_separator()
        self.history_menu.add_command(label="🗑 Delete Record", command=self.delete_selected_history)
        self.history_menu.add_command(label="🔥 PURGE HISTORY", command=self.clear_all_history)
        
        self.history_tree.bind("<Button-3>", self.show_history_menu)
        self.history_tree.bind("<Button-2>", self.show_history_menu)

        self.load_history()

    # --- VIEW: SETTINGS ---
    def show_settings(self):
        self.clear_stage()
        self.set_active_nav(self.btn_settings)
        
        container = tk.Frame(self.stage, bg=BG_PURE, padx=50, pady=40)
        container.pack(fill="both", expand=True)

        tk.Label(container, text="System Configuration", bg=BG_PURE, fg=FG_PRIMARY, font=("Inter", 24, "bold")).pack(anchor="w")
        
        card = tk.Frame(container, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1, pady=30)
        card.pack(fill="x", pady=40)
        
        # VT Key
        tk.Label(card, text="VirusTotal API Key", bg=BG_CARD, fg=FG_MUTED, font=("Inter", 10, "bold")).pack(anchor="w", padx=40, pady=(0, 5))
        vt_entry = tk.Entry(card, bg=BG_INPUT, fg=FG_PRIMARY, relief="flat", borderwidth=15, font=("Inter", 11))
        vt_entry.pack(fill="x", padx=40, pady=(0, 30))
        vt_entry.insert(0, self.get_env_value("VT_API_KEY"))

        # Backend Host
        tk.Label(card, text="Backend Connection String", bg=BG_CARD, fg=FG_MUTED, font=("Inter", 10, "bold")).pack(anchor="w", padx=40, pady=(0, 5))
        host_entry = tk.Entry(card, bg=BG_INPUT, fg=FG_PRIMARY, relief="flat", borderwidth=15, font=("Inter", 11))
        host_entry.pack(fill="x", padx=40, pady=(0, 30))
        host_entry.insert(0, self.get_env_value("BACKEND_HOST", "127.0.0.1"))

        def save():
            if self.save_env_values({"VT_API_KEY": vt_entry.get(), "BACKEND_HOST": host_entry.get()}):
                messagebox.showinfo("ZENITH", "Configuration saved successfully.\nPlease restart the service to apply.")

        ModernButton(card, text="💾 SAVE CONFIGURATION", command=save).pack(anchor="e", padx=40)

    # --- LOGIC & HELPERS ---

    def show_idle_state(self):
        for widget in self.result_area.winfo_children(): widget.destroy()
        tk.Label(self.result_area, text="AWAITING INPUT...", bg=BG_CARD, fg=FG_DIM, font=("Inter", 12, "bold")).place(relx=0.5, rely=0.5, anchor="center")

    def show_loading(self, message):
        for widget in self.result_area.winfo_children(): widget.destroy()
        tk.Label(self.result_area, text=message.upper(), bg=BG_CARD, fg=FG_PRIMARY, font=("Inter", 11, "bold")).place(relx=0.5, rely=0.4, anchor="center")
        p = ttk.Progressbar(self.result_area, mode="indeterminate", length=300, style="TProgressbar")
        p.place(relx=0.5, rely=0.5, anchor="center")
        p.start()

    def display_result(self, result):
        self.current_scan_id = result.get("id")
        for widget in self.result_area.winfo_children(): widget.destroy()
        
        label = result.get("label", "Unknown")
        score = result.get("score", 0.0)
        color = GREEN if label == "Safe" else (YELLOW if label == "Suspicious" else RED)
        
        # Header Badge Row
        h_frame = tk.Frame(self.result_area, bg=BG_CARD, padx=30, pady=25)
        h_frame.pack(fill="x")
        
        badge = tk.Label(h_frame, text=label.upper(), bg=color, fg="white", font=("Inter", 10, "bold"), padx=20, pady=6)
        badge.pack(side="left")
        
        tk.Label(h_frame, text=f"THREAT SCORE: {int(score*100)}%", bg=BG_CARD, fg=color, font=("Inter", 14, "bold")).pack(side="left", padx=20)

        if self.current_scan_id and self.current_scan_id != -1:
            ModernButton(h_frame, text="🗑 DELETE", bg=RED, command=self.delete_current_report).pack(side="right")

        # Report Content
        content = tk.Frame(self.result_area, bg=BG_CARD, padx=30)
        content.pack(fill="both", expand=True)

        tk.Label(content, text="TARGET IDENTIFIER", bg=BG_CARD, fg=FG_MUTED, font=("Inter", 8, "bold")).pack(anchor="w")
        tk.Label(content, text=result.get("target", "Unknown"), bg=BG_CARD, fg=FG_PRIMARY, font=("Inter", 11, "bold"), wraplength=800, justify="left").pack(anchor="w", pady=(2, 20))
        
        tk.Label(content, text="KEY SECURITY FINDINGS", bg=BG_CARD, fg=FG_MUTED, font=("Inter", 8, "bold")).pack(anchor="w")
        reasons_frame = tk.Frame(content, bg=BG_CARD, pady=10)
        reasons_frame.pack(fill="x")
        
        for r in result.get("reasons", []):
            tk.Label(reasons_frame, text=f"▪ {r}", bg=BG_CARD, fg=FG_PRIMARY, font=("Inter", 10), anchor="w").pack(fill="x", pady=2)

    def delete_current_report(self):
        if not self.current_scan_id: return
        if messagebox.askyesno("Confirm", "Delete this security report?"):
            requests.delete(f"{BACKEND_URL}/history/{self.current_scan_id}", headers=HEADERS)
            self.show_idle_state()
            self.load_history()

    # Communication & API
    def poll_backend_health(self):
        def check():
            try:
                r = requests.get(f"{BACKEND_URL}/health", headers=HEADERS, timeout=2)
                online = r.status_code == 200
                self.after(0, lambda: self.update_status(online, "ONLINE" if online else "ERROR"))
            except:
                self.after(0, lambda: self.update_status(False, "DISCONNECTED"))
            self.after(10000, self.poll_backend_health)
        threading.Thread(target=check, daemon=True).start()

    def update_status(self, online, text):
        self.is_online = online
        color = GREEN if online else RED
        self.status_dot.itemconfig("dot", fill=color)
        self.status_text.config(text=text, fg=color)

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.selected_file_path = Path(path)
            self.file_label.config(text=self.selected_file_path.name, fg=FG_PRIMARY)
            self.file_scan_btn.config(state="normal")

    def start_url_scan(self):
        url = self.url_entry.get().strip()
        if not url.startswith("http"):
            messagebox.showwarning("Zenith", "Please enter a valid URL.")
            return
        self.show_loading(f"Analyzing {url}")
        threading.Thread(target=self.do_url_scan, args=(url,), daemon=True).start()

    def do_url_scan(self, url):
        try:
            r = requests.post(f"{BACKEND_URL}/scan/url", json={"url": url}, headers=HEADERS, timeout=30)
            if r.status_code == 200:
                self.after(0, lambda: self.display_result(r.json()))
                self.after(0, self.load_history)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("API Error", str(e)))

    def start_file_scan(self):
        if not self.selected_file_path: return
        self.show_loading(f"Inspecting {self.selected_file_path.name}")
        threading.Thread(target=self.do_file_scan, args=(self.selected_file_path,), daemon=True).start()

    def do_file_scan(self, path):
        try:
            with open(path, "rb") as f:
                r = requests.post(f"{BACKEND_URL}/scan/file", files={"file": f}, headers=HEADERS, timeout=60)
            if r.status_code == 200:
                self.after(0, lambda: self.display_result(r.json()))
                self.after(0, self.load_history)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("API Error", str(e)))

    def load_history(self):
        def fetch():
            try:
                r = requests.get(f"{BACKEND_URL}/history/", params={"limit": 100}, headers=HEADERS, timeout=5)
                if r.status_code == 200:
                    self.after(0, lambda: self.update_history_tree(r.json()["records"]))
            except: pass
        threading.Thread(target=fetch, daemon=True).start()

    def update_history_tree(self, records):
        if not hasattr(self, 'history_tree'): return
        self.history_tree.delete(*self.history_tree.get_children())
        for rec in records:
            ts = rec["timestamp"].split("T")[1][:8] if "T" in rec["timestamp"] else rec["timestamp"]
            target = rec["target"]
            if len(target) > 60: target = target[:57] + "..."
            self.history_tree.insert("", "end", iid=rec["id"], values=(ts, rec["scan_type"], target, rec["label"], f"{int(rec['score']*100)}%"))

    def show_history_menu(self, event):
        item = self.history_tree.identify_row(event.y)
        if item:
            self.history_tree.selection_set(item)
            self.history_menu.post(event.x_root, event.y_root)

    def on_history_click(self, event):
        pass # Handle double click if needed

    def view_selected_history(self):
        selected = self.history_tree.selection()
        if not selected: return
        scan_id = selected[0]
        try:
            r = requests.get(f"{BACKEND_URL}/history/{scan_id}", headers=HEADERS)
            if r.status_code == 200:
                self.show_scanner()
                self.display_result(r.json())
        except: pass

    def delete_selected_history(self):
        selected = self.history_tree.selection()
        if not selected: return
        scan_id = selected[0]
        if messagebox.askyesno("Zenith", "Delete selected record?"):
            requests.delete(f"{BACKEND_URL}/history/{scan_id}", headers=HEADERS)
            self.load_history()

    def clear_all_history(self):
        if messagebox.askyesno("Zenith", "Danger: Clear all security history?"):
            requests.delete(f"{BACKEND_URL}/history/", headers=HEADERS)
            self.load_history()

    def get_env_value(self, key, default=""):
        env_path = Path(__file__).parent.parent / "backend" / ".env"
        if not env_path.exists(): return default
        with open(env_path, "r") as f:
            for line in f:
                if line.startswith(f"{key}="): return line.split("=", 1)[1].strip()
        return default

    def save_env_values(self, updates):
        try:
            env_path = Path(__file__).parent.parent / "backend" / ".env"
            lines = []
            if env_path.exists():
                with open(env_path, "r") as f: lines = f.readlines()
            for key, val in updates.items():
                found = False
                for i, line in enumerate(lines):
                    if line.startswith(f"{key}="):
                        lines[i] = f"{key}={val}\n"
                        found = True
                        break
                if not found: lines.append(f"{key}={val}\n")
            with open(env_path, "w") as f: f.writelines(lines)
            return True
        except: return False

if __name__ == "__main__":
    try:
        app = HybridThreatDetectorApp()
        app.mainloop()
    except KeyboardInterrupt:
        print("\n[!] Zenith Dashboard closed.")
