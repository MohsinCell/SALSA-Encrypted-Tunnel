import logging
import os
import queue
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, ttk
from typing import Any, Dict, List, Optional

from config import SalsaConfig
from socks_proxy import SOCKSProxy
from vpn_client import VPNClient
from vpn_server import VPNServer

logger = logging.getLogger(__name__)

BG = "#1a1a2e"
CARD = "#16213e"
ACCENT = "#0f3460"
HIGHLIGHT = "#e94560"
TEXT = "#e0e0e0"
TEXT_DIM = "#8899aa"
GREEN = "#00d26a"
ORANGE = "#ff9f1c"
RED = "#e94560"
BLUE = "#4da6ff"
FONT_SANS = ("Segoe UI", 10)
FONT_SANS_BOLD = ("Segoe UI", 10, "bold")
FONT_SANS_LG = ("Segoe UI", 14, "bold")
FONT_SANS_XL = ("Segoe UI", 20, "bold")
FONT_MONO = ("Consolas", 9)
FONT_MONO_SM = ("Consolas", 8)

class VPNGUIManager:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Salsa - Encrypted Tunnel")
        self.root.geometry("1100x750")
        self.root.configure(bg=BG)
        self.root.minsize(900, 600)

        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "SALSA.png")
        try:
            self.icon = tk.PhotoImage(file=icon_path)
            self.root.iconphoto(True, self.icon)
        except Exception:
            pass

        self.vpn_server: Optional[VPNServer] = None
        self.vpn_client: Optional[VPNClient] = None
        self.socks_proxy: Optional[SOCKSProxy] = None
        self._server_thread: Optional[threading.Thread] = None

        self.log_queue: queue.Queue = queue.Queue()
        self._log_entries: List[tuple] = []
        self._log_auto_scroll = True

        self._bw_history: List[tuple] = []
        self._max_bw_points = 120

        self._setup_styles()
        self._build_ui()
        self._update_loop()

    def _setup_styles(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".", background=BG, foreground=TEXT, font=FONT_SANS)
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT, font=FONT_SANS)
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=CARD, foreground=TEXT, padding=[16, 6], font=FONT_SANS_BOLD)
        style.map("TNotebook.Tab", background=[("selected", ACCENT)], foreground=[("selected", "#ffffff")])

        style.configure("Card.TFrame", background=CARD)
        style.configure("Card.TLabel", background=CARD, foreground=TEXT, font=FONT_SANS)
        style.configure("CardTitle.TLabel", background=CARD, foreground="#ffffff", font=FONT_SANS_BOLD)
        style.configure("CardDim.TLabel", background=CARD, foreground=TEXT_DIM, font=FONT_SANS)
        style.configure("CardBig.TLabel", background=CARD, foreground="#ffffff", font=FONT_SANS_XL)

        style.configure("Accent.TButton", background=ACCENT, foreground="#ffffff", font=FONT_SANS_BOLD, padding=[12, 6])
        style.map("Accent.TButton", background=[("active", HIGHLIGHT), ("disabled", "#333333")])
        style.configure("Danger.TButton", background=RED, foreground="#ffffff", font=FONT_SANS_BOLD, padding=[12, 6])
        style.map("Danger.TButton", background=[("active", "#c0392b"), ("disabled", "#333333")])
        style.configure("Green.TButton", background=GREEN, foreground="#111111", font=FONT_SANS_BOLD, padding=[12, 6])
        style.map("Green.TButton", background=[("active", "#00b359"), ("disabled", "#333333")])

        style.configure("TEntry", fieldbackground="#0d1b2a", foreground=TEXT, insertcolor=TEXT)
        style.configure("TCombobox", fieldbackground="#0d1b2a", foreground=TEXT)
        style.configure("TCheckbutton", background=CARD, foreground=TEXT)

    def _build_ui(self) -> None:
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self._tab_dashboard = ttk.Frame(notebook)
        self._tab_server = ttk.Frame(notebook)
        self._tab_client = ttk.Frame(notebook)
        self._tab_traffic = ttk.Frame(notebook)
        self._tab_logs = ttk.Frame(notebook)

        notebook.add(self._tab_dashboard, text=" Dashboard ")
        notebook.add(self._tab_server, text=" Server ")
        notebook.add(self._tab_client, text=" Client ")
        notebook.add(self._tab_traffic, text=" Traffic Monitor ")
        notebook.add(self._tab_logs, text=" Logs ")

        self._build_dashboard()
        self._build_server_tab()
        self._build_client_tab()
        self._build_traffic_tab()
        self._build_logs_tab()

    def _card(self, parent: tk.Widget, row: int = 0, col: int = 0, colspan: int = 1,
              rowspan: int = 1, sticky: str = "nsew", padx: int = 6, pady: int = 6) -> ttk.Frame:
        frame = ttk.Frame(parent, style="Card.TFrame", padding=12)
        frame.grid(row=row, column=col, columnspan=colspan, rowspan=rowspan,
                   sticky=sticky, padx=padx, pady=pady)
        return frame

    def _status_dot(self, parent: tk.Widget, color: str = RED) -> tk.Canvas:
        c = tk.Canvas(parent, width=14, height=14, bg=CARD, highlightthickness=0)
        c._dot = c.create_oval(2, 2, 12, 12, fill=color, outline="")
        return c

    def _set_dot_color(self, dot: tk.Canvas, color: str) -> None:
        dot.itemconfig(dot._dot, fill=color)

    def _build_dashboard(self) -> None:
        tab = self._tab_dashboard
        tab.columnconfigure(0, weight=1)
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(0, weight=0)
        tab.rowconfigure(1, weight=0)
        tab.rowconfigure(2, weight=1)

        card = self._card(tab, 0, 0, colspan=2)
        card.columnconfigure(1, weight=1)

        self._dash_dot = self._status_dot(card, RED)
        self._dash_dot.grid(row=0, column=0, padx=(0, 8))
        self._dash_status = ttk.Label(card, text="Disconnected", style="CardBig.TLabel")
        self._dash_status.grid(row=0, column=1, sticky="w")
        self._dash_detail = ttk.Label(card, text="No active connections", style="CardDim.TLabel")
        self._dash_detail.grid(row=1, column=1, sticky="w")

        btn_frame = ttk.Frame(card, style="Card.TFrame")
        btn_frame.grid(row=0, column=2, rowspan=2, padx=(20, 0))
        self._dash_start_btn = ttk.Button(btn_frame, text="Start Server", style="Green.TButton", command=self._start_server)
        self._dash_start_btn.pack(side=tk.LEFT, padx=4)
        self._dash_stop_btn = ttk.Button(btn_frame, text="Stop Server", style="Danger.TButton", command=self._stop_server, state=tk.DISABLED)
        self._dash_stop_btn.pack(side=tk.LEFT, padx=4)

        stats_card = self._card(tab, 1, 0, colspan=2)
        stats_card.columnconfigure(tuple(range(6)), weight=1)
        self._dash_stats = {}
        stat_items = [
            ("Uptime", "uptime", "00:00:00"),
            ("Bytes Sent", "bytes_sent", "0 B"),
            ("Bytes Received", "bytes_recv", "0 B"),
            ("Clients", "clients", "0"),
            ("Enc Ops", "enc_time", "0.000s"),
            ("Packets", "packets", "0"),
        ]
        for i, (label, key, default) in enumerate(stat_items):
            ttk.Label(stats_card, text=label, style="CardDim.TLabel").grid(row=0, column=i)
            lbl = ttk.Label(stats_card, text=default, style="CardTitle.TLabel")
            lbl.grid(row=1, column=i)
            self._dash_stats[key] = lbl

        srv_card = self._card(tab, 2, 0)
        ttk.Label(srv_card, text="Server", style="CardTitle.TLabel").pack(anchor="w")
        self._dash_srv_dot = self._status_dot(srv_card)
        self._dash_srv_dot.pack(anchor="w", pady=4)
        self._dash_srv_info = ttk.Label(srv_card, text="Stopped", style="Card.TLabel", wraplength=400, justify="left")
        self._dash_srv_info.pack(anchor="w", fill=tk.X)

        cli_card = self._card(tab, 2, 1)
        ttk.Label(cli_card, text="Client", style="CardTitle.TLabel").pack(anchor="w")
        self._dash_cli_dot = self._status_dot(cli_card)
        self._dash_cli_dot.pack(anchor="w", pady=4)
        self._dash_cli_info = ttk.Label(cli_card, text="Disconnected", style="Card.TLabel", wraplength=400, justify="left")
        self._dash_cli_info.pack(anchor="w", fill=tk.X)

    def _build_server_tab(self) -> None:
        tab = self._tab_server
        tab.columnconfigure(0, weight=1)
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(2, weight=1)

        cfg_card = self._card(tab, 0, 0)
        ttk.Label(cfg_card, text="Server Configuration", style="CardTitle.TLabel").grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 8))

        ttk.Label(cfg_card, text="Bind IP:", style="Card.TLabel").grid(row=1, column=0, sticky="w", padx=4)
        self._srv_ip = ttk.Entry(cfg_card, width=16)
        self._srv_ip.insert(0, "0.0.0.0")
        self._srv_ip.grid(row=1, column=1, padx=4)

        ttk.Label(cfg_card, text="Port:", style="Card.TLabel").grid(row=1, column=2, sticky="w", padx=4)
        self._srv_port = ttk.Entry(cfg_card, width=8)
        self._srv_port.insert(0, "8080")
        self._srv_port.grid(row=1, column=3, padx=4)

        ttk.Label(cfg_card, text="Max Clients:", style="Card.TLabel").grid(row=2, column=0, sticky="w", padx=4)
        self._srv_max = ttk.Entry(cfg_card, width=8)
        self._srv_max.insert(0, "100")
        self._srv_max.grid(row=2, column=1, padx=4)

        ttk.Label(cfg_card, text="Subnet:", style="Card.TLabel").grid(row=2, column=2, sticky="w", padx=4)
        self._srv_subnet = ttk.Entry(cfg_card, width=16)
        self._srv_subnet.insert(0, "10.0.0.0/24")
        self._srv_subnet.grid(row=2, column=3, padx=4)

        ctrl_card = self._card(tab, 0, 1)
        ttk.Label(ctrl_card, text="Server Control", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 8))

        btn_row = ttk.Frame(ctrl_card, style="Card.TFrame")
        btn_row.pack(fill=tk.X)
        self._srv_start_btn = ttk.Button(btn_row, text="Start Server", style="Green.TButton", command=self._start_server)
        self._srv_start_btn.pack(side=tk.LEFT, padx=4)
        self._srv_stop_btn = ttk.Button(btn_row, text="Stop Server", style="Danger.TButton", command=self._stop_server, state=tk.DISABLED)
        self._srv_stop_btn.pack(side=tk.LEFT, padx=4)

        status_row = ttk.Frame(ctrl_card, style="Card.TFrame")
        status_row.pack(fill=tk.X, pady=(8, 0))
        self._srv_dot = self._status_dot(ctrl_card)
        self._srv_dot.pack(anchor="w")
        self._srv_status_lbl = ttk.Label(ctrl_card, text="Stopped", style="Card.TLabel")
        self._srv_status_lbl.pack(anchor="w")

        user_card = self._card(tab, 1, 0, colspan=2)
        ttk.Label(user_card, text="User Management", style="CardTitle.TLabel").grid(row=0, column=0, columnspan=5, sticky="w", pady=(0, 8))

        ttk.Label(user_card, text="Username:", style="Card.TLabel").grid(row=1, column=0, sticky="w", padx=4)
        self._user_name = ttk.Entry(user_card, width=16)
        self._user_name.grid(row=1, column=1, padx=4)
        ttk.Label(user_card, text="Password:", style="Card.TLabel").grid(row=1, column=2, sticky="w", padx=4)
        self._user_pass = ttk.Entry(user_card, width=16, show="*")
        self._user_pass.grid(row=1, column=3, padx=4)
        ttk.Button(user_card, text="Add User", style="Accent.TButton", command=self._add_user).grid(row=1, column=4, padx=4)

        self._user_list = tk.Listbox(user_card, bg="#0d1b2a", fg=TEXT, font=FONT_MONO, height=4, selectbackground=ACCENT)
        self._user_list.grid(row=2, column=0, columnspan=4, sticky="ew", padx=4, pady=4)
        ttk.Button(user_card, text="Remove", style="Danger.TButton", command=self._remove_user).grid(row=2, column=4, padx=4)

        clients_card = self._card(tab, 2, 0, colspan=2)
        ttk.Label(clients_card, text="Connected Clients", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 8))
        self._clients_text = tk.Text(clients_card, bg="#0d1b2a", fg=TEXT, font=FONT_MONO, height=8, state=tk.DISABLED, wrap=tk.NONE)
        self._clients_text.pack(fill=tk.BOTH, expand=True)

        self._user_list.insert(tk.END, "admin")

    def _build_client_tab(self) -> None:
        tab = self._tab_client
        tab.columnconfigure(0, weight=1)
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(2, weight=1)

        conn_card = self._card(tab, 0, 0)
        ttk.Label(conn_card, text="Connection", style="CardTitle.TLabel").grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 8))

        ttk.Label(conn_card, text="Server:", style="Card.TLabel").grid(row=1, column=0, sticky="w", padx=4)
        self._cli_host = ttk.Entry(conn_card, width=16)
        self._cli_host.insert(0, "127.0.0.1")
        self._cli_host.grid(row=1, column=1, padx=4)

        ttk.Label(conn_card, text="Port:", style="Card.TLabel").grid(row=1, column=2, sticky="w", padx=4)
        self._cli_port = ttk.Entry(conn_card, width=8)
        self._cli_port.insert(0, "8080")
        self._cli_port.grid(row=1, column=3, padx=4)

        ttk.Label(conn_card, text="Username:", style="Card.TLabel").grid(row=2, column=0, sticky="w", padx=4)
        self._cli_user = ttk.Entry(conn_card, width=16)
        self._cli_user.grid(row=2, column=1, padx=4)

        ttk.Label(conn_card, text="Password:", style="Card.TLabel").grid(row=2, column=2, sticky="w", padx=4)
        self._cli_pass = ttk.Entry(conn_card, width=16, show="*")
        self._cli_pass.grid(row=2, column=3, padx=4)

        socks_card = self._card(tab, 0, 1)
        ttk.Label(socks_card, text="SOCKS5 Proxy", style="CardTitle.TLabel").grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 8))

        self._socks_enabled = tk.BooleanVar(value=True)
        ttk.Checkbutton(socks_card, text="Enable SOCKS Proxy", variable=self._socks_enabled, style="TCheckbutton").grid(row=1, column=0, columnspan=2, sticky="w", padx=4)

        ttk.Label(socks_card, text="Port:", style="Card.TLabel").grid(row=2, column=0, sticky="w", padx=4)
        self._socks_port = ttk.Entry(socks_card, width=8)
        self._socks_port.insert(0, "1080")
        self._socks_port.grid(row=2, column=1, padx=4)

        ctrl_card = self._card(tab, 1, 0, colspan=2)
        btn_row = ttk.Frame(ctrl_card, style="Card.TFrame")
        btn_row.pack(fill=tk.X)
        self._cli_connect_btn = ttk.Button(btn_row, text="Connect", style="Green.TButton", command=self._connect_client)
        self._cli_connect_btn.pack(side=tk.LEFT, padx=4)
        self._cli_disconnect_btn = ttk.Button(btn_row, text="Disconnect", style="Danger.TButton", command=self._disconnect_client, state=tk.DISABLED)
        self._cli_disconnect_btn.pack(side=tk.LEFT, padx=4)

        self._cli_dot = self._status_dot(ctrl_card)
        self._cli_dot.pack(anchor="w", pady=4)
        self._cli_status_lbl = ttk.Label(ctrl_card, text="Disconnected", style="Card.TLabel")
        self._cli_status_lbl.pack(anchor="w")

        info_card = self._card(tab, 2, 0, colspan=2)
        ttk.Label(info_card, text="Connection Details", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 8))
        self._cli_info_text = tk.Text(info_card, bg="#0d1b2a", fg=TEXT, font=FONT_MONO, height=10, state=tk.DISABLED, wrap=tk.WORD)
        self._cli_info_text.pack(fill=tk.BOTH, expand=True)

    def _build_traffic_tab(self) -> None:
        tab = self._tab_traffic
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(0, weight=0)
        tab.rowconfigure(1, weight=1)
        tab.rowconfigure(2, weight=1)

        stats_card = self._card(tab, 0, 0)
        stats_card.columnconfigure(tuple(range(8)), weight=1)
        self._traffic_stats = {}
        items = [
            ("Bytes Sent", "t_sent"), ("Bytes Recv", "t_recv"),
            ("Pkts Sent", "t_psent"), ("Pkts Recv", "t_precv"),
            ("Enc Time", "t_enc"), ("Dec Time", "t_dec"),
            ("Enc Errors", "t_eerr"), ("Dec Errors", "t_derr"),
        ]
        for i, (label, key) in enumerate(items):
            ttk.Label(stats_card, text=label, style="CardDim.TLabel").grid(row=0, column=i, padx=2)
            lbl = ttk.Label(stats_card, text="0", style="CardTitle.TLabel")
            lbl.grid(row=1, column=i, padx=2)
            self._traffic_stats[key] = lbl

        graph_card = self._card(tab, 1, 0)
        ttk.Label(graph_card, text="Bandwidth (10s rolling)", style="CardTitle.TLabel").pack(anchor="w")
        self._bw_canvas = tk.Canvas(graph_card, bg="#0d1b2a", height=140, highlightthickness=0)
        self._bw_canvas.pack(fill=tk.BOTH, expand=True, pady=4)

        pkt_card = self._card(tab, 2, 0)
        pkt_header = ttk.Frame(pkt_card, style="Card.TFrame")
        pkt_header.pack(fill=tk.X)
        ttk.Label(pkt_header, text="Live Packet Log", style="CardTitle.TLabel").pack(side=tk.LEFT)
        ttk.Button(pkt_header, text="Clear", command=self._clear_packet_log).pack(side=tk.RIGHT, padx=4)

        ttk.Label(pkt_header, text="Filter:", style="CardDim.TLabel").pack(side=tk.RIGHT, padx=(8, 2))
        self._pkt_filter = ttk.Combobox(pkt_header, values=["ALL", "DATA", "KEEPALIVE", "SOCKS", "CONTROL"], width=10, state="readonly")
        self._pkt_filter.set("ALL")
        self._pkt_filter.pack(side=tk.RIGHT)

        self._pkt_text = tk.Text(pkt_card, bg="#0d1b2a", fg=TEXT, font=FONT_MONO_SM, height=12, state=tk.DISABLED, wrap=tk.NONE)
        pkt_scroll = ttk.Scrollbar(pkt_card, command=self._pkt_text.yview)
        self._pkt_text.configure(yscrollcommand=pkt_scroll.set)
        self._pkt_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        pkt_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self._pkt_text.tag_configure("DATA", foreground=BLUE)
        self._pkt_text.tag_configure("KEEPALIVE", foreground=TEXT_DIM)
        self._pkt_text.tag_configure("SOCKS", foreground=ORANGE)
        self._pkt_text.tag_configure("CONTROL", foreground=GREEN)
        self._pkt_text.tag_configure("ERROR", foreground=RED)

    def _build_logs_tab(self) -> None:
        tab = self._tab_logs
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        ctrl = self._card(tab, 0, 0)
        ctrl_row = ttk.Frame(ctrl, style="Card.TFrame")
        ctrl_row.pack(fill=tk.X)

        ttk.Label(ctrl_row, text="Level:", style="Card.TLabel").pack(side=tk.LEFT, padx=4)
        self._log_filter = ttk.Combobox(ctrl_row, values=["ALL", "INFO", "WARNING", "ERROR", "DEBUG"], width=10, state="readonly")
        self._log_filter.set("ALL")
        self._log_filter.pack(side=tk.LEFT, padx=4)

        ttk.Label(ctrl_row, text="Search:", style="Card.TLabel").pack(side=tk.LEFT, padx=(12, 4))
        self._log_search = ttk.Entry(ctrl_row, width=24)
        self._log_search.pack(side=tk.LEFT, padx=4)
        self._log_search.bind("<Return>", lambda e: self._apply_log_filter())
        ttk.Button(ctrl_row, text="Filter", command=self._apply_log_filter).pack(side=tk.LEFT, padx=4)

        ttk.Button(ctrl_row, text="Clear", command=self._clear_logs).pack(side=tk.RIGHT, padx=4)
        ttk.Button(ctrl_row, text="Export", command=self._export_logs).pack(side=tk.RIGHT, padx=4)

        self._log_scroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(ctrl_row, text="Auto-scroll", variable=self._log_scroll_var, style="TCheckbutton").pack(side=tk.RIGHT, padx=4)

        log_card = self._card(tab, 1, 0)
        self._log_text = tk.Text(log_card, bg="#0d1b2a", fg=TEXT, font=FONT_MONO, state=tk.DISABLED, wrap=tk.NONE)
        log_scroll_y = ttk.Scrollbar(log_card, command=self._log_text.yview)
        log_scroll_x = ttk.Scrollbar(log_card, orient=tk.HORIZONTAL, command=self._log_text.xview)
        self._log_text.configure(yscrollcommand=log_scroll_y.set, xscrollcommand=log_scroll_x.set)
        self._log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        self._log_text.tag_configure("INFO", foreground=TEXT)
        self._log_text.tag_configure("WARNING", foreground=ORANGE)
        self._log_text.tag_configure("ERROR", foreground=RED)
        self._log_text.tag_configure("DEBUG", foreground=TEXT_DIM)

    def _start_server(self) -> None:
        if self.vpn_server and self.vpn_server.running:
            return

        try:
            ip = self._srv_ip.get().strip()
            port = int(self._srv_port.get().strip())
            max_clients = int(self._srv_max.get().strip())
            subnet = self._srv_subnet.get().strip()

            config = SalsaConfig(
                server_host=ip, server_port=port,
                max_clients=max_clients, tunnel_subnet=subnet,
            )

            for i in range(self._user_list.size()):
                username = self._user_list.get(i)

                config.add_user(username, username)

            config.add_user("admin", "admin123")

            self.vpn_server = VPNServer(config=config)
            self.vpn_server.on_log = lambda msg, lvl: self._enqueue_log(msg, lvl, "SERVER")
            self.vpn_server.on_client_connect = lambda s: self._enqueue_log(f"Client connected: {s.username} ({s.assigned_ip})", "INFO", "SERVER")
            self.vpn_server.on_client_disconnect = lambda cid: self._enqueue_log(f"Client disconnected: {cid}", "INFO", "SERVER")

            if not self.vpn_server.start_server():
                self._enqueue_log("Failed to start server", "ERROR", "SERVER")
                return

            self._server_thread = threading.Thread(target=self.vpn_server.accept_connections, daemon=True, name="gui-server")
            self._server_thread.start()

            self._srv_start_btn.config(state=tk.DISABLED)
            self._srv_stop_btn.config(state=tk.NORMAL)
            self._dash_start_btn.config(state=tk.DISABLED)
            self._dash_stop_btn.config(state=tk.NORMAL)
            self._set_dot_color(self._srv_dot, GREEN)
            self._set_dot_color(self._dash_srv_dot, GREEN)
            self._srv_status_lbl.config(text=f"Running on {ip}:{port}")
            self._enqueue_log(f"Server started on {ip}:{port}", "INFO", "SERVER")

        except Exception as e:
            self._enqueue_log(f"Server start error: {e}", "ERROR", "SERVER")

    def _stop_server(self) -> None:
        if self.vpn_server:
            self.vpn_server.stop_server()
            self.vpn_server = None

        self._srv_start_btn.config(state=tk.NORMAL)
        self._srv_stop_btn.config(state=tk.DISABLED)
        self._dash_start_btn.config(state=tk.NORMAL)
        self._dash_stop_btn.config(state=tk.DISABLED)
        self._set_dot_color(self._srv_dot, RED)
        self._set_dot_color(self._dash_srv_dot, RED)
        self._srv_status_lbl.config(text="Stopped")
        self._dash_srv_info.config(text="Stopped")
        self._enqueue_log("Server stopped", "INFO", "SERVER")

    def _add_user(self) -> None:
        username = self._user_name.get().strip()
        password = self._user_pass.get().strip()
        if not username or not password:
            return

        items = list(self._user_list.get(0, tk.END))
        if username not in items:
            self._user_list.insert(tk.END, username)

        if self.vpn_server:
            self.vpn_server.config.add_user(username, password)
        self._user_name.delete(0, tk.END)
        self._user_pass.delete(0, tk.END)
        self._enqueue_log(f"User added: {username}", "INFO", "SERVER")

    def _remove_user(self) -> None:
        sel = self._user_list.curselection()
        if not sel:
            return
        username = self._user_list.get(sel[0])
        self._user_list.delete(sel[0])
        if self.vpn_server:
            self.vpn_server.config.remove_user(username)
        self._enqueue_log(f"User removed: {username}", "INFO", "SERVER")

    def _connect_client(self) -> None:
        if self.vpn_client and self.vpn_client.authenticated:
            return

        host = self._cli_host.get().strip()
        port_str = self._cli_port.get().strip()
        username = self._cli_user.get().strip()
        password = self._cli_pass.get().strip()

        if not username or not password:
            self._enqueue_log("Username and password required", "ERROR", "CLIENT")
            return

        try:
            port = int(port_str)
        except ValueError:
            self._enqueue_log("Invalid port number", "ERROR", "CLIENT")
            return

        self._cli_connect_btn.config(state=tk.DISABLED)
        self._set_dot_color(self._cli_dot, ORANGE)
        self._cli_status_lbl.config(text="Connecting...")

        def do_connect():
            self.vpn_client = VPNClient(server_host=host, server_port=port)
            self.vpn_client.on_log = lambda msg, lvl: self._enqueue_log(msg, lvl, "CLIENT")
            self.vpn_client.on_status_change = self._on_client_status

            if self.vpn_client.connect(username, password):
                self.root.after(0, self._client_connected)

                if self._socks_enabled.get():
                    self._start_socks_proxy()
            else:
                self.root.after(0, self._client_failed)

        threading.Thread(target=do_connect, daemon=True).start()

    def _client_connected(self) -> None:
        self._cli_disconnect_btn.config(state=tk.NORMAL)
        self._cli_connect_btn.config(state=tk.DISABLED)
        self._set_dot_color(self._cli_dot, GREEN)
        self._set_dot_color(self._dash_cli_dot, GREEN)
        ip = self.vpn_client.assigned_ip or ""
        self._cli_status_lbl.config(text=f"Connected (IP: {ip})")
        self._dash_cli_info.config(text=f"Connected to {self.vpn_client.server_host}:{self.vpn_client.server_port}\nIP: {ip}")

    def _client_failed(self) -> None:
        self._cli_connect_btn.config(state=tk.NORMAL)
        self._cli_disconnect_btn.config(state=tk.DISABLED)
        self._set_dot_color(self._cli_dot, RED)
        self._set_dot_color(self._dash_cli_dot, RED)
        self._cli_status_lbl.config(text="Connection Failed")
        self._dash_cli_info.config(text="Connection failed")

    def _disconnect_client(self) -> None:
        if self.socks_proxy:
            self.socks_proxy.stop()
            self.socks_proxy = None
        if self.vpn_client:
            self.vpn_client.disconnect()
            self.vpn_client = None

        self._cli_connect_btn.config(state=tk.NORMAL)
        self._cli_disconnect_btn.config(state=tk.DISABLED)
        self._set_dot_color(self._cli_dot, RED)
        self._set_dot_color(self._dash_cli_dot, RED)
        self._cli_status_lbl.config(text="Disconnected")
        self._dash_cli_info.config(text="Disconnected")
        self._enqueue_log("Client disconnected", "INFO", "CLIENT")

    def _on_client_status(self, status: str, detail: str) -> None:
        self._enqueue_log(f"Client status: {status} - {detail}", "INFO", "CLIENT")
        if status == "disconnected":

            self.root.after(0, self._client_disconnected_by_server, detail)

    def _client_disconnected_by_server(self, detail: str = "") -> None:
        if self.socks_proxy:
            self.socks_proxy.stop()
            self.socks_proxy = None

        self.vpn_client = None

        self._cli_connect_btn.config(state=tk.NORMAL)
        self._cli_disconnect_btn.config(state=tk.DISABLED)
        self._set_dot_color(self._cli_dot, RED)
        self._set_dot_color(self._dash_cli_dot, RED)
        msg = f"Disconnected: {detail}" if detail else "Disconnected"
        self._cli_status_lbl.config(text=msg)
        self._dash_cli_info.config(text=msg)

    def _start_socks_proxy(self) -> None:
        if not self.vpn_client:
            return
        try:
            socks_port = int(self._socks_port.get().strip())
        except ValueError:
            socks_port = 1080

        self.socks_proxy = SOCKSProxy(self.vpn_client)
        self.socks_proxy.on_log = lambda msg, lvl: self._enqueue_log(msg, lvl, "SOCKS")
        if self.socks_proxy.start("127.0.0.1", socks_port):
            self._enqueue_log(f"SOCKS5 proxy started on 127.0.0.1:{socks_port}", "INFO", "SOCKS")
        else:
            self._enqueue_log("Failed to start SOCKS5 proxy", "ERROR", "SOCKS")

    def _enqueue_log(self, message: str, level: str = "INFO", source: str = "SYSTEM") -> None:
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.log_queue.put((timestamp, level, source, message))

    def _process_log_queue(self) -> None:
        count = 0
        while count < 100:
            try:
                ts, level, source, msg = self.log_queue.get_nowait()
                self._log_entries.append((ts, level, source, msg))

                selected_level = self._log_filter.get()
                search = self._log_search.get().strip().lower()

                if selected_level != "ALL" and level != selected_level:
                    count += 1
                    continue
                if search and search not in msg.lower() and search not in source.lower():
                    count += 1
                    continue

                line = f"[{ts}] [{level:7s}] [{source:6s}] {msg}\n"
                self._log_text.config(state=tk.NORMAL)
                self._log_text.insert(tk.END, line, level)
                if self._log_scroll_var.get():
                    self._log_text.see(tk.END)
                self._log_text.config(state=tk.DISABLED)

                if source in ("TUNNEL", "SOCKS"):
                    self._add_packet_entry(ts, level, source, msg)

                count += 1
            except queue.Empty:
                break

    def _add_packet_entry(self, ts: str, level: str, source: str, msg: str) -> None:
        pkt_filter = self._pkt_filter.get()
        tag = "DATA"
        msg_upper = msg.upper()
        if "KEEPALIVE" in msg_upper:
            tag = "KEEPALIVE"
        elif "SOCKS" in msg_upper:
            tag = "SOCKS"
        elif any(k in msg_upper for k in ("HANDSHAKE", "CONFIG", "DISCONNECT", "CONNECT")):
            tag = "CONTROL"
        elif "ERROR" in msg_upper or level == "ERROR":
            tag = "ERROR"

        if pkt_filter != "ALL" and tag != pkt_filter:
            return

        line = f"[{ts}] [{source}] {msg}\n"
        self._pkt_text.config(state=tk.NORMAL)
        self._pkt_text.insert(tk.END, line, tag)
        self._pkt_text.see(tk.END)
        self._pkt_text.config(state=tk.DISABLED)

    def _apply_log_filter(self) -> None:
        self._log_text.config(state=tk.NORMAL)
        self._log_text.delete("1.0", tk.END)
        selected_level = self._log_filter.get()
        search = self._log_search.get().strip().lower()
        for ts, level, source, msg in self._log_entries:
            if selected_level != "ALL" and level != selected_level:
                continue
            if search and search not in msg.lower() and search not in source.lower():
                continue
            line = f"[{ts}] [{level:7s}] [{source:6s}] {msg}\n"
            self._log_text.insert(tk.END, line, level)
        self._log_text.see(tk.END)
        self._log_text.config(state=tk.DISABLED)

    def _clear_logs(self) -> None:
        self._log_entries.clear()
        self._log_text.config(state=tk.NORMAL)
        self._log_text.delete("1.0", tk.END)
        self._log_text.config(state=tk.DISABLED)

    def _export_logs(self) -> None:
        filename = filedialog.asksaveasfilename(defaultextension=".log", filetypes=[("Log files", "*.log"), ("Text files", "*.txt")])
        if filename:
            with open(filename, "w") as f:
                for ts, level, source, msg in self._log_entries:
                    f.write(f"[{ts}] [{level}] [{source}] {msg}\n")
            self._enqueue_log(f"Logs exported to {filename}", "INFO", "SYSTEM")

    def _clear_packet_log(self) -> None:
        self._pkt_text.config(state=tk.NORMAL)
        self._pkt_text.delete("1.0", tk.END)
        self._pkt_text.config(state=tk.DISABLED)

    def _update_stats(self) -> None:
        server_running = self.vpn_server and self.vpn_server.running
        client_connected = self.vpn_client and self.vpn_client.authenticated

        total_stats = {
            "bytes_sent": 0, "bytes_received": 0,
            "packets_sent": 0, "packets_received": 0,
            "encryption_time": 0.0, "decryption_time": 0.0,
            "encryption_errors": 0, "decryption_errors": 0,
            "uptime": 0,
        }

        if server_running:
            agg = self.vpn_server.get_aggregate_tunnel_stats()
            for k in total_stats:
                if k in agg:
                    total_stats[k] += agg[k]
            srv_stats = self.vpn_server.get_server_stats()
            total_stats["uptime"] = max(total_stats["uptime"], srv_stats.get("uptime", 0))

        if client_connected:
            cli_status = self.vpn_client.get_status()
            for k in ("bytes_sent", "bytes_received", "packets_sent", "packets_received", "encryption_time", "decryption_time"):
                total_stats[k] += cli_status.get(k, 0)
            total_stats["uptime"] = max(total_stats["uptime"], cli_status.get("uptime", 0))

        self._dash_stats["uptime"].config(text=self._fmt_time(total_stats["uptime"]))
        self._dash_stats["bytes_sent"].config(text=self._fmt_bytes(total_stats["bytes_sent"]))
        self._dash_stats["bytes_recv"].config(text=self._fmt_bytes(total_stats["bytes_received"]))
        self._dash_stats["enc_time"].config(text=f"{total_stats['encryption_time']:.3f}s")
        self._dash_stats["packets"].config(text=str(total_stats["packets_sent"] + total_stats["packets_received"]))

        num_clients = len(self.vpn_server.clients) if server_running else 0
        self._dash_stats["clients"].config(text=str(num_clients))

        if server_running and client_connected:
            self._set_dot_color(self._dash_dot, GREEN)
            self._dash_status.config(text="Active")
            self._dash_detail.config(text=f"Server running, client connected ({self.vpn_client.assigned_ip})")
        elif server_running:
            self._set_dot_color(self._dash_dot, BLUE)
            self._dash_status.config(text="Server Running")
            self._dash_detail.config(text=f"{num_clients} client(s) connected")
        elif client_connected:
            self._set_dot_color(self._dash_dot, GREEN)
            self._dash_status.config(text="Client Connected")
            self._dash_detail.config(text=f"Connected to {self.vpn_client.server_host}")
        else:
            self._set_dot_color(self._dash_dot, RED)
            self._dash_status.config(text="Disconnected")
            self._dash_detail.config(text="No active connections")

        if server_running:
            srv = self.vpn_server.get_server_stats()
            info = f"Running on {self.vpn_server.config.server_host}:{self.vpn_server.config.server_port}\n"
            info += f"Clients: {srv['active_clients']}/{srv['max_clients']}\n"
            info += f"Uptime: {self._fmt_time(srv['uptime'])}"
            self._dash_srv_info.config(text=info)

        if server_running:
            srv = self.vpn_server.get_server_stats()
            lines = ["Username        IP              Tunnel     Bytes In      Bytes Out"]
            lines.append("-" * 70)
            for c in srv.get("clients", []):
                lines.append(
                    f"{c['username']:<15} {c['assigned_ip']:<15} {c['tunnel_state']:<10} "
                    f"{self._fmt_bytes(c['bytes_received']):<13} {self._fmt_bytes(c['bytes_sent'])}"
                )
            text = "\n".join(lines) if srv.get("clients") else "No clients connected"
            self._clients_text.config(state=tk.NORMAL)
            self._clients_text.delete("1.0", tk.END)
            self._clients_text.insert("1.0", text)
            self._clients_text.config(state=tk.DISABLED)

        if client_connected:
            status = self.vpn_client.get_status()
            socks_info = ""
            if self.socks_proxy and self.socks_proxy.running:
                socks_stats = self.socks_proxy.get_stats()
                socks_info = (
                    f"\nSOCKS5 Proxy: 127.0.0.1:{self.socks_proxy.port}"
                    f"\n  Active: {socks_stats['active_connections']} | Total: {socks_stats['total_connections']}"
                    f"\n  Bytes proxied: {self._fmt_bytes(socks_stats['bytes_proxied'])}"
                )
            info = (
                f"Server: {status['server']}\n"
                f"Client ID: {status['client_id']}\n"
                f"Assigned IP: {status['assigned_ip']}\n"
                f"Tunnel State: {status['tunnel_state']}\n"
                f"Uptime: {self._fmt_time(status['uptime'])}\n"
                f"Bytes Sent: {self._fmt_bytes(status['bytes_sent'])}\n"
                f"Bytes Received: {self._fmt_bytes(status['bytes_received'])}\n"
                f"Packets: {status['packets_sent']} sent / {status['packets_received']} recv\n"
                f"Encryption: {status['encryption_time']:.4f}s\n"
                f"Decryption: {status['decryption_time']:.4f}s"
                f"{socks_info}"
            )
            self._cli_info_text.config(state=tk.NORMAL)
            self._cli_info_text.delete("1.0", tk.END)
            self._cli_info_text.insert("1.0", info)
            self._cli_info_text.config(state=tk.DISABLED)

        self._traffic_stats["t_sent"].config(text=self._fmt_bytes(total_stats["bytes_sent"]))
        self._traffic_stats["t_recv"].config(text=self._fmt_bytes(total_stats["bytes_received"]))
        self._traffic_stats["t_psent"].config(text=str(total_stats["packets_sent"]))
        self._traffic_stats["t_precv"].config(text=str(total_stats["packets_received"]))
        self._traffic_stats["t_enc"].config(text=f"{total_stats['encryption_time']:.3f}s")
        self._traffic_stats["t_dec"].config(text=f"{total_stats['decryption_time']:.3f}s")
        self._traffic_stats["t_eerr"].config(text=str(total_stats["encryption_errors"]))
        self._traffic_stats["t_derr"].config(text=str(total_stats["decryption_errors"]))

        bps = total_stats["bytes_sent"] + total_stats["bytes_received"]
        self._bw_history.append((time.time(), bps))
        if len(self._bw_history) > self._max_bw_points:
            self._bw_history = self._bw_history[-self._max_bw_points:]
        self._draw_bandwidth_graph()

    def _draw_bandwidth_graph(self) -> None:
        canvas = self._bw_canvas
        canvas.delete("all")
        w = canvas.winfo_width()
        h = canvas.winfo_height()
        if w < 50 or h < 30 or len(self._bw_history) < 2:
            return

        deltas = []
        for i in range(1, len(self._bw_history)):
            dt = self._bw_history[i][0] - self._bw_history[i - 1][0]
            db = self._bw_history[i][1] - self._bw_history[i - 1][1]
            bps = max(0, db / dt) if dt > 0 else 0
            deltas.append(bps)

        if not deltas:
            return

        max_bps = max(max(deltas), 1)
        padding = 10
        graph_w = w - 2 * padding
        graph_h = h - 2 * padding

        for i in range(5):
            y = padding + (graph_h * i / 4)
            canvas.create_line(padding, y, w - padding, y, fill="#1a2a3a", dash=(2, 4))
            val = max_bps * (4 - i) / 4
            canvas.create_text(padding + 2, y - 8, text=self._fmt_bytes(val) + "/s", fill=TEXT_DIM, font=FONT_MONO_SM, anchor="w")

        points = []
        for i, bps in enumerate(deltas):
            x = padding + (graph_w * i / max(len(deltas) - 1, 1))
            y = padding + graph_h - (graph_h * bps / max_bps)
            points.append((x, y))

        if len(points) >= 2:

            fill_points = [(padding, padding + graph_h)] + points + [(points[-1][0], padding + graph_h)]
            flat = [coord for p in fill_points for coord in p]
            canvas.create_polygon(flat, fill="#0f3460", outline="")

            flat_line = [coord for p in points for coord in p]
            canvas.create_line(flat_line, fill=BLUE, width=2, smooth=True)

    @staticmethod
    def _fmt_bytes(b: float) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if abs(b) < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} TB"

    @staticmethod
    def _fmt_time(seconds: float) -> str:
        s = int(seconds)
        h, s = divmod(s, 3600)
        m, s = divmod(s, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def _update_loop(self) -> None:
        self._process_log_queue()
        self._update_stats()
        self.root.after(1000, self._update_loop)

    def shutdown(self) -> None:
        if self.socks_proxy:
            self.socks_proxy.stop()
        if self.vpn_client:
            self.vpn_client.disconnect()
        if self.vpn_server:
            self.vpn_server.stop_server()

def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    root = tk.Tk()
    app = VPNGUIManager(root)

    def on_closing():
        app.shutdown()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
