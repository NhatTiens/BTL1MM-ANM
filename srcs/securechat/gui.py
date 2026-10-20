"""Tkinter chat application: launch with ``python -m securechat.gui``.

User interface only. Cryptography and packet routing remain in the existing
securechat session/transfer/protocol modules, preserving the team's API.
"""
from __future__ import annotations

import argparse
import queue
import re
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any, Callable

from . import crypto
from .gui_client import GuiChatClient
from .server import RelayServer

# A small, dependency-free visual theme. Do not require a third-party UI kit.
# Bright, airy palette; keep all functionality and network code unchanged.
BG = "#f5f9ff"          # Main background: very pale sky blue
NAVY = "#24486d"        # Primary readable headings
PANEL = "#ffffff"       # Clean white surfaces
TEAL = "#168b9d"        # Accessible primary actions
TEAL_HOVER = "#106e80"
TEXT = "#24364b"        # Soft ink, not pure black
MUTED = "#637c91"       # Secondary text on white
LIGHT = "#e9f8fb"       # Incoming messages / selection accents
BORDER = "#dce8f3"      # Soft dividing lines
ENTRY_BG = "#ffffff"
STATUS_OK = "#19795d"
STATUS_IDLE = "#966300"
FONT = "Segoe UI"
ROOT = Path(".local")
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,24}$")


class ChatWindow:
    def __init__(self, root: tk.Tk, name: str = "", mssvs: str = "", host: str = "127.0.0.1", port: int = 9009) -> None:
        self.root = root
        root.title("SecureChat · E2EE Messenger")
        root.geometry("1090x710")
        root.minsize(830, 590)
        root.configure(bg=BG)
        root.protocol("WM_DELETE_WINDOW", self._on_close)

        self.events: queue.Queue[dict[str, Any]] = queue.Queue()
        self.client: GuiChatClient | None = None
        self.local_server: RelayServer | None = None
        self.server_thread: threading.Thread | None = None
        self.selected_peer: str | None = None
        self.connected = False
        self.is_closing = False
        self.messages: dict[str, list[tuple[str, str]]] = {}
        self.peers: list[str] = []
        self.name_var = tk.StringVar(value=name or "alice")
        self.mssvs_var = tk.StringVar(value=mssvs or "2312345,2312346")
        self.host_var = tk.StringVar(value=host)
        self.port_var = tk.StringVar(value=str(port))
        self.status_var = tk.StringVar(value="Chưa kết nối")
        self.title_var = tk.StringVar(value="Chọn một người dùng để bắt đầu trò chuyện")
        self.editor_var = tk.StringVar()

        style = ttk.Style(root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Primary.TButton", font=(FONT, 10, "bold"), padding=(13, 10),
                        background=TEAL, foreground="white", borderwidth=0)
        style.map("Primary.TButton", background=[("active", TEAL_HOVER),
                                                    ("disabled", "#d5e5ed")],
                  foreground=[("disabled", MUTED)])
        style.configure("Action.TButton", font=(FONT, 10), padding=(11, 9),
                        background="#eaf5fc", foreground=NAVY, borderwidth=0)
        style.map("Action.TButton", background=[("active", "#d5ecf8"),
                                                  ("disabled", "#edf3f8")])
        style.configure("Chat.TEntry", padding=10, font=(FONT, 11),
                        fieldbackground=ENTRY_BG, foreground=TEXT)
        style.configure("TEntry", padding=5, fieldbackground=ENTRY_BG, foreground=TEXT)
        self._build()
        self.root.after(80, self._drain_events)

    def _build(self) -> None:
        # White toolbar keeps the entire app bright, including connection status.
        header = tk.Frame(self.root, bg=PANEL, height=78,
                          highlightbackground=BORDER, highlightthickness=1)
        header.pack(side="top", fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="✦  SecureChat", font=(FONT, 21, "bold"),
                 fg=NAVY, bg=PANEL).pack(side="left", padx=(24, 18))
        tk.Label(header, text="Chat & chia sẻ file được mã hóa đầu cuối",
                 font=(FONT, 10), fg=MUTED, bg=PANEL).pack(side="left", pady=3)
        self.status_label = tk.Label(header, textvariable=self.status_var,
                                     font=(FONT, 10, "bold"), fg=STATUS_IDLE, bg=LIGHT,
                                     padx=13, pady=8)
        self.status_label.pack(side="right", padx=23)

        setup = tk.Frame(self.root, bg=PANEL, padx=18, pady=14,
                         highlightbackground=BORDER, highlightthickness=1)
        setup.pack(fill="x", padx=18, pady=(15, 12))
        self._field(setup, "Tên", self.name_var, 12)
        self._field(setup, "MSSV nhóm (phân cách dấu phẩy)", self.mssvs_var, 32)
        self._field(setup, "Host", self.host_var, 15)
        self._field(setup, "Port", self.port_var, 7)
        self.connect_button = ttk.Button(setup, text="Kết nối", style="Primary.TButton",
                                         command=self._connect)
        self.connect_button.pack(side="left", padx=(7, 4), pady=(18, 0))
        self.server_button = ttk.Button(setup, text="Chạy Server local", style="Action.TButton",
                                        command=self._start_local_server)
        self.server_button.pack(side="left", padx=4, pady=(18, 0))

        body = tk.PanedWindow(self.root, orient="horizontal", sashwidth=9,
                              sashrelief="flat", bg=BG, relief="flat", bd=0)
        body.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        side = tk.Frame(body, bg=PANEL, width=245, padx=16, pady=17,
                        highlightbackground=BORDER, highlightthickness=1)
        body.add(side, minsize=205)
        tk.Label(side, text="●  ĐANG TRỰC TUYẾN", font=(FONT, 10, "bold"),
                 fg=MUTED, bg=PANEL).pack(anchor="w", pady=(3, 10))
        self.peer_list = tk.Listbox(side, activestyle="none", font=(FONT, 12),
                                    selectmode="browse", bd=0, highlightthickness=0,
                                    bg="#f3faff", fg=TEXT, selectbackground="#caedf8",
                                    selectforeground=NAVY, exportselection=False,
                                    selectborderwidth=0)
        self.peer_list.pack(fill="both", expand=True)
        self.peer_list.bind("<<ListboxSelect>>", self._on_select_peer)
        ttk.Button(side, text="↻  Làm mới danh sách", style="Action.TButton", command=self._refresh).pack(fill="x", pady=(12, 4))
        ttk.Button(side, text="Tạo khóa demo Alice / Bob", style="Action.TButton", command=self._demo_keys).pack(fill="x", pady=3)
        tk.Label(side, text="Khóa công khai phải được xác minh\ntrước khi tin cậy ngoài môi trường demo.",
                 font=(FONT, 9), justify="left", wraplength=205, fg=MUTED, bg=PANEL).pack(anchor="w", pady=(13, 2))

        center = tk.Frame(body, bg=PANEL, padx=19, pady=15,
                          highlightbackground=BORDER, highlightthickness=1)
        body.add(center, minsize=480)
        topbar = tk.Frame(center, bg=PANEL)
        topbar.pack(fill="x", pady=(2, 9))
        tk.Label(topbar, textvariable=self.title_var, font=(FONT, 13, "bold"),
                 fg=TEXT, bg=PANEL).pack(side="left", anchor="w")
        self.secure_button = ttk.Button(topbar, text="🔒 Thiết lập khóa", style="Action.TButton", command=self._secure_selected)
        self.secure_button.pack(side="right")

        self.history = scrolledtext.ScrolledText(center, state="disabled", wrap="word",
                        borderwidth=0, highlightthickness=1, highlightbackground=BORDER,
                        highlightcolor=BORDER, background="#f8fcff",
                        foreground=TEXT, font=(FONT, 11), padx=17, pady=17, spacing3=9)
        self.history.pack(fill="both", expand=True)
        self.history.tag_configure("me", justify="right", foreground="#146a91",
                                   lmargin1=70, lmargin2=70, rmargin=12, spacing1=8)
        self.history.tag_configure("them", justify="left", foreground=NAVY,
                                   lmargin1=12, lmargin2=12, rmargin=70, spacing1=8)
        self.history.tag_configure("system", justify="center", foreground=MUTED,
                                   spacing1=7, spacing3=7)

        composer = tk.Frame(center, bg=PANEL)
        composer.pack(fill="x", pady=(12, 2))
        self.entry = ttk.Entry(composer, textvariable=self.editor_var, style="Chat.TEntry")
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 9))
        self.entry.bind("<Return>", self._send_enter)
        self.attach_button = ttk.Button(composer, text="📎 File", style="Action.TButton", command=self._send_file)
        self.attach_button.pack(side="left", padx=(0, 7))
        self.send_button = ttk.Button(composer, text="Gửi ➤", style="Primary.TButton", command=self._send_message)
        self.send_button.pack(side="left")
        self._update_enabled()

    def _field(self, parent: tk.Frame, label: str, variable: tk.StringVar, width: int) -> None:
        frame = tk.Frame(parent, bg=PANEL)
        frame.pack(side="left", padx=(0, 9))
        tk.Label(frame, text=label, font=(FONT, 9), fg=MUTED, bg=PANEL).pack(anchor="w")
        entry = ttk.Entry(frame, textvariable=variable, width=width)
        entry.pack(pady=(3, 0))
        if variable is self.name_var:
            self.name_entry = entry
        elif variable is self.mssvs_var:
            self.mssvs_entry = entry
        elif variable is self.host_var:
            self.host_entry = entry
        else:
            self.port_entry = entry

    def _add_line(self, peer: str, who: str, text: str) -> None:
        self.messages.setdefault(peer, []).append((who, text))
        if self.selected_peer == peer:
            self._write_line(who, text)

    def _write_line(self, who: str, content: str) -> None:
        self.history.configure(state="normal")
        prefix = "Bạn:  " if who == "me" else ("" if who == "system" else f"{self.selected_peer}:  ")
        self.history.insert("end", prefix + content + "\n", who)
        self.history.configure(state="disabled")
        self.history.see("end")

    def _show_peer(self, peer: str) -> None:
        self.selected_peer = peer
        self.title_var.set(f"●  {peer}  ·  Mã hóa đầu cuối")
        self.history.configure(state="normal")
        self.history.delete("1.0", "end")
        self.history.configure(state="disabled")
        for who, content in self.messages.get(peer, []):
            self._write_line(who, content)
        self._update_enabled()
        self.entry.focus_set()

    def _on_select_peer(self, _event: Any) -> None:
        indexes = self.peer_list.curselection()
        if indexes:
            self._show_peer(self.peer_list.get(indexes[0]))

    def _update_enabled(self) -> None:
        active = self.connected and self.selected_peer is not None
        state = "normal" if active else "disabled"
        self.entry.configure(state=state)
        self.send_button.configure(state=state)
        self.attach_button.configure(state=state)
        self.secure_button.configure(state=state)
        self.connect_button.configure(state="disabled" if self.connected or (self.client is not None) else "normal")
        for entry in (self.name_entry, self.mssvs_entry, self.host_entry, self.port_entry):
            entry.configure(state="disabled" if self.connected or self.client else "normal")

    def _spawn(self, action: Callable[[], None]) -> None:
        def worker() -> None:
            try:
                action()
            except Exception as exc:
                self.events.put({"kind": "ui_error", "message": f"{type(exc).__name__}: {exc}"})
        threading.Thread(target=worker, daemon=True, name="gui-operation").start()

    def _connect(self) -> None:
        name = self.name_var.get().strip()
        if not NAME_RE.fullmatch(name):
            messagebox.showerror("Tên không hợp lệ", "Chỉ dùng chữ, số, dấu _ hoặc -, tối đa 24 ký tự.")
            return
        try:
            mssvs = [x.strip() for x in self.mssvs_var.get().split(",")]
            crypto.validate_mssvs(mssvs)
            port = int(self.port_var.get())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror("Thông tin chưa hợp lệ", "Điền 2 đến 4 MSSV dạng số và port từ 1 đến 65535.")
            return
        self.status_var.set("Đang kết nối…")
        self.status_label.configure(fg=STATUS_IDLE)
        self.client = GuiChatClient(name, mssvs,
                    ROOT / "identities" / name, ROOT / "trusted" / name,
                    ROOT / "received" / name, self.host_var.get().strip(), port,
                    self.events.put)
        self._update_enabled()
        client = self.client
        self._spawn(lambda: client.connect())

    def _start_local_server(self) -> None:
        if self.local_server is not None:
            messagebox.showinfo("Server", "Server local đã được khởi động trong cửa sổ này.")
            return
        if self.host_var.get().strip() not in {"127.0.0.1", "localhost"}:
            messagebox.showerror("Chỉ dùng localhost", "Server tích hợp chỉ lắng nghe 127.0.0.1.")
            return
        try:
            port = int(self.port_var.get())
            self.local_server = RelayServer(("127.0.0.1", port))
        except (ValueError, OSError) as exc:
            messagebox.showerror("Không thể khởi động Server", str(exc))
            return
        server = self.local_server
        self.server_thread = threading.Thread(target=server.serve_forever,
                   kwargs={"poll_interval": 0.1}, daemon=True, name="gui-local-server")
        self.server_thread.start()
        self.server_button.configure(state="disabled")
        messagebox.showinfo("Server local", f"Server đã mở tại 127.0.0.1:{port}.\nMở thêm cửa sổ GUI để chạy Bob.")

    def _demo_keys(self) -> None:
        from .demo_setup import setup
        root = ROOT
        required = [root / "identities" / n / "private.pem" for n in ("alice", "bob")]
        required += [root / "trusted" / "alice" / "bob.pem",
                     root / "trusted" / "bob" / "alice.pem"]
        if all(f.is_file() for f in required):
            messagebox.showinfo("Khóa demo", "Khóa Alice/Bob đã có sẵn trong .local/. Không tạo đè khóa cũ.")
            return
        if any(f.exists() for f in required):
            messagebox.showwarning("Khóa chưa đồng bộ",
                "Một số khóa demo đã tồn tại. Kiểm tra .local/ trước khi khởi tạo để tránh ghi đè hoặc tin nhầm khóa.")
            return
        if not messagebox.askyesno("Chỉ dành cho demo local",
            "Tạo khóa Alice/Bob và tự cấp trust để DEMO trên localhost?\n"
            "Không dùng cơ chế tự tin khóa này ở môi trường thực tế."):
            return
        self._spawn(lambda: (setup(root), self.events.put({"kind": "setup_ready"})))

    def _refresh(self) -> None:
        if self.client and self.connected:
            self._spawn(self.client.request_peers)

    def _secure_selected(self) -> None:
        if self.client and self.selected_peer:
            peer = self.selected_peer
            self._spawn(lambda: self.client.establish_session(peer))

    def _send_enter(self, _event: Any) -> str:
        self._send_message()
        return "break"

    def _send_message(self) -> None:
        if not self.client or not self.selected_peer or not self.connected:
            return
        text = self.editor_var.get()
        if not text.strip():
            return
        self.editor_var.set("")
        peer = self.selected_peer
        self._spawn(lambda: self.client.send_message(peer, text))

    def _send_file(self) -> None:
        if not self.client or not self.selected_peer or not self.connected:
            return
        selected = filedialog.askopenfilename(title="Chọn file gửi (tối đa 20 MiB)")
        if not selected:
            return
        peer = self.selected_peer
        self._add_line(peer, "system", f"Đang mã hóa và gửi file: {Path(selected).name}…")
        self._spawn(lambda: self.client.send_encrypted_file(peer, Path(selected)))

    def _set_peers(self, names: list[str]) -> None:
        self.peers = sorted(n for n in names if isinstance(n, str) and n != self.name_var.get().strip())
        self.peer_list.delete(0, "end")
        for name in self.peers:
            self.peer_list.insert("end", name)
        if self.selected_peer in self.peers:
            idx = self.peers.index(self.selected_peer)
            self.peer_list.selection_set(idx)
        elif self.peers:
            self.peer_list.selection_set(0)
            self._show_peer(self.peers[0])
        else:
            self.selected_peer = None
            self.title_var.set("Chưa có người dùng khác trực tuyến")
            self._update_enabled()

    def _drain_events(self) -> None:
        if self.is_closing:
            return
        try:
            for _ in range(100):
                event = self.events.get_nowait()
                kind = event.get("kind")
                peer = str(event.get("peer", ""))
                if kind == "connected":
                    self.connected = True
                    self.status_var.set(f"●  Đã kết nối · {self.name_var.get()}")
                    self.status_label.configure(fg=STATUS_OK)
                    self._set_peers(event.get("peers", []))
                    if self.client:
                        self._spawn(self.client.request_peers)
                elif kind == "disconnected":
                    self.connected = False
                    self.status_var.set("Đã ngắt kết nối")
                    self.status_label.configure(fg=STATUS_IDLE)
                    self._update_enabled()
                elif kind == "peers":
                    self._set_peers(event["peers"])
                elif kind == "message_received":
                    self._add_line(peer, "them", event["message"])
                elif kind == "message_sent":
                    self._add_line(peer, "me", event["message"])
                elif kind == "session_received":
                    self._add_line(peer, "system", "✓ Đã xác thực phiên và khóa công khai đã ghim")
                elif kind == "session_ready":
                    self._add_line(peer, "system", "🔒 " + event["message"])
                elif kind == "file_receiving":
                    self._add_line(peer, "system", "📎 Đang nhận file mã hóa…")
                elif kind == "file_received":
                    self._add_line(peer, "system", f"✓ Đã kiểm tra hash và lưu file: {event['path']}")
                elif kind == "file_sent":
                    self._add_line(peer, "me", f"📎 Đã gửi file: {Path(event['path']).name}")
                elif kind == "setup_ready":
                    messagebox.showinfo("Hoàn tất", "Đã tạo khóa demo Alice/Bob dưới .local/.")
                elif kind in {"ui_error", "security_error", "warning"}:
                    error = str(event.get("message", "Lỗi không xác định"))
                    self.status_var.set("⚠ " + error[:70])
                    if kind == "ui_error" and not self.connected and self.client:
                        self.client.close()
                        self.client = None
                    if kind == "security_error":
                        messagebox.showerror("Lỗi an toàn/giao thức", error)
                    elif kind == "ui_error":
                        messagebox.showerror("Lỗi thao tác", error)
                    self._update_enabled()
        except queue.Empty:
            pass
        finally:
            if not self.is_closing:
                self.root.after(80, self._drain_events)

    def _on_close(self) -> None:
        self.is_closing = True
        if self.client:
            self.client.close()
        if self.local_server:
            server = self.local_server
            def shutdown() -> None:
                server.shutdown()
                server.server_close()
            threading.Thread(target=shutdown, daemon=True).start()
        self.root.destroy()


def main() -> None:
    parser = argparse.ArgumentParser(description="E2EE Chat graphical interface")
    parser.add_argument("--name", default="", help="Alice or Bob")
    parser.add_argument("--mssvs", default="", help="Comma-separated team MSSVs")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9009)
    args = parser.parse_args()
    root = tk.Tk()
    ChatWindow(root, args.name, args.mssvs, args.host, args.port)
    root.mainloop()


if __name__ == "__main__":
    main()
