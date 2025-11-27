"""Simple Tkinter-based GUI to inspect and manage wallets."""

from __future__ import annotations

import json
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

import qrcode
from PIL import Image, ImageTk

from . import crypto_utils
from .wallet import Wallet


def _format_point(point) -> str:
    """Return a short hex representation of an elliptic curve point."""

    return crypto_utils.point_to_bytes(point).hex()


class WalletGUI:
    """Tkinter GUI helping users inspect wallet keys and transactions."""

    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("Privacy Wallet")

        self.wallet: Wallet | None = None

        self.view_private_var = tk.StringVar()
        self.spend_private_var = tk.StringVar()
        self.view_public_var = tk.StringVar()
        self.spend_public_var = tk.StringVar()
        self.address_var = tk.StringVar()

        self.view_private_entry: ttk.Entry | None = None
        self.spend_private_entry: ttk.Entry | None = None
        self.mnemonic_entry: ttk.Entry | None = None
        self.mnemonic_text: scrolledtext.ScrolledText | None = None
        self.transaction_text: scrolledtext.ScrolledText | None = None
        self.address_entry: ttk.Entry | None = None
        self.qr_code_canvas: tk.Canvas | None = None
        self.qr_code_image: ImageTk.PhotoImage | None = None

        self._build_layout()
        self.generate_wallet()

    # ------------------------------------------------------------------
    # Layout helpers
    def _build_layout(self) -> None:
        """Build the main GUI layout."""

        main = ttk.Frame(self.root, padding=16)
        main.grid(column=0, row=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        notebook = ttk.Notebook(main)
        notebook.grid(column=0, row=0, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(0, weight=1)

        self._build_wallet_tab(notebook)
        self._build_restore_tab(notebook)
        self._build_tx_tab(notebook)

    def _build_wallet_tab(self, notebook: ttk.Notebook) -> None:
        """Build the wallet tab."""

        parent = ttk.Frame(notebook, padding=12)
        notebook.add(parent, text="Wallet")

        wallet_frame = ttk.LabelFrame(parent, text="Wallet Keys", padding=12)
        wallet_frame.grid(column=0, row=0, sticky="nsew")
        parent.columnconfigure(0, weight=1)

        self._add_labeled_entry(wallet_frame, "View private", self.view_private_var, 0)
        self._add_labeled_entry(wallet_frame, "Spend private", self.spend_private_var, 1)
        self._add_labeled_entry(wallet_frame, "View public", self.view_public_var, 2)
        self._add_labeled_entry(wallet_frame, "Spend public", self.spend_public_var, 3)
        self._add_labeled_entry(wallet_frame, "Address", self.address_var, 4)

        for child in wallet_frame.winfo_children():
            child.grid_configure(pady=2, padx=4)

        qr_frame = ttk.LabelFrame(parent, text="Address QR Code", padding=12)
        qr_frame.grid(column=1, row=0, rowspan=2, sticky="nsew", padx=(12, 0))
        self.qr_code_canvas = tk.Canvas(qr_frame, width=256, height=256)
        self.qr_code_canvas.pack()

        mnemonic_frame = ttk.LabelFrame(parent, text="Mnemonic Phrase", padding=12)
        mnemonic_frame.grid(column=0, row=1, columnspan=2, sticky="nsew", pady=(12, 0))
        self.mnemonic_text = scrolledtext.ScrolledText(
            mnemonic_frame, height=3, width=80, wrap=tk.WORD
        )
        self.mnemonic_text.grid(column=0, row=0, sticky="nsew")
        self.mnemonic_text.configure(state="disabled")
        mnemonic_frame.columnconfigure(0, weight=1)
        mnemonic_frame.rowconfigure(0, weight=1)

        btn_frame = ttk.Frame(parent)
        btn_frame.grid(column=0, row=2, sticky="ew", pady=(12, 0))
        ttk.Button(btn_frame, text="Generate wallet", command=self.generate_wallet).pack(
            side=tk.LEFT
        )
        ttk.Button(btn_frame, text="Copy address", command=self.copy_address).pack(
            side=tk.LEFT, padx=(8, 0)
        )

    def _build_restore_tab(self, notebook: ttk.Notebook) -> None:
        """Build the restore tab."""

        parent = ttk.Frame(notebook, padding=12)
        notebook.add(parent, text="Restore")

        restore_frame = ttk.LabelFrame(
            parent, text="Restore from private keys", padding=12
        )
        restore_frame.grid(column=0, row=0, sticky="ew", pady=(12, 0))
        self.view_private_entry = self._add_simple_entry(
            restore_frame, "View private", 0, placeholder="decimal or 0x..."
        )
        self.spend_private_entry = self._add_simple_entry(
            restore_frame, "Spend private", 1, placeholder="decimal or 0x..."
        )
        ttk.Button(
            restore_frame, text="Restore", command=self.restore_from_inputs
        ).grid(column=0, row=2, columnspan=2, sticky="ew", pady=(8, 0))

        mnemonic_frame = ttk.LabelFrame(parent, text="Restore from mnemonic", padding=12)
        mnemonic_frame.grid(column=0, row=1, sticky="ew", pady=(12, 0))
        self.mnemonic_entry = self._add_simple_entry(
            mnemonic_frame, "Mnemonic", 0, placeholder="12 word phrase"
        )
        ttk.Button(
            mnemonic_frame, text="Restore", command=self.restore_from_mnemonic
        ).grid(column=0, row=1, columnspan=2, sticky="ew", pady=(8, 0))

    def _build_tx_tab(self, notebook: ttk.Notebook) -> None:
        """Build the transaction tab."""

        parent = ttk.Frame(notebook, padding=12)
        notebook.add(parent, text="Transactions")

        address_frame = ttk.LabelFrame(parent, text="Inspect address", padding=12)
        address_frame.grid(column=0, row=0, sticky="ew", pady=(12, 0))
        ttk.Label(address_frame, text="Address").grid(column=0, row=0, sticky="w")
        self.address_entry = ttk.Entry(address_frame, width=80)
        self.address_entry.grid(column=1, row=0, sticky="ew")
        ttk.Button(address_frame, text="Decode", command=self.decode_address).grid(
            column=2, row=0, padx=(8, 0)
        )
        address_frame.columnconfigure(1, weight=1)

        tx_frame = ttk.LabelFrame(parent, text="Transaction tools", padding=12)
        tx_frame.grid(column=0, row=1, sticky="nsew", pady=(12, 0))
        self.transaction_text = scrolledtext.ScrolledText(tx_frame, height=10, width=80)
        self.transaction_text.grid(column=0, row=0, columnspan=2, sticky="nsew")
        tx_frame.columnconfigure(0, weight=1)
        tx_frame.rowconfigure(0, weight=1)

        ttk.Button(
            tx_frame, text="Check recipient", command=self.check_transaction
        ).grid(column=0, row=1, sticky="ew", pady=(8, 0))
        ttk.Button(
            tx_frame, text="Decrypt amount", command=self.decrypt_amount
        ).grid(column=1, row=1, sticky="ew", pady=(8, 0), padx=(8, 0))

        parent.rowconfigure(1, weight=1)

    def _add_labeled_entry(self, master, label, variable, row):
        ttk.Label(master, text=label).grid(column=0, row=row, sticky="w")
        entry = ttk.Entry(master, textvariable=variable, width=80)
        entry.grid(column=1, row=row, sticky="ew")
        master.columnconfigure(1, weight=1)
        return entry

    def _add_simple_entry(self, master, label, row, placeholder=""):
        ttk.Label(master, text=label).grid(column=0, row=row, sticky="w")
        entry = ttk.Entry(master, width=50)
        if placeholder:
            entry.insert(0, placeholder)
        entry.grid(column=1, row=row, sticky="ew")
        master.columnconfigure(1, weight=1)
        return entry

    # ------------------------------------------------------------------
    # Wallet operations
    def generate_wallet(self) -> None:
        self.wallet, mnemonic = Wallet.generate(include_mnemonic=True)
        self._update_wallet_fields()
        messagebox.showinfo(
            "Wallet",
            "Generated a fresh wallet. Please store the mnemonic phrase securely",
        )

    def restore_from_inputs(self) -> None:
        if not self.view_private_entry or not self.spend_private_entry:
            return
        try:
            view_key = int(self.view_private_entry.get().strip(), 0)
            spend_key = int(self.spend_private_entry.get().strip(), 0)
        except ValueError:
            messagebox.showerror("Restore", "Private keys must be integers")
            return

        if view_key <= 0 or spend_key <= 0:
            messagebox.showerror("Restore", "Private keys must be positive")
            return

        self.wallet = Wallet(view_key, spend_key)
        self._update_wallet_fields()
        messagebox.showinfo("Restore", "Wallet restored from provided keys")

    def restore_from_mnemonic(self) -> None:
        if not self.mnemonic_entry:
            return
        mnemonic = self.mnemonic_entry.get().strip()
        if not mnemonic:
            messagebox.showerror("Restore", "Please enter a mnemonic phrase")
            return
        try:
            view_key = crypto_utils.keys_from_mnemonic(mnemonic)
            spend_key = crypto_utils.keys_from_mnemonic(mnemonic, passphrase="spend")
        except ValueError:
            messagebox.showerror("Restore", "Invalid mnemonic phrase")
            return

        self.wallet = Wallet(view_key, spend_key)
        self._update_wallet_fields(mnemonic)
        messagebox.showinfo("Restore", "Wallet restored from mnemonic phrase")

    def _update_wallet_fields(self, mnemonic: str | None = None) -> None:
        if not self.wallet:
            return
        self.view_private_var.set(str(self.wallet.view_private_key))
        self.spend_private_var.set(str(self.wallet.spend_private_key))
        self.view_public_var.set(_format_point(self.wallet.view_public_key))
        self.spend_public_var.set(_format_point(self.wallet.spend_public_key))
        address = self.wallet.export_address()
        self.address_var.set(address)

        if self.mnemonic_text:
            self.mnemonic_text.configure(state="normal")
            self.mnemonic_text.delete("1.0", tk.END)
            if mnemonic:
                self.mnemonic_text.insert("1.0", mnemonic)
            self.mnemonic_text.configure(state="disabled")

        if self.qr_code_canvas:
            self.qr_code_canvas.delete("all")
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(address)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")
            self.qr_code_image = ImageTk.PhotoImage(img)
            self.qr_code_canvas.create_image(
                128, 128, anchor=tk.CENTER, image=self.qr_code_image
            )

    # ------------------------------------------------------------------
    # UI callbacks
    def copy_address(self) -> None:
        if not self.wallet:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self.wallet.export_address())
        messagebox.showinfo("Address", "Address copied to clipboard")

    def decode_address(self) -> None:
        if not self.address_entry:
            return
        address = self.address_entry.get().strip()
        if not address:
            messagebox.showwarning("Address", "Please paste an address first")
            return
        try:
            view_point, spend_point = Wallet.import_address(address)
        except ValueError as exc:
            messagebox.showerror("Address", f"Invalid address: {exc}")
            return
        messagebox.showinfo(
            "Address details",
            f"View public: {_format_point(view_point)}\n"
            f"Spend public: {_format_point(spend_point)}",
        )

    def _load_transaction(self) -> dict | None:
        if not self.transaction_text:
            return None
        raw = self.transaction_text.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showwarning("Transaction", "Please paste a transaction JSON")
            return None
        try:
            transaction = json.loads(raw)
        except json.JSONDecodeError as exc:
            messagebox.showerror("Transaction", f"JSON error: {exc}")
            return None
        if not isinstance(transaction, dict):
            messagebox.showerror("Transaction", "Expected a JSON object")
            return None
        return transaction

    def check_transaction(self) -> None:
        if not self.wallet:
            messagebox.showwarning("Wallet", "Generate or restore a wallet first")
            return
        transaction = self._load_transaction()
        if not transaction:
            return
        if self.wallet.belongs_to_transaction(transaction):
            messagebox.showinfo("Transaction", "Transaction is addressed to this wallet")
        else:
            messagebox.showinfo(
                "Transaction", "Transaction does not belong to this wallet"
            )

    def decrypt_amount(self) -> None:
        if not self.wallet:
            messagebox.showwarning("Wallet", "Generate or restore a wallet first")
            return
        transaction = self._load_transaction()
        if not transaction:
            return
        try:
            amount = self.wallet.decrypt_transaction_amount(transaction)
        except ValueError as exc:
            messagebox.showerror("Decrypt", str(exc))
            return
        messagebox.showinfo("Decrypt", f"Decrypted amount: {amount}")

    # ------------------------------------------------------------------
    def run(self) -> None:
        self.root.mainloop()


def main() -> None:  # pragma: no cover - manual GUI entry point
    WalletGUI().run()


if __name__ == "__main__":  # pragma: no cover
    main()

