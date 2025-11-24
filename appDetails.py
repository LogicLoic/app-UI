# appDetails.py
import os
import io
import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import subprocess
from appDB import delete_application, update_tags, get_icon, get_tags

class AppDetails:
    def __init__(self, master, conn, app_name, app_path, refresh_callback):
        self.master = master
        self.conn = conn
        self.app_name = app_name
        self.app_path = app_path
        self.refresh_callback = refresh_callback
        self.tags = get_tags(conn, app_name) or []

        self.window = tk.Toplevel(master)
        self.window.title(f"Details — {app_name}")
        self.window.geometry("600x700")
        self.window.configure(bg="#1e1e1e")
        self.window.attributes("-topmost", True)

        # --- App icon ---
        self.icon_pil = get_icon(conn, app_name)
        if self.icon_pil:
            self.icon_img = ImageTk.PhotoImage(self.icon_pil.resize((128, 128)))
            self.icon_label = tk.Label(self.window, image=self.icon_img, bg="#1e1e1e")
            self.icon_label.pack(pady=10)
        else:
            self.icon_label = tk.Label(self.window, text="[no icon]", fg="gray", bg="#1e1e1e")
            self.icon_label.pack(pady=10)

        # --- App name ---
        tk.Label(self.window, text=app_name, font=("Consolas", 18, "bold"), fg="white", bg="#1e1e1e").pack()

        # --- App path ---
        tk.Label(self.window, text=app_path, font=("Consolas", 10), fg="lightgray", bg="#1e1e1e").pack(pady=5)

        # --- Options box ---
        tk.Label(self.window, text="Options :", font=("Consolas", 12), fg="white", bg="#1e1e1e").pack(pady=(20, 5))
        self.options_entry = tk.Entry(self.window, width=50, font=("Consolas", 11))
        self.options_entry.pack(pady=5)

        # --- Buttons ---
        button_frame = tk.Frame(self.window, bg="#1e1e1e")
        button_frame.pack(pady=20)

        tk.Button(button_frame, text="▶ Exécuter", width=15, command=self.run_app).grid(row=0, column=0, padx=10)
        tk.Button(button_frame, text="🗑 Supprimer", width=15, command=self.delete_app).grid(row=0, column=1, padx=10)
        tk.Button(button_frame, text="↩ Retour", width=15, command=self.window.destroy).grid(row=0, column=2, padx=10)

        # --- Tags section ---
        tk.Label(self.window, text="Tags :", font=("Consolas", 12), fg="white", bg="#1e1e1e").pack(pady=(10, 5))
        self.tag_frame = tk.Frame(self.window, bg="#1e1e1e")
        self.tag_frame.pack(pady=5)

        self.tag_entry = tk.Entry(self.window, width=30, font=("Consolas", 11))
        self.tag_entry.pack(pady=(5, 5))
        tk.Button(self.window, text="Ajouter tag", command=self.add_tag).pack()

        self.render_tags()

    # --------------------- TAGS ---------------------
    def render_tags(self):
        """Affiche dynamiquement les tags actuels."""
        for widget in self.tag_frame.winfo_children():
            widget.destroy()

        for tag in self.tags:
            frame = tk.Frame(self.tag_frame, bg="#2a2a2a", padx=5, pady=2)
            frame.pack(side=tk.TOP, fill="x", pady=2)
            lbl = tk.Label(frame, text=tag, fg="white", bg="#2a2a2a", font=("Consolas", 10))
            lbl.pack(side=tk.LEFT)
            btn = tk.Button(frame, text="✖", command=lambda t=tag: self.remove_tag(t), bg="#444", fg="white", bd=0)
            btn.pack(side=tk.RIGHT)

    def add_tag(self):
        tag = self.tag_entry.get().strip()
        if tag and tag not in self.tags:
            self.tags.append(tag)
            self.tag_entry.delete(0, tk.END)
            self.render_tags()
            update_tags(self.conn, self.app_name, self.tags)

    def remove_tag(self, tag):
        if tag in self.tags:
            self.tags.remove(tag)
            self.render_tags()
            update_tags(self.conn, self.app_name, self.tags)

    # --------------------- ACTIONS ---------------------
    def run_app(self):
        """Lance l’application avec les options spécifiées."""
        opts = self.options_entry.get().strip()
        try:
            working_dir = os.path.dirname(self.app_path)
            subprocess.Popen([self.app_path] + opts.split(), cwd=working_dir, shell=True)
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de lancer l’application : {e}")

    def delete_app(self):
        """Supprime l’application de la base."""
        if messagebox.askyesno("Confirmer", f"Supprimer {self.app_name} ?"):
            delete_application(self.conn, self.app_name)
            self.refresh_callback()
            self.window.destroy()
