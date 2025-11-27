import os
import io
import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import subprocess
from appDB import delete_application, update_tags, get_icon, get_tags

class AppDetails:
    def __init__(self, master, conn, app_name, app_path, refresh_callback, close_on_run, objects, settings):
        self.master = master
        self.conn = conn
        self.app_name = app_name
        self.app_path = app_path
        self.refresh_callback = refresh_callback
        self.close_on_run = close_on_run
        self.tags = get_tags(conn, app_name) or []
        self.objects = objects
        self.settings = settings

        self.window = tk.Toplevel(master)
        self.window.title(f"Details — {app_name}")
        self.window.geometry("600x700")
        self.window.configure(bg=self.settings[0])
        
        # --- App icon ---
        self.icon_pil = get_icon(conn, app_name)
        if self.icon_pil:
            self.icon_img = ImageTk.PhotoImage(self.icon_pil.resize((128, 128)))
            self.icon_label = tk.Label(self.window, image=self.icon_img, bg=settings[0])
            self.icon_label.pack(pady=10)
        else:
            self.icon_label = tk.Label(self.window, text="[no icon]", fg="gray", bg=self.settings[0])
            self.icon_label.pack(pady=10)
    
        # --- App name ---
        tk.Label(self.window, text=app_name, font=(self.settings[5], 18, "bold"), fg=self.settings[6], bg=self.settings[1]).pack()
        # --- App path ---
        tk.Label(self.window, text=app_path, font=(self.settings[5], 10), fg=self.settings[6], bg=self.settings[1]).pack(pady=5)

        # --- Options box ---
        tk.Label(self.window, text="Options :", font=(self.settings[5], 12), fg=self.settings[6], bg=self.settings[1]).pack(pady=(20, 5))
        self.options_entry = tk.Entry(self.window, width=50, bg=settings[1], fg=settings[6], insertbackground=settings[3], font=(settings[5], 11))
        self.options_entry.pack(pady=5)

        # --- Buttons ---
        button_frame = tk.Frame(self.window, bg=self.settings[0])
        button_frame.pack(pady=20)

        tk.Button(button_frame, text="▶ Launch", width=15, command=self.run_app, bg=settings[1], fg=settings[6], font=(settings[5], 10)).grid(row=0, column=0, padx=10)
        tk.Button(button_frame, text="🗑 Delete", width=15, command=self.delete_app, bg=settings[1], fg=settings[6], font=(settings[5], 10)).grid(row=0, column=1, padx=10)
        tk.Button(button_frame, text="↩ Cancel", width=15, command=self.window.destroy, bg=settings[1], fg=settings[6], font=(settings[5], 10)).grid(row=0, column=2, padx=10)

        # --- Tags section ---
        tk.Label(self.window, text="Tags :", font=(self.settings[5], 12), fg=self.settings[6], bg=self.settings[0]).pack(pady=(10, 5))
        self.tag_frame = tk.Frame(self.window, bg=self.settings[0])
        self.tag_frame.pack(pady=5)

        self.tag_entry = tk.Entry(self.window, width=30, bg=settings[1], fg=settings[6], insertbackground=settings[3], font=(settings[5], 11))
        self.tag_entry.pack(pady=(5, 5))
        tk.Button(self.window, text="Add tag", command=self.add_tag, bg=settings[1], fg=settings[6], font=(settings[5], 10)).pack()

        self.render_tags()

    # --------------------- TAGS ---------------------
    def render_tags(self):
        """Affiche dynamiquement les tags actuels."""
        for widget in self.tag_frame.winfo_children():
            widget.destroy()

        for tag in self.tags:
            frame = tk.Frame(self.tag_frame, bg=self.settings[1], padx=5, pady=2)
            frame.pack(side=tk.TOP, fill="x", pady=2)
            lbl = tk.Label(frame, text=tag, fg=self.settings[6], bg=self.settings[1], font=(self.settings[5], 10))
            lbl.pack(side=tk.LEFT)
            btn = tk.Button(frame, text="✖", command=lambda t=tag: self.remove_tag(t), bg=self.settings[0], fg=self.settings[1], bd=0)
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
        """Launches, with options if any, the application."""
        opts = self.options_entry.get().strip()
        try:
            working_dir = os.path.dirname(self.app_path)
            subprocess.Popen([self.app_path] + opts.split(), cwd=working_dir, shell=True)
        except Exception as e:
            messagebox.showerror("Error", f"Impossible to launch : {e}")
        if self.close_on_run:
            self.master.quit()
            exit()

    def delete_app(self):
        """Deletes the application after confirmation."""
        if messagebox.askyesno("Confirm", f"Delete {self.app_name} ?"):
            delete_application(self.conn, self.app_name)
            for obj in self.objects:
                if obj.canvas.itemcget(obj.title, "text") == self.app_name:
                    obj.canvas.delete(obj.box)
                    obj.canvas.delete(obj.logo)
                    obj.canvas.delete(obj.title)
                    self.objects.remove(obj)
                    break
            self.refresh_callback()
            self.window.destroy()
