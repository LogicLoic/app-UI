from tkinter import *
from math import *
from PIL import Image, ImageTk
from IconLoader import extract_icon_from_exe as extract
from tkinter import filedialog
from appDB import *
from settings import open_settings, apply_settings
from os import system

def interpolate_color(color1, color2, t):
    c1 = [int(color1[i:i+2], 16) for i in (1, 3, 5)]
    c2 = [int(color2[i:i+2], 16) for i in (1, 3, 5)]
    c = [int(c1[j] + (c2[j] - c1[j]) * t) for j in range(3)]
    return f"#{c[0]:02x}{c[1]:02x}{c[2]:02x}"

class Object:
    def __init__(self, canvas, x, y, logo, title):
        self.canvas = canvas
        self.x = x
        self.y = y

        self.base_coords = (
            x * WIDTH + MARGIN,
            y * HEIGHT + MARGIN,
            x * WIDTH + WIDTH / AMOUNT_PER_LINE * 0.8,
            y * HEIGHT + HEIGHT / AMOUNT_PER_LINE * 0.8
        )

        self.zoomed_coords = (
            x * WIDTH + (MARGIN / 1.5),
            y * HEIGHT + (MARGIN / 1.5),
            x * WIDTH + WIDTH / AMOUNT_PER_LINE * 0.92,
            y * HEIGHT + HEIGHT / AMOUNT_PER_LINE * 0.92
        )

        self.base_fill = "#0066bb"
        self.zoomed_fill = "#44aaff"
        self.base_outline = "#0088ff"
        self.zoomed_outline = "#aaddff"
        self.thickness = 2

        self.box = canvas.create_rectangle(*self.base_coords,
                                           fill=self.base_fill,
                                           outline=self.base_outline, width=self.thickness)
        
        self.logo = canvas.create_image(self.x * WIDTH + WIDTH / AMOUNT_PER_LINE * 0.4,
                                       self.y * HEIGHT + HEIGHT / AMOUNT_PER_LINE * 0.4 + MARGIN / 2,
                                       image=logo)
        self.icon = logo
        self.title = canvas.create_text(
            x * WIDTH + WIDTH / AMOUNT_PER_LINE * 0.3 + MARGIN *4/3,
            y * HEIGHT + HEIGHT / AMOUNT_PER_LINE * 0.4 + MARGIN / 2,
            text=title,
            fill="#ffffff",
            font=("Consolas", 16)
        )

        self.zoom = 0.0
        self.target_zoom = 0.0
        self.animation_id = None

        for tag in (self.box, self.logo, self.title):
            canvas.tag_bind(tag, "<Enter>", self.on_enter)
            canvas.tag_bind(tag, "<Leave>", self.on_leave)
            canvas.tag_bind(tag, "<Button-1>", lambda e, t=title: run(t))

    def on_enter(self, event):
        self.animate_to(1.0, duration=1000)

    def on_leave(self, event):
        self.animate_to(0.0, duration=1000)

    def animate_to(self, target, duration=1000, fps=60):
        self.target_zoom = target
        if self.animation_id:
            self.canvas.after_cancel(self.animation_id)

        frames = max(1, int(duration / (1000 / fps)))
        start_zoom = self.zoom
        delta = target - start_zoom

        def step(i=0):

            t = i / frames

            eased_t = 1 - exp(-4 * t)
            eased_t /= 1 - exp(-4)

            self.zoom = start_zoom + delta * eased_t

            x1 = self.base_coords[0] + (self.zoomed_coords[0] - self.base_coords[0]) * self.zoom
            y1 = self.base_coords[1] + (self.zoomed_coords[1] - self.base_coords[1]) * self.zoom
            x2 = self.base_coords[2] + (self.zoomed_coords[2] - self.base_coords[2]) * self.zoom
            y2 = self.base_coords[3] + (self.zoomed_coords[3] - self.base_coords[3]) * self.zoom

            fill_color = interpolate_color(self.base_fill, self.zoomed_fill, self.zoom)
            outline_color = interpolate_color(self.base_outline, self.zoomed_outline, self.zoom)
            self.canvas.itemconfig(self.box, fill=fill_color, outline=outline_color)

            self.canvas.coords(self.box, x1, y1, x2, y2)

            if i < frames and abs(self.zoom - self.target_zoom) > 0.001:
                self.animation_id = self.canvas.after(int(1000 / fps), step, i + 1)
            else:
                self.zoom = self.target_zoom
                self.animation_id = None

        step()

def run(app_name):
    path = get_path(conn, app_name)
    if path:
        system(f'start "" "{path}"')

def add_exe(conn, canvas, objects):
    file_path = filedialog.askopenfilename(title="Select Executable", filetypes=[("Executable Files", "*.exe")])
    if file_path:
        name = file_path.split("/")[-1].split(".exe")[0]
        path = extract(file_path, name, ".", out_width=128, out_height=128)
        if path is None:
            print(f"[WARN] Impossible d’extraire une icône depuis {file_path}")
            return

        icon = Image.open(path).resize((int(WIDTH / AMOUNT_PER_LINE * 0.15),
                                   int(WIDTH / AMOUNT_PER_LINE * 0.15)))

        add_application(conn, name, file_path, icon)

        icon_tk = ImageTk.PhotoImage(icon)

        i = len(objects)
        objects.append(Object(canvas, (i%AMOUNT_PER_LINE)*(1/AMOUNT_PER_LINE), (i//AMOUNT_PER_LINE)*(1/AMOUNT_PER_LINE), icon_tk, name))

scroll_offset = 0
scroll_target = 0
scroll_animation = None

def on_scroll(event):
    """Gère la molette et déclenche le défilement fluide."""
    global scroll_target

    # Sens du scroll
    direction = 1 if event.delta > 0 else -1
    step = HEIGHT / 10  # Distance à parcourir par "cran"
    scroll_target += direction * step
    
    animate_scroll()

def animate_scroll(duration=400, fps=60):
    """Anime le déplacement fluide des objets sur le canvas."""
    global scroll_offset, scroll_target, scroll_animation

    if scroll_animation:
        root.after_cancel(scroll_animation)

    frames = int(duration / (1000 / fps))
    start = scroll_offset
    delta = scroll_target - start

    def step(i=0):
        global scroll_offset, scroll_animation
        t = i / frames
        eased_t = 1 - exp(-6 * t)
        eased_t /= 1 - exp(-6)
        new_offset = start + delta * eased_t
        dy = new_offset - scroll_offset
        scroll_offset = new_offset

        # Déplace tout le contenu
        for obj in objects:
            canvas.move(obj.box, 0, dy)
            canvas.move(obj.logo, 0, dy)
            canvas.move(obj.title, 0, dy)

            # Met à jour les coordonnées internes logiques
            obj.y += dy / HEIGHT  # proportionnel à la taille de l’écran

            # Tu peux aussi recalculer base_coords & zoomed_coords si tu veux
            obj.base_coords = tuple(
                c + (dy / HEIGHT) * HEIGHT if j % 2 == 1 else c
                for j, c in enumerate(obj.base_coords)
            )
            obj.zoomed_coords = tuple(
                c + (dy / HEIGHT) * HEIGHT if j % 2 == 1 else c
                for j, c in enumerate(obj.zoomed_coords)
            )

        if i < frames:
            scroll_animation = root.after(int(1000 / fps), step, i + 1)
        else:
            scroll_animation = None

    step()
    
zoom_level = 1.0
target_zoom = 1.0
zoom_anim = None

def on_ctrl_scroll(event):
    """Ctrl + molette => zoom fluide de la grille"""
    global target_zoom

    # direction molette (Windows : delta multiple de 120)
    direction = 1 if event.delta > 0 else -1
    target_zoom *= 1.1 if direction > 0 else 0.9
    target_zoom = max(0.5, min(2.0, target_zoom))  # limites

    start_zoom_animation()

def start_zoom_animation(duration=400, fps=60):
    """Anime le zoom global en interpolant toutes les positions"""
    global zoom_level, target_zoom, zoom_anim, AMOUNT_PER_LINE

    if zoom_anim:
        root.after_cancel(zoom_anim)

    frames = int(duration / (1000 / fps))
    start_zoom = zoom_level
    delta = target_zoom - start_zoom

    def step(i=0):
        global zoom_level, zoom_anim, AMOUNT_PER_LINE

        t = i / frames
        eased_t = 1 - exp(-6 * t)
        eased_t /= 1 - exp(-6)

        zoom_level = start_zoom + delta * eased_t
        AMOUNT_PER_LINE = int(6 / zoom_level)
        AMOUNT_PER_LINE = max(2, min(10, AMOUNT_PER_LINE))

        box_w = WIDTH / AMOUNT_PER_LINE
        box_h = HEIGHT / AMOUNT_PER_LINE

        for idx, obj in enumerate(objects):
            target_x = (idx % AMOUNT_PER_LINE) / AMOUNT_PER_LINE
            target_y = (idx // AMOUNT_PER_LINE) / AMOUNT_PER_LINE

            # interpolation fluide vers nouvelle position
            obj.x += (target_x - obj.x) * 0.3
            obj.y += (target_y - obj.y) * 0.3

            # mise à jour des coordonnées
            obj.base_coords = (
                obj.x * WIDTH + MARGIN,
                obj.y * HEIGHT + MARGIN,
                obj.x * WIDTH + box_w * 0.8,
                obj.y * HEIGHT + box_h * 0.8
            )
            obj.zoomed_coords = (
                obj.x * WIDTH + (MARGIN / 1.5),
                obj.y * HEIGHT + (MARGIN / 1.5),
                obj.x * WIDTH + box_w * 0.92,
                obj.y * HEIGHT + box_h * 0.92
            )

            # repositionnement
            x1, y1, x2, y2 = obj.base_coords
            obj.canvas.coords(obj.box, x1, y1, x2, y2)
            obj.canvas.coords(obj.logo,
                obj.x * WIDTH + box_w * 0.4,
                obj.y * HEIGHT + box_h * 0.4 + MARGIN / 2
            )
            obj.canvas.coords(obj.title,
                obj.x * WIDTH + box_w * 0.3 + MARGIN * 4/3,
                obj.y * HEIGHT + box_h * 0.4 + MARGIN / 2
            )

        if i < frames:
            zoom_anim = root.after(int(1000 / fps), step, i + 1)
        else:
            zoom_level = target_zoom
            zoom_anim = None

    step()

conn = connect_db('apps.db')
create_table(conn)

root = Tk()

WIDTH = root.winfo_screenwidth()
HEIGHT = root.winfo_screenheight()
MARGIN = WIDTH / 20
AMOUNT_PER_LINE = 6
root.attributes("-fullscreen", True)
root.title("App catalog")

canvas = Canvas(root, bg="#002244")
canvas.pack(fill=BOTH, expand=True)

button1 = Button(root, text="Exit", command=lambda: exit())
button1.place(relx=0.5, rely=0.5)

button2 = Button(root, text="Add Executable", command=lambda: add_exe(conn, canvas, objects))
button2.place(relx=0.9, rely=0.1)

button3 = Button(root, text="Settings", command=lambda: open_settings(canvas, objects))
button3.place(relx=0.8, rely=0.1)

objects = []
image = Image.open("gcfw-icon-128x128tr.png")
image = image.resize((int(WIDTH / AMOUNT_PER_LINE *0.15), int(WIDTH / AMOUNT_PER_LINE *0.15)))
image = ImageTk.PhotoImage(image)

settings = []
with open("settings.set", "r") as f:
    settings = [line.strip() for line in f.readlines()]


apps = get_applications(conn)
for i, app in enumerate(apps):
    objects.append(Object(canvas, (i%AMOUNT_PER_LINE)*(1/AMOUNT_PER_LINE), (i//AMOUNT_PER_LINE)*(1/AMOUNT_PER_LINE), app[2], app[0]))
"""
for i in range(100):
    objects.append(Object(canvas, (i%AMOUNT_PER_LINE)*(1/AMOUNT_PER_LINE), (i//AMOUNT_PER_LINE)*(1/AMOUNT_PER_LINE), image, str(i)))
"""
apply_settings(settings, canvas, objects)

canvas.bind("<MouseWheel>", on_scroll) #Windows
canvas.bind_all("<Control-MouseWheel>", on_ctrl_scroll)
canvas.bind_all("<Button-4>", lambda e: on_scroll(type("Event", (), {"delta": 120})))  # Linux (scroll up)
canvas.bind_all("<Button-5>", lambda e: on_scroll(type("Event", (), {"delta": -120}))) # Linux (scroll down)
canvas.bind_all("<Control-Button-4>", lambda e: on_ctrl_scroll(type("Event", (), {"delta": 120})))  # Linux up
canvas.bind_all("<Control-Button-5>", lambda e: on_ctrl_scroll(type("Event", (), {"delta": -120}))) # Linux down
root.mainloop()

close_db(conn)
