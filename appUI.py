from tkinter import *
from math import *
from PIL import Image, ImageTk
#from IconLoader import extract_highres_icon_from_exe
from tkinter import filedialog
from appDB import *
from settings import open_settings

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

def apply_settings(new_settings):
    global settings
    settings = new_settings
    canvas.config(bg=settings[0])
    for obj in objects:
        obj.base_fill = settings[1]
        obj.zoomed_fill = settings[2]
        obj.base_outline = settings[3]
        obj.zoomed_outline = settings[4]
        obj.thickness = settings[5]
        obj.canvas.itemconfig(obj.box, width=obj.thickness)
        obj.canvas.itemconfig(obj.title, font=(settings[6], settings[7]), fill=settings[8])

"""
def add_exe(conn, canvas, objects):
    file_path = filedialog.askopenfilename(title="Select Executable", filetypes=[("Executable Files", "*.exe")])
    if file_path:
        name = file_path.split("/")[-1].split(".exe")[0]
        icon = extract_highres_icon_from_exe(file_path)
        if icon is None:
            print(f"[WARN] Impossible d’extraire une icône depuis {file_path}")
            return

        icon.load()
        icon = icon.convert("RGBA")

        size = int(WIDTH / AMOUNT_PER_LINE * 0.15)
        icon = icon.resize((size, size), Image.LANCZOS)

        #add_application(conn, name, file_path, icon_data)

        i = len(objects)
        obj = Object(canvas, (i % AMOUNT_PER_LINE) * (1 / AMOUNT_PER_LINE), (i // AMOUNT_PER_LINE) * (1 / AMOUNT_PER_LINE), icon, name)
        objects.append(obj)
"""
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

button3 = Button(root, text="Settings", command=lambda: (open_settings(settings), apply_settings(settings)))
button3.place(relx=0.8, rely=0.1)

objects = []
image = Image.open("gcfw-icon-128x128tr.png")
image = image.resize((int(WIDTH / AMOUNT_PER_LINE *0.15), int(WIDTH / AMOUNT_PER_LINE *0.15)))
image = ImageTk.PhotoImage(image)

settings = [
    "#002244", #background color
    #Box settings
    "#0066bb", #base_fill
    "#44aaff", #zoomed_fill
    "#0088ff", #base_outline
    "#aaddff", #zoomed_outline
    2, #thickness
    
    #Font settings
    "Consolas", #font family
    16, #font size
    "#ffffff" #font color
]

"""
apps = get_applications(conn)
for i, app in enumerate(apps):
    objects.append(Object(canvas, (i%AMOUNT_PER_LINE)*(1/AMOUNT_PER_LINE), (i//AMOUNT_PER_LINE)*(1/AMOUNT_PER_LINE)))
"""
for i in range(20):
    objects.append(Object(canvas, (i%AMOUNT_PER_LINE)*(1/AMOUNT_PER_LINE), (i//AMOUNT_PER_LINE)*(1/AMOUNT_PER_LINE), image, "App"))

root.mainloop()

close_db(conn)
