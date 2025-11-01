from tkinter import *
from tkinter import colorchooser
from operator import setitem

def choose_color():
    color_code = colorchooser.askcolor(title="Choose color")
    if color_code:
        return color_code[1]
    return "#000000"

def apply_settings(new_settings, canvas, objects):
    global settings
    settings = new_settings
    canvas.config(bg=settings[0])
    for obj in objects:
        obj.base_fill = settings[1]
        obj.zoomed_fill = settings[2]
        obj.base_outline = settings[3]
        obj.zoomed_outline = settings[4]
        obj.thickness = settings[5]
        obj.canvas.itemconfig(obj.box, width=obj.thickness, fill = obj.base_fill, outline = obj.base_outline)
        obj.canvas.itemconfig(obj.title, font=(settings[6], settings[7]), fill=settings[8])

def open_settings(canvas, objects):
    def save_and_close():
        with open("settings.set", "w") as f:
            for item in new_settings:
                f.write(f"{item}\n")
        window.destroy()
        apply_settings(new_settings, canvas, objects)

    with open("settings.set", "r") as f:
        settings = [line.strip() for line in f.readlines()]

    window = Tk()
    window.title("Settings")
    window.geometry("400x700")
    window.resizable(False, False)
    window.attributes("-topmost", True)

    new_settings = settings.copy()

    label = Label(window, text="Settings")
    label.pack(pady=20)

    Button1 = Button(window, text="Choose Background Color", command=lambda: setitem(new_settings, 0, choose_color()))
    Button1.pack(pady=10)
    Button2 = Button(window, text="Choose Box Color", command=lambda: setitem(new_settings, 1, choose_color()))
    Button2.pack(pady=10)
    Button3 = Button(window, text="Choose Pointed Box Color", command=lambda: setitem(new_settings, 2, choose_color()))
    Button3.pack(pady=10)
    Button4 = Button(window, text="Choose Border Color", command=lambda: setitem(new_settings, 3, choose_color()))
    Button4.pack(pady=10)
    Button5 = Button(window, text="Choose Pointed Border Color", command=lambda: setitem(new_settings, 4, choose_color()))
    Button5.pack(pady=10)

    label1 = Label(window, text="Border Thickness")
    label1.pack(pady=5)
    Entry1 = Entry(window)
    Entry1.insert(0, str(new_settings[5]))
    Entry1.pack(pady=10)
    Label2 = Label(window, text="Font Name")
    Label2.pack(pady=5)
    Entry2 = Entry(window)
    Entry2.insert(0, str(new_settings[6]))
    Entry2.pack(pady=10)
    label3 = Label(window, text="Font Size")
    label3.pack(pady=5)
    Entry3 = Entry(window)
    Entry3.insert(0, str(new_settings[7]))
    Entry3.pack(pady=10)
    Button6 = Button(window, text="Choose Font Color", command=lambda: setitem(new_settings, 8, choose_color()))
    Button6.pack(pady=10)

    close_button = Button(window, text="Close", command=save_and_close)
    close_button.pack(pady=10)

    cancel_button = Button(window, text="Cancel", command=window.destroy)
    cancel_button.pack(pady=10)

    window.mainloop()
