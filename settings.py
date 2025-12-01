from tkinter import *
from tkinter import colorchooser
from operator import setitem

def choose_color():
    color_code = colorchooser.askcolor(title="Choose color")
    if color_code:
        return color_code[1]
    return "#000000"

def apply_settings(settings, canvas, objects, widgets):
    canvas.config(bg=settings[0])
    for obj in objects:
        obj.base_fill = settings[1]
        obj.zoomed_fill = settings[2]
        obj.base_outline = settings[3]
        obj.zoomed_outline = settings[4]
        obj.canvas.itemconfig(obj.box, fill = obj.base_fill, outline = obj.base_outline)
        obj.font = settings[5]
        obj.canvas.itemconfig(obj.title, font=(settings[5]), fill=settings[6])
    
    for w in widgets:
        try:
            if isinstance(w, (Label)):
                w.config(bg=settings[0], fg=settings[6], font=(settings[5], 10))
            elif isinstance(w, (Button)):
                w.config(bg=settings[1], fg=settings[6], font=(settings[5], 11))
            elif isinstance(w, (Checkbutton)):
                w.config(bg=settings[0], fg=settings[6], font=(settings[5], 10), activebackground=settings[0], activeforeground=settings[6], selectcolor=settings[1])
            elif isinstance(w, (Entry)):
                w.config(bg=settings[1], fg=settings[6], insertbackground=settings[3], font=(settings[5], 11))
            else:
                # autres widgets -> juste couleurs
                w.config(bg=settings[0], fg=settings[6])
        except Exception as e:
            print(f"Could not update widget {w}: {e}")

def open_settings(canvas, objects, settings, widgets):
    def save_and_close():
        new_settings[5] = Entry1.get()
        with open("settings.set", "w") as f:
            for item in new_settings:
                f.write(f"{item}\n")
        window.destroy()
        settings[:] = new_settings
        apply_settings(new_settings, canvas, objects, widgets)

    with open("settings.set", "r") as f:
        settings[:] = [line.strip() for line in f.readlines()]

    window = Tk()
    window.title("Settings")
    window.geometry("400x700")
    window.resizable(False, False)
    window.attributes("-topmost", True)
    window.configure(bg=settings[0])
    
    new_settings = settings.copy()

    label = Label(window, text="Settings", font=(settings[5], 18, "bold"), fg=settings[6], bg=settings[0])
    label.pack(pady=20)

    Button1 = Button(window, text="Choose Background Color", command=lambda: setitem(new_settings, 0, choose_color()), font=(settings[5], 10), fg=settings[6], bg=settings[1])
    Button1.pack(pady=10)

    Button2 = Button(window, text="Choose Box Color", command=lambda: setitem(new_settings, 1, choose_color()), font=(settings[5], 10), fg=settings[6], bg=settings[1])
    Button2.pack(pady=10)

    Button3 = Button(window, text="Choose Pointed Box Color", command=lambda: setitem(new_settings, 2, choose_color()), font=(settings[5], 10), fg=settings[6], bg=settings[1])
    Button3.pack(pady=10)

    Button4 = Button(window, text="Choose Border Color", command=lambda: setitem(new_settings, 3, choose_color()), font=(settings[5], 10), fg=settings[6], bg=settings[1])
    Button4.pack(pady=10)

    Button5 = Button(window, text="Choose Pointed Border Color", command=lambda: setitem(new_settings, 4, choose_color()), font=(settings[5], 10), fg=settings[6], bg=settings[1])
    Button5.pack(pady=10)

    Button6 = Button(window, text="Choose Font Color", command=lambda: setitem(new_settings, 6, choose_color()), font=(settings[5], 10), fg=settings[6], bg=settings[1])
    Button6.pack(pady=10)

    Label1 = Label(window, text="Font Name :", font=(settings[5], 12), fg=settings[6], bg=settings[0])
    Label1.pack(pady=5)

    Entry1 = Entry(window, font=(settings[5], 11), fg=settings[6], bg=settings[1], insertbackground=settings[3])
    Entry1.insert(0, str(new_settings[5]))
    Entry1.pack(pady=10)

    close_button = Button(window, text="Save and Close", command=save_and_close, font=(settings[5], 10), fg=settings[6], bg=settings[1])
    close_button.pack(pady=10)

    cancel_button = Button(window, text="Cancel", command=window.destroy, font=(settings[5], 10), fg=settings[6], bg=settings[1])
    cancel_button.pack(pady=10)

    window.mainloop()
