from tkinter import *

class Object:
    def __init__(self, canvas, x, y):
        self.canvas = canvas
        self.x = x
        self.y = y
        self.id = canvas.create_rectangle(x*WIDTH+50, y*HEIGHT+50, x*WIDTH+WIDTH/AMOUNT_PER_LINE*0.9, y*HEIGHT+HEIGHT/AMOUNT_PER_LINE*0.9,
                                          fill="#0066bb", outline="#0088ff", width=2)

    def pointed(self, event):
        coords = self.canvas.coords(self.id)
        while coords[0] <= event.x <= coords[2] and coords[1] <= event.y <= coords[3]:
            self.canvas.itemconfig(self.id, fill="#00bb00")
            self.canvas.update()
        self.canvas.itemconfig(self.id, fill="#0066bb")
        self.canvas.update()

root = Tk()

WIDTH = root.winfo_screenwidth()
HEIGHT = root.winfo_screenheight()
AMOUNT_PER_LINE = 6

root.attributes("-fullscreen", True)
root.title("Simple GUI")

canvas = Canvas(root, bg="#004488")
canvas.pack(fill=BOTH, expand=True)

button = Button(root, text="Exit", command=lambda: exit())
button.place(relx=0.5, rely=0.5)

objects = []

for i in range(10):
    objects.append(Object(canvas, (i%AMOUNT_PER_LINE)*(1/AMOUNT_PER_LINE), (i//AMOUNT_PER_LINE)*(1/AMOUNT_PER_LINE)))
    canvas.tag_bind(objects[i].id, "<Enter>", objects[i].pointed)

root.mainloop()
