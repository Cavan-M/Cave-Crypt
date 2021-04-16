import tkinter as tk
from tkinter import filedialog

def file_select():
    root = tk.Tk()
    root.withdraw()
    path = filedialog.askopenfilename()
    return path