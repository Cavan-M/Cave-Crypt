import tkinter as tk
import QuickSelect
import aes
import sha

class CaveCrypt:
    # initialize the app, widgets, etc
    def __init__(self):
        # Main window
        self.window = tk.Tk()
        self.window.wm_title("CaveCrypt")
        self.window.minsize(400, 300)
        self.window.resizable(False, False)
        self.window.iconbitmap('lock.ico')
        # top bar
        self.upper = tk.Frame(self.window, height=70, bg="peach puff")
        self.upper.pack(fill="x")
        self.select_AES = tk.Button(
            self.upper, text="AES",
            command=self.set_aes,
            bd=0,
            width=10,
            bg="antique white",
            activebackground="navajo white")
        self.select_AES.grid(column=1, row=1, padx=10)
        self.select_home = tk.Button(
            self.upper,
            text="Home",
            command=self.set_home,
            bd=0, width=10,
            bg="antique white",
            activebackground="navajo white")
        self.select_home.grid(row=1, column=0, padx=10)
        self.select_SHA = tk.Button(
            self.upper,
            text="SHA",
            command=self.set_sha,
            bd=0, width=10,
            bg="antique white",
            activebackground="navajo white")
        self.select_SHA.grid(row=1, column=2, padx=10)
        # Bottom screen
        self.lower = tk.Frame(self.window, bg="antique white")
        self.lower.pack(fill="both", expand=True)
        # program control
        self.program_state = {"home": False, "aes": False, "sha": False}
        self.path = "No File Selected"
        # start the program
        self.set_home()
        self.window.mainloop()

    # sets all program states to False
    def clear_program_state(self):
        for x in self.program_state:
            self.program_state[x] = False

    # open the Home screen
    def set_home(self):
        # check for duplicate program state
        if not self.program_state["home"]:
            # set the program state
            self.clear_program_state()
            self.program_state["home"] = True
            # clear the bottom screen
            self.lower.destroy()
            self.lower = tk.Frame(self.window, bg="antique white")
            self.lower.pack(fill="both", expand=True)
            # tkinter widgets
            self.intro = tk.Label(self.lower, text="Hello! Welcome to CaveCrypt!", bg="antique white")
            self.intro.config(font=("Verdana", 18))
            self.description = tk.Label(self.lower,
                                        text="Use the tabs above to select an encryption method.",
                                        font=("Verdana", 11),
                                        bg="antique white")
            self.intro.pack(pady=10)
            self.description.pack(pady=30)

    def set_sha(self):
        if not self.program_state["sha"]:
            # set the program state
            self.clear_program_state()
            self.program_state["sha"] = True
            # clear the bottom screen
            self.lower.destroy()
            self.lower = tk.Frame(self.window, bg="antique white")
            self.lower.pack(fill="both", expand=True)
            self.path = "No File Selected"
            # tkinter widgets
            self.title = tk.Label(self.lower, text="Generate SHA256 Hash", bg="antique white")
            self.title.config(font=("Verdana", 16))
            self.title.pack(fill="x", expand=False, side="top")
            self.spacer = tk.Frame(self.lower, bg="antique white", height=15)
            self.spacer.pack()
            self.file_select_button = tk.Button(self.lower, text="Choose...", command=self.file_path)
            self.file_select_label = tk.Label(self.lower, text=self.path, width=20, bg="antique white")
            self.file_select_label.pack(side="left")
            self.file_select_button.pack(side="left")
            self.spacer_two = tk.Frame(self.lower, bg="antique white", width=10)
            self.spacer_two.pack(side="right")
            self.hash_box = tk.Text(self.lower, width=30, height=8, state='disabled')
            self.hash_text = ""
            self.generate_button = tk.Button(self.lower, text="Generate", command=self.generate_sha)
            self.generate_button.pack()
            self.hash_box.pack(side="top")

    def generate_sha(self):
        self.hash_box.configure(state='normal')
        try:
            self.hash_text = sha.generate_sha_hash(self.path)
        except FileNotFoundError:
            self.hash_text = "Error: No File Selected"
        self.hash_box.delete('1.0', tk.END)
        self.hash_box.insert(tk.END, self.hash_text)
        self.hash_box.configure(state='disabled')


    # open the AES encryption screen
    def set_aes(self):
        # check for duplicate program state
        if not self.program_state["aes"]:
            # set the program state
            self.clear_program_state()
            self.program_state["aes"] = True
            # clear the bottom screen
            self.lower.destroy()
            self.lower = tk.Frame(self.window, bg="antique white")
            self.lower.pack(fill="both", expand=True)
            self.path = "No File Selected"
            # tkinter widgets
            self.title = tk.Label(self.lower, text="Encrypt and Decrypt using AES", bg="antique white")
            self.title.config(font=("Verdana", 16))
            self.title.pack(fill="x", expand=False, side="top")
            self.spacer = tk.Frame(self.lower, bg="antique white", height=35)
            self.spacer.pack()
            # left side
            self.left = tk.Frame(self.lower, bg="antique white")
            self.left.pack(fill="both", expand=True, side="left")
            # right side
            self.right = tk.Frame(self.lower, bg="antique white")
            self.right.pack(fill="both", expand=True, side="right")
            # left widgets
            self.file_select_button = tk.Button(self.left, text="Choose...", command=self.file_path)
            self.file_select_label = tk.Label(self.left, text=self.path, width=20, bg="antique white")
            self.file_select_label.grid(row=1, column=0, sticky="ew")
            self.file_select_button.grid(row=1, column=1, sticky="w")
            self.password_entry = tk.Entry(self.left, textvariable="Password", show="*")
            self.password_entry.grid(row=0, column=1, sticky="ew")
            self.password_label = tk.Label(self.left, text="Password:", bg="antique white")
            self.password_label.grid(row=0, column=0, sticky="e")
            # todo add optional IV

            # right widgets
            self.encrypt_button = tk.Button(self.right, text="Encrypt", command=self.aes_encrypt)
            self.encrypt_button.pack(pady=10)
            self.decrypt_button = tk.Button(self.right, text="Decrypt", command=self.aes_decrypt)
            self.decrypt_button.pack(pady=20, side="top")

    # will select file and store path
    def file_path(self):
        self.path = QuickSelect.file_select()
        self.file_select_label.configure(text=self.path[:20] + "...")

    # encrypt selected file
    def aes_encrypt(self):
        # get password text
        pw = self.password_entry.get()
        try:
            # attempt encryption
            aes.encrypt_file(self.path, pw)
            # success Label
            self.success_label = tk.Label(self.right, text="Success")
            self.success_label.pack()
        except FileNotFoundError:
            print("Invalid Selection; File Not Found")

    # encrypt selected file
    def aes_decrypt(self):
        pw = self.password_entry.get()
        try:
            dec_file = open(self.path.strip("encrypted.aes") + "Decrypted.txt", 'w')
            newline = False
            for x in str(aes.decrypt_file(self.path, pw)).strip('b').strip("'"):
                if ord(x) == 92:
                    newline = True
                elif ord(x) == 110 and newline:
                    dec_file.write('\n')
                elif ord(x) == 114 and newline:
                    newline = True
                else:
                    newline = False
                    dec_file.write(x)
            dec_file.close()
            self.success_label = tk.Label(self.right, text="Success")
            self.success_label.pack()
        except FileNotFoundError:
            print("Invalid Selection; File Not Found")


app = CaveCrypt()
