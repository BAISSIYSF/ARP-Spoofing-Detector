# import os
# import tkinter as tk
# from tkinter import simpledialog, messagebox
# import subprocess

# def sudo_requires_password():
#     try:
#         subprocess.run(["sudo", "-n", "true"], check=True)
#         return False  # sudo didn't ask for a password
#     except subprocess.CalledProcessError:
#         return True  # sudo asked for a password


# if os.geteuid() != 0:
#     if sudo_requires_password():
#         password = simpledialog.askstring("sudo required", "Enter password:")
#     else:
#         password = None  # No need to ask for password if sudo doesn't require it

#     command = f"echo '{password}' | sudo -S python3 ./src/gui.py" if password else "sudo python3 ./src/gui.py"
#     process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#     _, error = process.communicate()
#     if process.returncode != 0:
#         error_message = error.decode().strip()  # Remove leading/trailing whitespaces
#         messagebox.showerror("Error", f"{error_message}\nPlease try again. Exiting.")
#         exit()


