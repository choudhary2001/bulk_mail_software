import os
import json
import csv
import requests
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from form import create_email_form, open_file, toggle_custom_filename, paypal_form
import threading
from bs4 import BeautifulSoup
from PIL import Image, ImageTk
from tkinter import PhotoImage
import sys

BASE_API_URL = "https://brahmastra.site/"

if getattr(sys, 'frozen', False):
    # If run as a PyInstaller executable, use sys._MEIPASS
    base_path = sys._MEIPASS
else:
    # If run as a script, use the script's directory
    base_path = os.path.dirname(os.path.abspath(__file__))


def read_attachments_json(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
    except FileNotFoundError:
        data = []
    return data

def open_page(option, login_window, f, root, index):
    login_window.grid_forget()

    form_frame = ttk.Frame(f, padding="10")
    form_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    style = ttk.Style()
    style.configure("Main.TFrame", background="#333333")  # Replace "#333333" with your desired color
    form_frame.configure(style="Main.TFrame")
    back_button = ttk.Button(form_frame, text="Back", command=lambda: show_main_window(form_frame, f, root, index))
    back_button.grid(row=0, column=0, pady=10, sticky=tk.W)

    try:
        f.grid_forget()
        login_window.destroy()
        canvas = tk.Canvas(f)
        canvas.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar = ttk.Scrollbar(f, orient="vertical", command=canvas.yview)
        scrollbar.grid(row=0, column=10, sticky=(tk.N, tk.S))
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.configure(bg="#333333")

        form_frame = ttk.Frame(canvas, padding="20")
        style = ttk.Style()
        style.configure("Main.TFrame", background="#333333") 
        form_frame.configure(style="Main.TFrame")
        # root.configure(style="Main.TFrame")
        canvas.create_window((0, 0), window=form_frame, anchor="nw")

        if option == "Google API":
            create_email_form(form_frame, option, index, root)
        if option == "SMTP":
            create_email_form(form_frame, option, index, root)
        if option == "PayPal API":
            paypal_form(form_frame, option, index, root)

        form_frame.rowconfigure(0, weight=1)
        form_frame.columnconfigure(0, weight=1)
        canvas.rowconfigure(0, weight=1)
        canvas.columnconfigure(0, weight=1)
        f.rowconfigure(0, weight=1)
        f.columnconfigure(0, weight=1)

        form_frame.bind("<Configure>", lambda event: canvas.configure(scrollregion=canvas.bbox("all")))
        f.grid_propagate(True)

        # Update the window size based on the frame width
        root.update_idletasks()
        new_width = form_frame.winfo_reqwidth() + f.winfo_x() + 50
        new_height = form_frame.winfo_reqheight() + f.winfo_y()
        min_height = 950  # Change this to your dessssired minimum height
        new_height = min(new_height, min_height)

        root.geometry(f"{new_width}x{new_height}")
        root.update_idletasks()
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = (screen_width - root.winfo_width()) // 2
        y = (screen_height - root.winfo_height()) // 2
        root.geometry("+{}+{}".format(x, y))

    except Exception as e:
        messagebox.showerror("Error", f"Error updating CSV file: {str(e)}")
        return False


def create_google_api_form(frame, index):
    ttk.Label(frame, text="Upload Google API JSON file:").grid(row=1, column=0, pady=10)
    json_file_label = ttk.Label(frame, text="")
    json_file_label.grid(row=1, column=3, pady=10)
    ttk.Button(frame, text="Upload", command=lambda: upload_json(frame, json_file_label, index)).grid(row=1, column=2, pady=10, sticky=tk.W)


def validate_not_empty(value):
    return bool(value.strip())

def read_smtp_config_csv(csv_file_path):
    smtp_config_data = []

    with open(csv_file_path, mode='r') as file:
        csv_reader = csv.reader(file)
        next(csv_reader)  # Skip the header row
        for row in csv_reader:
            email, password, smtp, port, ssl, authentication, name = row
            smtp_config_data.append({
                'email': email,
                'password': password,
                'smtp': smtp,
                'port': port,
                'ssl': ssl.lower() == 'true',
                'authentication' : authentication,  
                'name' : name
            })

    return smtp_config_data


def download_file():
    file_name = "test_password.csv"
    ccsv_file_path = os.path.join(base_path, file_name)

    # Assuming read_smtp_config_csv returns a dictionary
    smtp_config_data = read_smtp_config_csv(ccsv_file_path)
    smtp_config_data = smtp_config_data[0]

    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])

    if file_path:
        with open(file_path, mode='w', newline='', encoding='utf-8') as file:
            # Write the header
            header = "email,password,smtp,port,ssl,authentication,name\n"
            file.write(header)

            # Write the configuration line
            line = ",".join([
                smtp_config_data.get('email', ''),
                smtp_config_data.get('password', ''),
                smtp_config_data.get('smtp', ''),
                str(smtp_config_data.get('port', '')),
                str(smtp_config_data.get('ssl', '')),
                str(smtp_config_data.get('authentication', '')),
                smtp_config_data.get('name', '')
            ]) + '\n'
            file.write(line)

            print("CSV file has been saved successfully.")


smtp_servers = ["", "smtp.gmail.com", "smtp.yahoo.com", "smtp.amazon.com"]

def create_smtp_form(option, frame, f, root, index):
    # First Column - Form Fields
    ttk.Label(frame, text="SMTP Server:").grid(row=1, column=1, pady=5, sticky=tk.W)
    smtp_server_var = tk.StringVar()
    smtp_server_var.set(smtp_servers[0])  # Default selection
    smtp_server_dropdown = ttk.Combobox(frame, textvariable=smtp_server_var, values=smtp_servers, width=27)
    smtp_server_dropdown.grid(row=1, column=2, pady=5, sticky=tk.W)

    ttk.Label(frame, text="PORT:").grid(row=2, column=1, pady=5, sticky=tk.W)
    port_entry = ttk.Entry(frame, textvariable=tk.IntVar(), width=30)
    port_entry.grid(row=2, column=2, pady=5, sticky=tk.W)
    port_entry.config(validate="focusout", validatecommand=(port_entry.register(validate_not_empty), "%P"))

    auth_var = tk.BooleanVar()
    auth_checkbox = ttk.Checkbutton(frame, text="Enable Authentication", variable=auth_var)
    auth_checkbox.grid(row=3, column=1, pady=5, sticky=tk.W)

    ssl_var = tk.BooleanVar()
    ssl_checkbox = ttk.Checkbutton(frame, text="Enable SSL/TLS", variable=ssl_var)
    ssl_checkbox.grid(row=3, column=2, pady=5, sticky=tk.W)

    ttk.Label(frame, text="SMTP Username:").grid(row=4, column=1, pady=5, sticky=tk.W)
    username_entry = ttk.Entry(frame, textvariable=tk.StringVar(), width=30)
    username_entry.grid(row=4, column=2, pady=5, sticky=tk.W)
    username_entry.config(validate="focusout", validatecommand=(username_entry.register(validate_not_empty), "%P"))

    ttk.Label(frame, text="SMTP Password:").grid(row=5, column=1, pady=5, sticky=tk.W)
    password_entry = ttk.Entry(frame, textvariable=tk.StringVar(), show="*", width=30)
    password_entry.grid(row=5, column=2, pady=5, sticky=tk.W)
    password_entry.config(validate="focusout", validatecommand=(password_entry.register(validate_not_empty), "%P"))

    ttk.Label(frame, text="Sender Name:").grid(row=6, column=1, pady=5, sticky=tk.W)
    sender_name_entry = ttk.Entry(frame, textvariable=tk.StringVar(), width=30)
    sender_name_entry.grid(row=6, column=2, pady=5, sticky=tk.W)

    ttk.Button(frame, text="Submit", command=lambda: save_submit_form(option, frame, f, root, index, smtp_server_var, port_entry, auth_var, ssl_var, username_entry, password_entry, sender_name_entry)).grid(row=9, column=1, pady=(10, 0), sticky=tk.W)

    separator = ttk.Separator(frame, orient=tk.VERTICAL)
    separator.grid(row=1, column=3, rowspan=8, sticky="ns", padx=10)

    # Second Column - Upload Option

    ttk.Label(frame, text="Format of CSV File :").grid(row=2, column=4, pady=5, sticky=tk.W)
    ttk.Label(frame, text="email,password,smtp,port,ssl,authentication,name").grid(row=3, column=4, pady=5, sticky=tk.W)
    ttk.Label(frame, text="Download Demo file").grid(row=4, column=4, pady=5, sticky=tk.W)

    smtp_file_button = ttk.Button(frame, text="Download", command=lambda: download_file())
    smtp_file_button.grid(row=5, column=4, pady=5, sticky=tk.W)
    
    ttk.Label(frame, text="Upload file").grid(row=6, column=4, pady=5, sticky=tk.W)

    smtp_file_button = ttk.Button(frame, text="Upload", command=lambda: open_smtp_file(frame, f, root, index))
    smtp_file_button.grid(row=7, column=4, pady=5, sticky=tk.W)


    def on_smtp_server_selected(event):
        selected_server = smtp_server_var.get()
        if selected_server == "smtp.gmail.com":
            # Automatically fill in values for Gmail
            port_entry.delete(0, tk.END)
            port_entry.insert(0, 465)  # Fill in port 465 for Gmail
            auth_var.set(True)  # Enable authentication
            ssl_var.set(True)   # Enable SSL/TLS
        elif selected_server == "smtp.yahoo.com":
            # Implement logic for Yahoo
            port_entry.delete(0, tk.END)
            ssl_var.set(False)
        elif selected_server == "smtp.amazon.com":
            # Implement logic for Amazon
            port_entry.delete(0, tk.END)
            ssl_var.set(False)
        else:
            # Clear the entries for other servers
            port_entry.delete(0, tk.END)
            auth_var.set(False)
            ssl_var.set(False)
            username_entry.delete(0, tk.END)
            password_entry.delete(0, tk.END)
            

    smtp_server_dropdown.bind("<<ComboboxSelected>>", on_smtp_server_selected)


def save_submit_form(option, frame, f, root, index, smtp_server_var, port_entry, auth_var, ssl_var, username_entry, password_entry, sender_name_entry):
    if validate_form(frame):
        smtp_server = smtp_server_var.get()
        port = port_entry.get()
        enable_auth = auth_var.get()
        enable_ssl = ssl_var.get()
        username = username_entry.get()
        password = password_entry.get()
        sender_name = sender_name_entry.get()
        save_smtp_data_csv(smtp_server, port, enable_auth, enable_ssl, username, password, sender_name, index)

        # success_label.config(text="Form submitted successfully!")

        add_another = messagebox.askyesno("Add Another", "Do you want to add another entry?")
        
        if add_another:
            clear_smtp_form(smtp_server_var, port_entry, auth_var, ssl_var, username_entry, password_entry, sender_name_entry)
        else:
            # success_label.config(text="")
            submit_form(option, frame, f, root, index)
    else:
        error_label.config(text="Please fill in all required fields.")

def clear_smtp_form(smtp_server_var, port_entry, auth_var, ssl_var, username_entry, password_entry, sender_name_entry):
    smtp_server_var.set(smtp_servers[0])
    port_entry.delete(0, tk.END)
    auth_var.set(False)
    ssl_var.set(False)
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    sender_name_entry.delete(0, tk.END)
    # success_label.config(text="")

def save_smtp_data_csv(smtp_server, port, enable_auth, enable_ssl, username, password, sender_name, index):
    tab_directory = f"Window{index}"
    mail_password_file_name = f"mail_password_{index}.csv"
    file_path = os.path.join(base_path, tab_directory, mail_password_file_name)
    data = [username, password, smtp_server, port, enable_ssl, enable_auth, sender_name]

    try:
        with open(file_path, mode='a', newline='') as file:
            writer = csv.writer(file)
            if file.tell() == 0:
                writer.writerow(["email", "password", "smtp", "port", "ssl", "authentication", "name"])
            writer.writerow(data)
    except FileNotFoundError:
        with open(file_path, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["email", "password", "smtp", "port", "ssl", "authentication", "name"])
            writer.writerow(data)

def submit_form(option, frame, f, root, index):
    if validate_form(frame):
        f.grid_forget()
        frame.destroy()
        canvas = tk.Canvas(f)
        canvas.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar = ttk.Scrollbar(f, orient="vertical", command=canvas.yview)
        scrollbar.grid(row=0, column=10, sticky=(tk.N, tk.S))
        canvas.configure(yscrollcommand=scrollbar.set)

        form_frame = ttk.Frame(canvas, padding="20")
        canvas.create_window((0, 0), window=form_frame, anchor="nw")

        if option == "Google API":
            create_email_form(form_frame, option, index, root)
        if option == "SMTP":
            create_email_form(form_frame, option, index, root)
        if option == "PayPal API":
            paypal_form(form_frame, option, index, root)

        form_frame.rowconfigure(0, weight=1)
        form_frame.columnconfigure(0, weight=1)
        canvas.rowconfigure(0, weight=1)
        canvas.columnconfigure(0, weight=1)
        f.rowconfigure(0, weight=1)
        f.columnconfigure(0, weight=1)

        form_frame.bind("<Configure>", lambda event: canvas.configure(scrollregion=canvas.bbox("all")))
        f.grid_propagate(True)

        # Update the window size based on the frame width
        root.update_idletasks()
        new_width = form_frame.winfo_reqwidth() + f.winfo_x()
        new_height = form_frame.winfo_reqheight() + f.winfo_y()
        min_height = 850  # Change this to your dessssired minimum height
        new_height = min(new_height, min_height)

        root.geometry(f"{new_width}x{new_height}")
        root.update_idletasks()
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = (screen_width - root.winfo_width()) // 2
        y = (screen_height - root.winfo_height()) // 2
        root.geometry("+{}+{}".format(x, y))

    else:
        error_label.config(text="Please fill in all required fields.")

def open_smtp_file(frame, f, root, index):
    file_path_input = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    
    if not file_path_input:
        messagebox.showerror("Error", "Please select a CSV file.")
        return False
    
    file_name = os.path.basename(file_path_input)
    tab_directory = f"Window{index}"
    mail_password_file_name = f"mail_password_{index}.csv"
    file_path = os.path.join(base_path, tab_directory, mail_password_file_name)
    required_fields = ["email", "password", "smtp", "port", "ssl", "authentication", "name"]

    try:
        if not os.path.exists(file_path):
            with open(file_path, "w", newline='') as new_file:
                new_file.write(",".join(required_fields) + "\n")
    except Exception as create_exception:
        messagebox.showerror("Error", f"Failed to create CSV file: {str(create_exception)}")
        return False

    try:
        with open(file_path_input, "r") as selected_file:
            print(selected_file.read())
            header = selected_file.readline().strip().split(',')
            print(required_fields)
            for field in required_fields:
                if field not in header:
                    raise ValueError(f"Missing required field: {field}")
                    return False

            if not selected_file.readline():
                print(selected_file.readline())
                raise ValueError("CSV file must contain at least one email details.")
                return False
    except Exception as e:
        print(e)
        messagebox.showerror("Error", f"Invalid CSV file: {str(e)}")
        return False

    option = "SMTP"

    try:
        with open(file_path, "wb") as new_filee, open(file_path, "rb") as selected_filee:
            new_filee.write(selected_filee.read())
    except Exception as e:
        messagebox.showerror("Error", f"Error saving CSV file: {str(e)}")
        return False

    try:
        f.grid_forget()
        frame.destroy()
        canvas = tk.Canvas(f)
        canvas.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar = ttk.Scrollbar(f, orient="vertical", command=canvas.yview)
        scrollbar.grid(row=0, column=10, sticky=(tk.N, tk.S))
        canvas.configure(yscrollcommand=scrollbar.set)

        form_frame = ttk.Frame(canvas, padding="20")
        canvas.create_window((0, 0), window=form_frame, anchor="nw")

        if option == "Google API":
            create_email_form(form_frame, option, index, root)
        if option == "SMTP":
            create_email_form(form_frame, option, index, root)
        if option == "PayPal API":
            paypal_form(form_frame, option, index, root)

        form_frame.rowconfigure(0, weight=1)
        form_frame.columnconfigure(0, weight=1)
        canvas.rowconfigure(0, weight=1)
        canvas.columnconfigure(0, weight=1)
        f.rowconfigure(0, weight=1)
        f.columnconfigure(0, weight=1)

        form_frame.bind("<Configure>", lambda event: canvas.configure(scrollregion=canvas.bbox("all")))
        f.grid_propagate(True)

        # Update the window size based on the frame width
        root.update_idletasks()
        new_width = form_frame.winfo_reqwidth() + f.winfo_x()
        new_height = form_frame.winfo_reqheight() + f.winfo_y()
        min_height = 850  # Change this to your dessssired minimum height
        new_height = min(new_height, min_height)

        root.geometry(f"{new_width}x{new_height}")
        root.update_idletasks()
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = (screen_width - root.winfo_width()) // 2
        y = (screen_height - root.winfo_height()) // 2
        root.geometry("+{}+{}".format(x, y))

    except Exception as e:
        messagebox.showerror("Error", f"Error updating CSV file: {str(e)}")
        return False



def upload_json(frame, json_file_label, index):
    file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
    if file_path:

        tab_directory = f"Window{index}"
        
        # Extract the filename from the short path obtained from the file dialog
        file_name = os.path.basename(file_path)
        
        credentials_path = os.path.join(base_path, tab_directory, f"credentials_{index}.json")

        # Create the directory if it doesn't exist
        if not os.path.exists(os.path.dirname(credentials_path)):
            os.makedirs(os.path.dirname(credentials_path), exist_ok=True)

        with open(credentials_path, "wb") as new_file, open(file_path, "rb") as selected_file:
            new_file.write(selected_file.read())

        json_file_label.config(text=file_name)

    else:
        error_label.config(text="Please fill in all required fields.")

def validate_form(frame):
    for widget in frame.winfo_children():
        if isinstance(widget, ttk.Entry) and "validate" in widget.config():
            if not widget.validate():
                return False
    return True

def show_options(frame):
    frame.destroy()
    # option_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    # error_label.config(text="")



def show_main_window(login_window, f, root, index):
    # Remove the previous frame if it exists
    tab_directory = f"Window{index}"
    os.makedirs(os.path.join(base_path, tab_directory), exist_ok=True)
    login_window.grid_forget()
    if hasattr(f, "main_frame"):
        f.main_frame.destroy()

    # Create a new frame for the buttons
    main_frame = ttk.Frame(f)
    main_frame.grid(row=0, column=0, pady=(50, 50), padx=20, sticky="nsew")

    # Add logo
    canvas = tk.Canvas(main_frame, bg='black', height=50)
    canvas.grid(row=0, columnspan=10, column=0, sticky="nsew")  # Use grid to span the full window

    # Configure row and column weights to make the canvas expand with the window
    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)
    canvas.config(bg="#333333")

    logo_image_path = os.path.join(base_path, "images", "logo.png")

    logo_image = Image.open(logo_image_path)
    logo_image = logo_image.resize((200, 200))
    logo_image = ImageTk.PhotoImage(logo_image)

    logo_label = ttk.Label(main_frame, image=logo_image)
    logo_label.image = logo_image  # Keep a reference to the image
    logo_label.grid(row=0, column=0, columnspan=3, padx=10, pady=10)

    style = ttk.Style()
    style.configure("Main.TFrame", background="#333333")  # Replace "#333333" with your desired color
    main_frame.configure(style="Main.TFrame")
    f.configure(style="Main.TFrame")

    # option_label = ttk.Label(main_frame,  background="#333333", text="Select an API:")
    # option_label.grid(row=0, column=0, columnspan=3,  sticky="nsew")
    # main_frame = login_window

    button_options = ["SMTP", "Google API", "PayPal API"]

    # Sample icons, replace with the actual paths to your icons
    icon_paths = [
        os.path.join(base_path, "images", "gmail.png"),
        os.path.join(base_path, "images", "search.png"),
        os.path.join(base_path, "images", "paypal.png")
    ]
    for i, (option, icon_path) in enumerate(zip(button_options, icon_paths)):
        button = ttk.Button(main_frame, text=option, command=lambda o=option: open_page(o, main_frame, f, root, index))

        # Load the image and resize it if needed
        icon_image = Image.open(icon_path).resize((30, 30))
        icon_image = ImageTk.PhotoImage(icon_image)

        # Set the image and text on the button
        button.config(image=icon_image, compound=tk.TOP, padding=5)
        button.image = icon_image  # Keep a reference to the image

        button.grid(row=1, column=i, pady=(0, 80), sticky="nsew")

        main_frame.columnconfigure(i, weight=1)

    f.main_frame = main_frame
