import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import csv
import io
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from random import randint, choices
import string
import uuid
import datetime
from datetime import date as datee
import pdfkit
import os, sys
import time, requests
from PIL import Image
from io import BytesIO
import base64
import mimetypes
from email.message import EmailMessage
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.text import MIMEText
import threading
import google.auth
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from tkinter import ttk, filedialog, messagebox
import random
# from wkhtmltopdf import wkhtmltopdf
import shutil
import customtkinter as ctk
ctk.set_appearance_mode("System")   

from shared import shared_data
 
# Sets the color of the widgets in the window
# Supported themes : green, dark-blue, blue    
ctk.set_default_color_theme("green") 

BASE_API_URL = "https://brahmastra.site/"

def get_public_ip():
    try:
        response = requests.get('https://ipinfo.io')
        ip_data = response.json()
        print(ip_data)
        ip_address = ip_data.get('ip', 'Unable to retrieve IP')
        return ip_address
    except Exception as e:
        print(f"Error: {e}")
        return None

if getattr(sys, 'frozen', False):
    # Path when running as a PyInstaller executable
    # path_wkhtmltopdf = os.path.join(sys._MEIPASS, "w/wkhtmltopdf.exe")
    path_wkhtmltopdf = os.path.join(sys._MEIPASS, "w", "wkhtmltopdf.exe")
else:
    base_path = os.path.dirname(os.path.abspath(__file__))
    # Path in a normal environment
    path_wkhtmltopdf = os.path.join(base_path, 'w', 'wkhtmltopdf.exe')

# Configure pdfkit with the determined path
config = pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)

if getattr(sys, 'frozen', False):
    # Path when running as a PyInstaller executable
    # wkhtmltoimage_path = os.path.join(sys._MEIPASS, "w/wkhtmltoimage.exe")
    wkhtmltoimage_path = os.path.join(sys._MEIPASS, "w", "wkhtmltoimage.exe")
else:
    base_path = os.path.dirname(os.path.abspath(__file__))
    # Path in a normal environment
    wkhtmltoimage_path =  os.path.join(base_path, 'w', 'wkhtmltoimage.exe')

if getattr(sys, 'frozen', False):
    # If run as a PyInstaller executable, use sys._MEIPASS
    base_path = sys._MEIPASS
else:
    # If run as a script, use the script's directory
    base_path = os.path.dirname(os.path.abspath(__file__))

json_file_path = os.path.join(base_path, 'brahmastra_mailer_credentials.json')


from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from PIL import Image
import subprocess
import random
import string
import img2pdf
import re
import json
import sys
from tkinter.scrolledtext import ScrolledText

import secrets
import string
file_lock = threading.Lock()

parent_directory = os.path.dirname(os.path.realpath(__file__))

import os, sys
import json
import csv
import requests
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter import  Toplevel, Tk
from PIL import Image, ImageTk
from tkinter import PhotoImage

if getattr(sys, 'frozen', False):
    # If run as a PyInstaller executable, use sys._MEIPASS
    base_path = sys._MEIPASS
else:
    # If run as a script, use the script's directory
    base_path = os.path.dirname(os.path.abspath(__file__))


smtp_servers = ["", "smtp.gmail.com", "smtp.yahoo.com", "smtp.amazon.com", "smtp.mail.me.com", "smtp.aol.com", "smtp.mail.yahoo.com", "smtp-mail.outlook.com"]

def validate_not_empty(value):
    return bool(value.strip())

def validate_form(frame):
    for widget in frame.winfo_children():
        if isinstance(widget, ttk.Entry) and "validate" in widget.config():
            if not widget.validate():
                return False
    return True

def download_file():
    file_name = "test_password.csv"
    parent_directory = os.path.dirname(os.path.realpath(__file__))
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


def create_smtp_form(option, frame, f, root, index):
    smtp_form_window = tk.Toplevel(root)

    smtp_form_window.title('SMTP Form')
    # smtp_form_window.geometry('300x150')
    smtp_form_window.resizable(False, False)
    smtp_form_window.grab_set()  # Make the OTP window modal
    # smtp_form_window.attributes('-topmost', True)
    image_path = os.path.join(base_path, "images", "logo.png")
    p1 = PhotoImage(file=image_path)
    smtp_form_window.iconphoto(False, p1)
    # smtp_form_window.attributes('-top', True)
    # frame = smtp_form_window
    frame = ttk.Frame(smtp_form_window, padding="20")
    frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    style = ttk.Style()
    style.configure("Main.TFrame", background="#333333")  # Replace "#333333" with your desired color
    frame.configure(style="Main.TFrame")
    # First Column - Form Fields
    ttk.Label(frame, foreground="white", background="#333333", text="SMTP Server:").grid(row=1, column=1, pady=5, sticky=tk.W)
    smtp_server_var = tk.StringVar()
    smtp_server_var.set(smtp_servers[0])  # Default selection
    smtp_server_dropdown = ttk.Combobox(frame, textvariable=smtp_server_var, values=smtp_servers, width=27)
    smtp_server_dropdown.grid(row=1, column=2, pady=5, sticky=tk.W)

    ttk.Label(frame, foreground="white", background="#333333", text="PORT:").grid(row=2, column=1, pady=5, sticky=tk.W)
    port_entry = ttk.Entry(frame, textvariable=tk.IntVar(), width=30)
    port_entry.grid(row=2, column=2, pady=5, sticky=tk.W)
    port_entry.config(validate="focusout",  validatecommand=(port_entry.register(validate_not_empty), "%P"))

    auth_var = tk.BooleanVar()
    auth_checkbox = ttk.Checkbutton(frame, text="Enable Authentication", variable=auth_var)
    auth_checkbox.grid(row=3, column=1, pady=5, sticky=tk.W)

    ssl_var = tk.BooleanVar()
    ssl_checkbox = ttk.Checkbutton(frame, text="Enable SSL/TLS", variable=ssl_var)
    ssl_checkbox.grid(row=3, column=2, pady=5, sticky=tk.W)

    ttk.Label(frame,  foreground="white", background="#333333", text="SMTP Username:").grid(row=4, column=1, pady=5, sticky=tk.W)
    username_entry = ttk.Entry(frame, textvariable=tk.StringVar(), width=30)
    username_entry.grid(row=4, column=2, pady=5, sticky=tk.W)
    username_entry.config(validate="focusout", validatecommand=(username_entry.register(validate_not_empty), "%P"))

    ttk.Label(frame,  foreground="white", background="#333333", text="SMTP Password:").grid(row=5, column=1, pady=5, sticky=tk.W)
    password_entry = ttk.Entry(frame, textvariable=tk.StringVar(), show="*", width=30)
    password_entry.grid(row=5, column=2, pady=5, sticky=tk.W)
    password_entry.config(validate="focusout", validatecommand=(password_entry.register(validate_not_empty), "%P"))

    ttk.Label(frame,  foreground="white", background="#333333", text="Sender Name:").grid(row=6, column=1, pady=5, sticky=tk.W)
    sender_name_entry = ttk.Entry(frame, textvariable=tk.StringVar(), width=30)
    sender_name_entry.grid(row=6, column=2, pady=5, sticky=tk.W)

    ctk.CTkButton(frame, text="Submit", command=lambda: save_submit_form(option, frame, f, root, index, smtp_server_var, port_entry, auth_var, ssl_var, username_entry, password_entry, sender_name_entry, smtp_form_window)).grid(row=9, column=1, pady=10, padx=10, sticky=tk.W)
    ctk.CTkButton(frame, text="Test", command=lambda: check_submit_form(option, frame, f, root, index, smtp_server_var, port_entry, auth_var, ssl_var, username_entry, password_entry, sender_name_entry, smtp_form_window)).grid(row=9, column=2, pady=10, padx=10, sticky=tk.W)

    separator = ttk.Separator(frame, orient=tk.VERTICAL)
    separator.grid(row=1, column=3, rowspan=8, sticky="ns", padx=10)

    # Second Column - Upload Option

    ttk.Label(frame,  foreground="white", background="#333333", text="Format of CSV File :").grid(row=2, column=4, pady=5, sticky=tk.W)
    ttk.Label(frame,  foreground="white", background="#333333", text="email,password,smtp,port,ssl,authentication,name").grid(row=3, column=4, pady=5, sticky=tk.W)
    ttk.Label(frame,  foreground="white", background="#333333", text="Download Demo file").grid(row=4, column=4, pady=5, sticky=tk.W)

    smtp_file_button =  ctk.CTkButton(frame, text="Download", command=lambda: download_file())
    smtp_file_button.grid(row=5, column=4, pady=5, sticky=tk.W)
    
    ttk.Label(frame,  foreground="white", background="#333333", text="Upload file").grid(row=6, column=4, pady=5, sticky=tk.W)

    smtp_file_button =  ctk.CTkButton(frame, text="Upload", command=lambda: open_smtp_file(frame, f, root, index, smtp_form_window))
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
        elif selected_server == "smtp.mail.me.com":
            # Implement logic for Amazon
            port_entry.delete(0, tk.END)
            port_entry.insert(0, 587)  # Fill in port 465 for Gmail
            auth_var.set(True)  # Enable authentication
            ssl_var.set(True)   # Enable SSL/TLS
        elif selected_server == "smtp.mail.yahoo.com":
            # Implement logic for Amazon
            port_entry.delete(0, tk.END)
            port_entry.insert(0, 465)  # Fill in port 465 for Gmail
            auth_var.set(True)  # Enable authentication
            ssl_var.set(True)   # Enable SSL/TLS
        elif selected_server == "smtp.aol.com":
            # Implement logic for Amazon
            port_entry.delete(0, tk.END)
            port_entry.insert(0, 465)  # Fill in port 465 for Gmail
            auth_var.set(True)  # Enable authentication
            ssl_var.set(True)   # Enable SSL/TLS
        elif selected_server == "smtp-mail.outlook.com":
            # Implement logic for Amazon
            port_entry.delete(0, tk.END)
            port_entry.insert(0, 587)  # Fill in port 465 for Gmail
            auth_var.set(True)  # Enable authentication
            ssl_var.set(True)   # Enable SSL/TLS
        else:
            # Clear the entries for other servers
            port_entry.delete(0, tk.END)
            auth_var.set(False)
            ssl_var.set(False)
            username_entry.delete(0, tk.END)
            password_entry.delete(0, tk.END)
            

    smtp_server_dropdown.bind("<<ComboboxSelected>>", on_smtp_server_selected)

def check_submit_form(option, frame, f, root, index, smtp_server_var, port_entry, auth_var, ssl_var, username_entry, password_entry, sender_name_entry, smtp_form_window):
    topmost_root = Tk()
    topmost_root.withdraw()  
    if validate_form(frame):
        smtp_server = smtp_server_var.get()
        port = port_entry.get()
        enable_auth = auth_var.get()
        enable_ssl = ssl_var.get()
        username = username_entry.get()
        password = password_entry.get()
        sender_name = sender_name_entry.get()

        country_entry_window = tk.Toplevel(root)
        country_entry_window.title('Account Test')
        country_entry_window.geometry('300x150')
        country_entry_window.resizable(False, False)
        image_path = os.path.join(base_path, "images", "logo.png")
        p1 = PhotoImage(file=image_path)
        country_entry_window.iconphoto(False, p1)
        country_entry_window.grab_set()  
        country_entry_window.attributes('-topmost', True)

        ttk.Label(country_entry_window, text='Enter Email for Test:').grid(row=0, column=0, pady=10, padx=10, sticky=tk.W)

        email_entry = ttk.Entry(country_entry_window, width=20)
        email_entry.grid(row=0, column=1, pady=10, padx=10)

        ttk.Button(country_entry_window, text='Test', command=lambda: check_email(email_entry)).grid(row=1, column=0, columnspan=2,  pady=10)

        def check_email(email_entry):
            email = email_entry.get()
            try:
                if enable_ssl:
                    if int(port) == 587:
                        mailserver = smtplib.SMTP(smtp_server, int(port))
                    else:
                        mailserver = smtplib.SMTP_SSL(smtp_server, int(port))
                else:
                    mailserver = smtplib.SMTP(smtp_server, int(port))
                if int(port) == 587:
                    mailserver.starttls()
                # if smtp_enable_auth:
                mailserver.login(username, password)
                subject = f"Test Mail"
                description = f"Test Mail from Brahmastra"
                newMessage = MIMEMultipart()
                newMessage['To'] = email
                newMessage['Subject'] = subject
                newMessage.attach(MIMEText(description, 'plain'))
                newMessage['From'] = f'"{sender_name}" <{username}>'
                    

                mailserver.sendmail(username, email, newMessage.as_string())

                # Quit the SMTP session
                mailserver.quit()
                country_entry_window.destroy()
                smtp_form_window.attributes('-topmost', True)
                messagebox.showinfo("Success", f"Mail send Successfully.")

            except Exception as e:
                messagebox.showerror("Error", f"Error in Sending Mail : {e}.")

    else:
        error_label.config(text="Please fill in all required fields.")


def save_submit_form(option, frame, f, root, index, smtp_server_var, port_entry, auth_var, ssl_var, username_entry, password_entry, sender_name_entry, smtp_form_window):
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
        topmost_root = Tk()
        topmost_root.withdraw() 
        add_another = messagebox.askyesno("Add Another", "Do you want to add another entry?", parent=topmost_root)
        
        if add_another:
            clear_smtp_form(smtp_server_var, port_entry, auth_var, ssl_var, username_entry, password_entry, sender_name_entry)
        else:
            # success_label.config(text="")
            submit_smtp_data_form(option, frame, f, root, index, smtp_form_window)
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

def submit_smtp_data_form(option, frame, f, root, index, smtp_form_window):
    if validate_form(frame):
        smtp_form_window.destroy()
        account_list(f, index)
    else:
        error_label.config(text="Please fill in all required fields.")

def open_smtp_file(frame, f, root, index, smtp_form_window):
    smtp_form_window.iconify()
    file_path_input = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])

    # smtp_form_window.withdraw() 
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
        smtp_form_window.deiconify()
        return False

    try:
        with open(file_path_input, "r") as selected_file:
            header = selected_file.readline().strip().split(',')
            for field in required_fields:
                if field not in header:
                    smtp_form_window.deiconify()
                    raise ValueError(f"Missing required field: {field}")

            # Check if the file contains at least one email detail
            if not any(line.strip() and ',' in line for line in selected_file):
                smtp_form_window.deiconify()
                raise ValueError("CSV file must contain at least one email detail.")
    except Exception as e:
        messagebox.showerror("Error", f"Invalid CSV file: {str(e)}")
        smtp_form_window.deiconify()
        return False


    option = "SMTP"

    try:
        with open(file_path, "a", newline='') as new_file, open(file_path_input, "r") as selected_file:
            # Skip the header line
            selected_file.readline()

            # Append the content of the selected file to the new file
            new_file.write(selected_file.read())

        account_list(f, index)
        smtp_form_window.destroy()
    except Exception as e:
        messagebox.showerror("Error", f"Error saving CSV file: {str(e)}")
        smtp_form_window.deiconify()
        return False
    return True


def generate_random_alphanumeric(length):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(secrets.choice(characters) for _ in range(length))
    return random_string

email_filename = None


def open_file(entry, email_file_name_label, index):
    file_path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
    global email_filename
    if file_path:
        # Save the file as email.txt in the Tab directory

        tab_directory = f"Window{index}"
        parent_directory = os.path.dirname(os.path.realpath(__file__))
        email_file_name = f"Window{index}email_{index}.txt"
        email_file_name_csv = f"Window{index}email_{index}.csv"
        file_path_email = os.path.join(os.path.dirname(os.path.realpath(__file__)), email_file_name)
        file_path_email_csv = os.path.join(os.path.dirname(os.path.realpath(__file__)), email_file_name)
        if os.path.exists(file_path_email):
            os.remove(file_path_email)
        if os.path.exists(file_path_email_csv):
            os.remove(file_path_email_csv)

        if file_path.endswith(".txt"):
            file_name = f"email_{index}.txt"
            new_file_path = os.path.join(parent_directory, tab_directory, file_name)
            file_name = os.path.basename(file_path)
            email_filename = file_name
            # Create the directory if it doesn't exist
            os.makedirs(os.path.join(parent_directory, tab_directory), exist_ok=True)

            # Copy or overwrite the selected file to email.txt in the Tab directory
            with open(new_file_path, "wb") as new_file, open(file_path, "rb") as selected_file:
                new_file.write(selected_file.read())

            emails = read_emails(new_file_path)
            email_file_name_label.config(text=f"{file_name}, {len(emails)} mails in this document.")
        elif file_path.endswith(".csv"):
            with open(file_path, mode='r') as csv_file:
                # Create a CSV reader
                csv_reader = csv.DictReader(csv_file)
                # Read all rows of data
                data = list(csv_reader)

            # Ensure "email" is present in all rows
            for row in data:
                if "email" not in row:
                    raise ValueError("Email is compulsory for all rows.")

            # Specify the CSV file path for output
            csv_file_path = f"email_{index}.csv"
            email_filename = csv_file_path
            if getattr(sys, 'frozen', False):
                # Running as a bundled executable
                current_directory = sys._MEIPASS
            else:
                # Running as a script
                current_directory = os.path.dirname(__file__)

            # Create or update the directory if it doesn't exist
            credentials_dir = f"Window{index}"
            os.makedirs(os.path.join(current_directory, credentials_dir), exist_ok=True)

            # Combine the directory path and the output CSV file name
            description_csv_file_path = os.path.join(current_directory, credentials_dir, csv_file_path)

            # Write data to the output CSV file
            with open(description_csv_file_path, mode='w', newline='') as output_csv_file:
                # Extract headers from the first row of data
                headers = list(data[0].keys())
                # Create a CSV writer
                csv_writer = csv.DictWriter(output_csv_file, fieldnames=headers)
                # Write headers
                csv_writer.writeheader()
                # Write data
                csv_writer.writerows(data)
            file_name = os.path.basename(file_path)
            file_base, file_extension = os.path.splitext(file_name)
            email_file_name_label.config(text=f"{file_name} is uploaded.")
        else:
            messagebox.showerror('Error', 'Please select txt and csv file.')

def process_csv(input_csv_path, output_csv_path, number, test_email):
    # Create a new list to store the processed data
    processed_data = []

    # Read the input CSV file into a list of dictionaries
    with open(input_csv_path, 'r') as input_file:
        reader = csv.DictReader(input_file)
        data = list(reader)
        
        # Extract email addresses from the header
        emails = [row['email'] for row in data]

    # Iterate through the emails
    for index in range(len(emails)):
        # Calculate the new index based on the specified operations
        new_index = (index + number) % (len(emails) + 1)  # Add 1 to handle the case where new_index is at the end

        # Insert the test email at the calculated new index
        emails.insert(new_index, test_email)

    # Combine the emails with the header email
    processed_data = [{'email': email} for email in emails]

    # Write the result to the new CSV file
    with open(output_csv_path, 'w', newline='') as output_file:
        # Include all fields from the input CSV file in the fieldnames list
        fieldnames = ['email']
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(processed_data)
          
        
def open_subject_file(entry, subject_file_name_label, index):
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv")])

    if file_path:
        # Save the file as eemail.txt in the parent directory
        tab_directory = f"Window{index}"
        parent_directory = os.path.dirname(os.path.realpath(__file__))
        file_subject = f"subject_{index}.txt"
        new_file_path = os.path.join(parent_directory, tab_directory, file_subject)
        file_name = os.path.basename(file_path)

        # Create the directory if it doesn't exist
        os.makedirs(os.path.join(parent_directory, tab_directory), exist_ok=True)

        # Copy or overwrite the selected file to subject.txt in the Tab directory
        with open(new_file_path, "wb") as new_file, open(file_path, "rb") as selected_file:
            new_file.write(selected_file.read())

        emails = read_emails(new_file_path)
        subject_file_name_label.config(text=f"{file_name}, {len(emails)} subjects.")

def open_sender_name_file(entry, sender_file_name_label, index):
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv")])

    if file_path:
        tab_directory = f"Window{index}"
        parent_directory = os.path.dirname(os.path.realpath(__file__))
        sender_file_name = f"sender_name_{index}.txt"
        new_file_path = os.path.join(parent_directory, tab_directory, sender_file_name)
        file_name = os.path.basename(file_path)

        # Create the directory if it doesn't exist
        os.makedirs(os.path.join(parent_directory, tab_directory), exist_ok=True)

        # Copy or overwrite the selected file to sender_name.txt in the Tab directory
        with open(new_file_path, "wb") as new_file, open(file_path, "rb") as selected_file:
            new_file.write(selected_file.read())

        emails = read_emails(new_file_path)
        sender_file_name_label.config(text=f"{file_name}, {len(emails)} Sender Name.")

def open_html(frame, tree, attachment_type_var, index):
    print(attachment_type_var)
    if attachment_type_var.get() == "normal":
        file_path = filedialog.askopenfilename(filetypes=[("All files", f"*.*")])
    else:
        file_path = filedialog.askopenfilename(filetypes=[("HTML files", "*.html")])

    if file_path:
        # Save the HTML file with a random name
        if attachment_type_var.get() == 'normal':
            file_name = os.path.basename(file_path)
            file_base, file_extension = os.path.splitext(file_name)
        else:
            file_base = generate_random_filename()
            file_extension = ".html"

        tab_directory = f"Window{index}"
        parent_directory = os.path.dirname(os.path.realpath(__file__))
        new_file_path = os.path.join(parent_directory, tab_directory, f"{file_base}{file_extension}")

        # Create the directory if it doesn't exist
        os.makedirs(os.path.join(parent_directory, tab_directory), exist_ok=True)

        # Copy or overwrite the selected HTML file to the parent directory with a random name
        with open(new_file_path, "wb") as new_file, open(file_path, "rb") as selected_file:
            new_file.write(selected_file.read())

        # Create or update attachments.json
        attachments_file_name = f"attachments_{index}.json"
        attachments_json_path = os.path.join(parent_directory, tab_directory, attachments_file_name)
        attachments_data = read_attachments_json(attachments_json_path)
        attachments_data.append({
            "file_name": f"{file_base}{file_extension}",
            "attachment_type": attachment_type_var.get()
        })
        write_attachments_json(attachments_json_path, attachments_data)

        # Update the Treeview
        update_tree(tree, attachments_data)

def open_description_file(frame, tree, description_type_var, index):
    description_type_var = description_type_var.get()
    if description_type_var == 'html':
        file_path = filedialog.askopenfilename(filetypes=[("HTML files", "*.html")])
    else:
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])

    if file_path:
        # Save the HTML file with a random name
        random_filename = generate_random_filename()
        tab_directory = f"Window{index}"
        parent_directory = os.path.dirname(os.path.realpath(__file__))
        new_file_path = os.path.join(parent_directory, tab_directory, f"{random_filename}.{description_type_var}")

        # Create the directory if it doesn't exist
        os.makedirs(os.path.join(parent_directory, tab_directory), exist_ok=True)

        # Copy or overwrite the selected HTML file to the parent directory with a random name
        with open(new_file_path, "wb") as new_file, open(file_path, "rb") as selected_file:
            new_file.write(selected_file.read())

        # Create or update attachments.json
        description_file_path_name = f"description_{index}.json"
        attachments_json_path = os.path.join(parent_directory, tab_directory, description_file_path_name)
        attachments_data = read_attachments_json(attachments_json_path)
        attachments_data.append({
            "file_name": f"{random_filename}.{description_type_var}",
            "attachment_type": description_type_var
        })
        write_attachments_json(attachments_json_path, attachments_data)

        # Update the Treeview
        update_tree(tree, attachments_data)

def open_description_header_file(frame, description_file_name_label, description_type_var, index):
    # Ask the user to select a CSV file
    file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])

    if not file_path:
        # No file selected, handle accordingly
        return

    # Read data from the selected CSV file
    with open(file_path, mode='r') as csv_file:
        # Create a CSV reader
        csv_reader = csv.DictReader(csv_file)
        # Read all rows of data
        data = list(csv_reader)

    # Ensure "email" is present in all rows
    for row in data:
        if "email" not in row:
            raise ValueError("Email is compulsory for all rows.")

    # Specify the CSV file path for output
    csv_file_path = "description_header_output.csv"

    if getattr(sys, 'frozen', False):
        # Running as a bundled executable
        current_directory = sys._MEIPASS
    else:
        # Running as a script
        current_directory = os.path.dirname(__file__)

    # Create or update the directory if it doesn't exist
    credentials_dir = f"Window{index}"
    os.makedirs(os.path.join(current_directory, credentials_dir), exist_ok=True)

    # Combine the directory path and the output CSV file name
    description_csv_file_path = os.path.join(current_directory, credentials_dir, csv_file_path)

    # Write data to the output CSV file
    with open(description_csv_file_path, mode='w', newline='') as output_csv_file:
        # Extract headers from the first row of data
        headers = list(data[0].keys())
        # Create a CSV writer
        csv_writer = csv.DictWriter(output_csv_file, fieldnames=headers)
        # Write headers
        csv_writer.writeheader()
        # Write data
        csv_writer.writerows(data)
    file_name = os.path.basename(file_path)
    file_base, file_extension = os.path.splitext(file_name)
    description_file_name_label.config(text=f"{file_name} is uploaded.")
    print(f"Output CSV file saved at: {description_csv_file_path}")


def update_tree(tree, attachments_data):
    # Clear previous items in the Treeview
    for item in tree.get_children():
        tree.delete(item)

    # Insert new items into the Treeview
    for attachment in attachments_data:
        tree.insert("", "end", values=(attachment["file_name"], attachment["attachment_type"]))

def generate_random_filename():
    import secrets
    import string

    characters = string.ascii_letters + string.digits
    random_string = ''.join(secrets.choice(characters) for _ in range(8))
    return random_string

def read_attachments_json(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
    except FileNotFoundError:
        data = []
    return data

def write_attachments_json(file_path, data):
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=2)
      
def toggle_custom_filename(entry, state_var):
    if state_var.get() == "Custom":
        entry["state"] = "normal"
    else:
        entry["state"] = "disabled"

def toggle_custom_mail_type(entry, custom_email_entry, state_var):
    if state_var.get() == "Send After":
        entry["state"] = "normal"
        custom_email_entry['state'] = "normal"
    else:
        entry["state"] = "disabled"
        custom_email_entry['state'] = "disabled"

stop_flag = False

def stop_execution():
    global stop_flag
    stop_flag = True
    print("Stopped Successfully.")

def fetch_random_name(main_window):
    url = f'{BASE_API_URL}random_name/'
    with open(json_file_path, 'r') as file:
        json_file_path_data = json.load(file)
        print(json_file_path_data)
        bearer = json_file_path_data.get('access_token')
        headers = {
            'Authorization': f'Bearer {bearer}'
        }
        print(headers)

        try:
            response = requests.get(url, headers=headers)
            # response.raise_for_status()
            user_data = response.json()
            print(user_data)
            full_name = user_data.get('sender_name', '')
            return full_name
        except Exception as e:
            sign_out(main_window)
            print(e)

def fetch_random_subject(main_window):
    url = f'{BASE_API_URL}random_subject/'
    with open(json_file_path, 'r') as file:
        json_file_path_data = json.load(file)
        print(json_file_path_data)
        bearer = json_file_path_data.get('access_token')
        headers = {
            'Authorization': f'Bearer {bearer}'
        }
        print(headers)

        try:
            response = requests.get(url, headers=headers)
            # response.raise_for_status()
            user_data = response.json()
            print(user_data)
            subject = user_data.get('subject', '')
            return subject
        except Exception as e:
            sign_out(main_window)
            print(e)

def fetch_random_description(main_window):
    url = f'{BASE_API_URL}random_description/'
    with open(json_file_path, 'r') as file:
        json_file_path_data = json.load(file)
        print(json_file_path_data)
        bearer = json_file_path_data.get('access_token')
        headers = {
            'Authorization': f'Bearer {bearer}'
        }
        print(headers)

        try:
            response = requests.get(url, headers=headers)
            # response.raise_for_status()
            user_data = response.json()
            print(user_data)
            description = user_data.get('description', '')
            return description
        except Exception as e:
            sign_out(main_window)
            print(e)


def create_email_form(root, option, index, main_window):
    # Create a frame
    style = ttk.Style()
    style.configure("Main.TFrame", background="#333333")  # Replace "#333333" with your desired color
    root.configure(style="Main.TFrame")
    style.map("Main.TFrame", background=[("selected", "#333333")])
    # main_window.configure(style="Main.TFrame")

    frame = ttk.Frame(root)
    frame.grid(row=0, column=0, padx=20, sticky="nsew")
    style = ttk.Style()
    style.configure("Main.TFrame", background="#333333")  # Replace "#333333" with your desired color
    frame.configure(style="Main.TFrame")
    verify_url = f'{BASE_API_URL}home/'

    canvas = tk.Canvas(frame, bg='black', height=50)
    canvas.grid(row=0, columnspan=10, column=0, sticky="nsew")  # Use grid to span the full window

    # Configure row and column weights to make the canvas expand with the window
    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)
    canvas.config(bg="#333333")

    with open(json_file_path, 'r') as file:
        json_file_path_data = json.load(file)
        print(json_file_path_data)
        bearer = json_file_path_data.get('access_token')
        headers = {
            'Authorization': f'Bearer {bearer}'
        }
        print(headers)

        try:
            response = requests.get(verify_url, headers=headers)
            # response.raise_for_status()
            user_data = response.json()
            print(user_data)
            full_name = user_data.get('full_name', '')
            # Update labels with user information
            full_name_label = ttk.Label(frame,text=f"{full_name} ({get_public_ip()})", foreground="white", background="#333333", font=("Helvetica", 12, "bold")).grid(row=0, column=0, pady=5, padx=5, sticky=tk.W)
            
        except Exception as e:
            sign_out(main_window)
            print(e)

    logo_image_path = os.path.join(base_path, "images", "logo.png")

    logo_image = Image.open(logo_image_path)
    logo_image = logo_image.resize((100, 100))
    logo_image = ImageTk.PhotoImage(logo_image)


    logo_label = ttk.Label(frame, image=logo_image)
    logo_label.image = logo_image 
    logo_label.grid(row=0, column=1, columnspan=2)

    default_country_name = shared_data['country_name'] if shared_data['country_name'] else ""

    selected_country = tk.StringVar(value=default_country_name)
    # Create a dropdown to display country names
    country_dropdown = ttk.Combobox(frame, textvariable=selected_country, state="readonly")
    country_dropdown.grid(row=0, column=3)

    def update_selected_country(*args):
        new_country_name = selected_country.get()
        selected_country.set(new_country_name)
        shared_data['country_name'] = new_country_name
        print(new_country_name)

    selected_country.trace_add("write", lambda *args: update_selected_country())



    try:
        response = requests.get('https://restcountries.com/v2/all')
        countries_data = response.json()

        # Extract country names from the response
        country_names = [country['name'] for country in countries_data]

        # Update the dropdown with the fetched country names
        country_dropdown['values'] = country_names
    except requests.RequestException as e:
        print('Error fetching countries:', e)

    tags_label_show = ttk.Label(frame, text="Tags", foreground="white", background="#333333", font=("Helvetica", 12, "bold"))
    tags_label_show.grid(row=0, column=5, pady=5, padx=5, sticky=tk.W)

    style.configure("Main.TButton", background="blue" ,foreground = "blue")


    # Subject
    subject_label = ttk.Label(frame,  foreground="white", background="#333333", text="Subject :")
    subject_label.grid(row=1, column=0, padx=5, sticky=tk.W)

    # Name Entry Field
    subject_name_entry = ctk.CTkEntry(frame,placeholder_text="Subject")
    subject_name_entry.grid(row=1, column=1,padx=2,pady=2, sticky="ew")

    subject_file_button = ctk.CTkButton(frame, command=lambda:  open_subject_file(frame, subject_file_name_label, index),
                                    text="Upload")
    
    subject_file_button.grid(row=1, column=2,padx=10, pady=10,sticky="ew")
    # subject_file_ai_button = ctk.CTkButton(frame, command=lambda:  open_subject_file(frame, subject_file_name_label, index),
    #                                 text="Ai")
    # subject_file_ai_button.grid(row=1, column=3,padx=10, pady=10,sticky="ew")

    subject_file_name_label = ttk.Label(frame, foreground="white", background="#333333", text="")
    subject_file_name_label.grid(row=2, column=3, padx=10, pady=10, sticky="ew")

    ai_subject = tk.BooleanVar()

    def update_ai_subject_value():
        ai_value = ai_subject.get()
        if ai_value == True:
            fetch_subject = fetch_random_subject(main_window)
            print(fetch_subject)
            if fetch_subject is not None:
                subject_name_entry.delete(0, tk.END)
                subject_name_entry.insert(tk.END, fetch_subject)
            rotate_subject_checkbox.grid(row=1, column=4, pady=10, padx=10, sticky="ew")
            subject_file_name_label.config(text="")
        else:
            rotate_subject.set(ai_value)
            rotate_subject_checkbox.grid_remove()

    rotate_ai_checkbox = ttk.Checkbutton(frame, text="AI", variable=ai_subject, command=update_ai_subject_value)
    rotate_ai_checkbox.grid(row=1, column=3, pady=10, padx=10, sticky="ew")

    rotate_subject = tk.BooleanVar()
    rotate_subject_checkbox = ttk.Checkbutton(frame, text="Rotate", variable=rotate_subject)



    if option == "Google API":
        sender_name_label = ttk.Label(frame, foreground="white",  background="#333333", text="Sender Name :")
        sender_name_label.grid(row=2, column=0,  sticky=tk.W)
        
        def update_sender_name_type(*args):
            selected_sender_name_type = sender_name_type.get()

            if selected_sender_name_type == "Upload":
                sender_name_file_button.grid(row=2, column=2,
                                        
                                        padx=10, pady=10,
                                        sticky="ew")
                # sender_name_file_button.configure(style="Main.TButton")
                sender_name_entry.grid_remove()
                sender_name_file_name_label.grid(row=3, column=2,  pady=10, padx=10, sticky=tk.W)

            elif selected_sender_name_type == "Write":
                sender_name_entry.grid(row=2, column=2,padx=10, pady=10,
                                    sticky="ew" )
                sender_name_file_button.grid_remove()
                sender_name_file_name_label.grid_remove()
                rotate_sender_name_checkbox.grid_remove()
            elif selected_sender_name_type == "AI":
                rotate_sender_name_checkbox.grid(row=2, column=2, pady=10, padx=10, sticky="ew")
                sender_name_file_button.grid_remove()
                sender_name_file_name_label.grid_remove()
                
            else:
                sender_name_file_button.grid_remove()
                sender_name_entry.grid_remove()
                rotate_sender_name_checkbox.grid_remove()
                sender_name_file_name_label.grid_remove()


        sender_name_type = tk.StringVar()
        sender_name_type.set("Upload")
        sender_name_type.trace_add("write", update_sender_name_type)
        def update_variable(*args):
            sender_name_type.set(sender_name_type_dropdown.get())

        # sender_name_type_dropdown = ttk.Combobox(frame, textvariable=sender_name_type, values=["Write", "Upload", "AI"])
        # sender_name_type_dropdown.grid(row=5, column=3, sticky=tk.W)

        sender_name_type_dropdown = ctk.CTkOptionMenu(frame,  command=update_variable,
                                       values=[ "Upload","Write", "AI"])
        sender_name_type_dropdown.grid(row=2, column=1,
                                       padx=10, pady=10,
                                    sticky="ew")
        

        sender_name_type_dropdown.bind("<<ComboboxSelected>>", update_variable)

        sender_name_entry = ttk.Entry(frame, width=30)

        rotate_sender_name = tk.BooleanVar()
        rotate_sender_name_checkbox = ttk.Checkbutton(frame, text="Rotate", variable=rotate_sender_name)
        

        # sender_name_entry.grid(row=4, column=2, pady=5)
        # sender_name_file_button = ttk.Button(frame, text="Upload", command=lambda: open_sender_name_file(frame, sender_name_file_name_label, index))
        # sender_name_file_button.grid(row=6, column=3, sticky=tk.W)
        sender_name_file_button = ctk.CTkButton(frame, command=lambda: open_sender_name_file(frame, sender_name_file_name_label, index),
                                         text="Upload")
        sender_name_file_button.grid(row=2, column=2,
                                        
                                        padx=10, pady=10,
                                        sticky="ew")
        
        sender_name_file_name_label = ttk.Label(frame, foreground="white", background="#333333", text="")

        sender_name_file_name_label.grid(row=3, column=2,  pady=10, padx=10, sticky=tk.W)
        sender_email_label = ttk.Label(frame, foreground="white",  background="#333333", text="Sender Email :")
        sender_email_label.grid(row=3, column=0, sticky=tk.W)
        sender_email_entry = ttk.Entry(frame, width=30)
        sender_email_entry.grid(row=3, column=1,padx=10, pady=10,
                                    sticky="ew")
    else:
        sender_name_entry = ttk.Entry(frame)
        sender_name_type = ttk.Entry(frame)
        sender_email_entry = ttk.Entry(frame)
        rotate_sender_name = tk.BooleanVar()


    attachement_file_label = ttk.Label(frame, foreground="white", background="#333333", text="Attachements :").grid(row=4, column=0, pady=5, sticky=tk.W)
    attachment_type_var = tk.StringVar()
    attachment_type_var.set("jpgtopdf")  

    def attachements_update_variable(*args):
        attachment_type_var.set(attachment_type_dropdown.get())

    attachment_type_dropdown = ctk.CTkOptionMenu(frame, command=attachements_update_variable,
                                       values=[ "jpgtopdf",  "pdf", "jpg", "png","normal"])
    attachment_type_dropdown.grid(row=4, column=1,
                                    padx=10, pady=10,
                                sticky="ew")
    attachment_type_dropdown.bind("<<ComboboxSelected>>", attachements_update_variable)

    html_button = ctk.CTkButton(frame, command=lambda:  open_html(frame, tree, attachment_type_var, index),
                                        text="Upload")
    html_button.grid(row=4, column=2,padx=10, pady=10,sticky="ew")
    # html_button.configure(style="Main.TButton")

    # Treeview to display attachments
    tree = ttk.Treeview(frame, columns=("File Name", "Attachment Type"), show="headings", height=5)
    tree.heading("File Name", text="File Name")
    tree.heading("Attachment Type", text="Attachment Type")
    tree.grid(row=5, column=0, columnspan=2, rowspan=2, sticky = tk.W)

    clear_all_attachments_button = ctk.CTkButton(frame, text="Clear All Attachments", command=lambda: clear_all_attachments(tree, index))
    clear_all_attachments_button.grid(row=5, column=2,padx=10, pady=10,sticky="ew")

    # Function to clear all attachments from the Treeview
    def clear_all_attachments(tree, index):
        for item in tree.get_children():
            values = tree.item(item, 'values')
            file_name = values[0]
            attachment_type = values[1]

            # Remove file associated with the attachment
            file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), file_name)
            if os.path.exists(file_path):
                os.remove(file_path)

            # Remove the attachment from the Treeview
            tree.delete(item)

        # Remove the JSON file containing attachment information
        attachements_file_name = f"Window{index}/attachments_{index}.json"
        file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), attachements_file_name)
        if os.path.exists(file_path):
            os.remove(file_path)

    # Function to clear a selected attachment from the Treeview
    def clear_selected_attachment(tree, index):
        selected_item = tree.selection()
        if selected_item:
            values = tree.item(selected_item, 'values')
            file_name = values[0]
            attachment_type = values[1]

            # Remove file associated with the selected attachment
            file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), file_name)
            if os.path.exists(file_path):
                os.remove(file_path)

            # Remove the selected attachment from the Treeview
            tree.delete(selected_item)

            # Update JSON file without the selected attachment
            attachments_file_name = f"Window{index}/attachments_{index}.json"
            file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), attachments_file_name)
            if os.path.exists(file_path):
                attachments_data = read_attachments_json(file_path)
                attachments_data = [attachment for attachment in attachments_data if attachment.get("file_name") != file_name]
                with open(file_path, 'w') as json_file:
                    json.dump(attachments_data, json_file)


    # Button to clear a selected attachment
    clear_selected_attachment_button = ctk.CTkButton(frame, text="Clear Selected Attachment", command=lambda: clear_selected_attachment(tree, index))
    clear_selected_attachment_button.grid(row=6, column=2 , padx=10, pady=10,sticky="ew")
    # clear_selected_attachment_button.configure(style="Main.TButton")


    def update_description_type(*args):
        selected_des_type = description_type_input_var.get()

        if selected_des_type == "Write":
            description_text.grid(row=10, column=0, columnspan=3,rowspan=2, pady=5, sticky=tk.W)
            description_type_input_button.grid_remove()
            clear_all_description_attachments_button.grid_remove()
            clear_selected_description_attachment_button.grid_remove()
            rotate_ai_checkbox.grid(row=10, column=3, pady=10, padx=10,sticky="ew")
            description_tree.grid_remove()

        elif selected_des_type == "Upload":
            description_text.grid_remove()
            rotate_description_checkbox.grid_remove()
            rotate_ai_checkbox.grid_remove()
            description_type_input_button.grid(row=9, column=2, pady=10, padx=10,sticky="ew")
            description_tree.grid(row=9, column=0, columnspan=2, rowspan = 3, pady=10,sticky="ew")
            clear_all_description_attachments_button.grid(row=10, column=2, pady=10, padx=10,sticky="ew")
            clear_selected_description_attachment_button.grid(row=11, column=2, pady=10, padx=10,sticky="ew")

        else:
            description_text.grid_remove()
            rotate_ai_checkbox.grid_remove()
            description_type_input_button.grid_remove()
            rotate_description_checkbox.grid_remove()
            description_tree.grid_remove()
            clear_all_description_attachments_button.grid_remove()
            clear_selected_description_attachment_button.grid_remove()

    # Description Type
    description_type_label = ttk.Label(frame, foreground="white", background="#333333", text="Description Type :")
    description_type_label.grid(row=8, column=0, pady=5,sticky="ew")
    description_type_var = tk.StringVar()
    description_type_var.set("html")
    def description_update_variable(value):
        description_type_var.set(value)
    description_types = ["html", "txt"]


    for i, description_type in enumerate(description_types):
        rb = tk.Radiobutton(frame, text=description_type, variable=description_type_var, value=description_type,
                            command=lambda type=description_type: description_update_variable(type))
        rb.grid(row=8, column=2+i, padx=10, pady=10, sticky="ew")

    description_type_input_var = tk.StringVar()
    description_type_input_var.set("Write")
    description_type_input_var.trace_add("write", update_description_type)
    def description_type_update_variable(*args):
        description_type_input_var.set(description_type_input_dropdown.get())

    description_type_input_dropdown = ctk.CTkOptionMenu(frame, command=description_type_update_variable,values=["Write", "Upload"])
    description_type_input_dropdown.grid(row=8, column=1,padx=10, pady=10,sticky="ew")
    description_type_input_dropdown.bind("<<ComboboxSelected>>", description_type_update_variable)
    # description_type_input_dropdown = ttk.Combobox(frame, textvariable=description_type_input_var, values=["Write", "Upload"])
    # description_type_input_dropdown.grid(row=8, column=1, pady=5, sticky=tk.W)
    description_type_input_button =  ctk.CTkButton(frame, text="Upload",  command=lambda: open_description_file(frame, description_tree, description_type_var, index))

    description_text = tk.Text(frame, height=10, width=70)
    # description_text.grid(row=8, column=0, columnspan=2, pady=5, sticky=tk.W)
    description_text.grid(row=10, column=0, columnspan=3, rowspan=2, pady=5, sticky=tk.W)

    description_tree = ttk.Treeview(frame, columns=("File Name", "Attachment Type"), show="headings", height=6)
    description_tree.heading("File Name", text="File Name")
    description_tree.heading("Attachment Type", text="Attachment Type")
    


    ai_description = tk.BooleanVar()

    def update_ai_description_value():
        ai_value = ai_description.get()
        if ai_value == True:
            fetch_description = fetch_random_description(main_window)
            print(fetch_description)
            if fetch_description is not None:
                description_text.delete(1.0, tk.END)
                description_text.insert(tk.END, fetch_description)
            rotate_description_checkbox.grid(row=11, column=3, pady=10, padx=10, sticky="ew")
        else:
            rotate_description.set(ai_value)
            rotate_description_checkbox.grid_remove()

    rotate_ai_checkbox = ttk.Checkbutton(frame, text="AI", variable=ai_description, command=update_ai_description_value)
    rotate_ai_checkbox.grid(row=10, column=3, pady=10, padx=10, sticky="ew")

    rotate_description = tk.BooleanVar()
    rotate_description_checkbox = ttk.Checkbutton(frame, text="Rotate", variable=rotate_description)


    # Function to clear all attachments from the Treeview
    def clear_all_description_attachments(tree, index):
        for item in tree.get_children():
            values = tree.item(item, 'values')
            file_name = values[0]
            attachment_type = values[1]

            # Remove file associated with the attachment
            file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), file_name)
            if os.path.exists(file_path):
                os.remove(file_path)

            # Remove the attachment from the Treeview
            tree.delete(item)

        # Remove the JSON file containing attachment information
        description_file_name = f"Window{index}/description_{index}.json"
        file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), description_file_name)
        if os.path.exists(file_path):
            os.remove(file_path)

    # Function to clear a selected attachment from the Treeview
    def clear_selected_description_attachment(tree, index):
        selected_item = tree.selection()
        if selected_item:
            values = tree.item(selected_item, 'values')
            file_name = values[0]
            attachment_type = values[1]

            # Remove file associated with the selected attachment
            file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), file_name)
            if os.path.exists(file_path):
                os.remove(file_path)

            # Remove the selected attachment from the Treeview
            tree.delete(selected_item)

            # Update JSON file without the selected attachment
            description_file_name = f"Window{index}/description_{index}.json"
            file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), description_file_name)
            if os.path.exists(file_path):
                attachments_data = read_attachments_json(file_path)
                attachments_data = [attachment for attachment in attachments_data if attachment.get("file_name") != file_name]
                with open(file_path, 'w') as json_file:
                    json.dump(attachments_data, json_file)

    # Button to clear all attachments
    clear_all_description_attachments_button =  ctk.CTkButton(frame, text="Clear All Attachments", command=lambda: clear_all_description_attachments(description_tree, index))
    
    # Button to clear a selected attachment
    clear_selected_description_attachment_button = ctk.CTkButton(frame, text="Clear Selected Attachment", command=lambda: clear_selected_description_attachment(description_tree, index))
    

    # Attachments Name
    attachments_name_label = ttk.Label(frame,foreground="white",  background="#333333", text="Attachments Name :")
    attachments_name_label.grid(row=12, column=0, pady=5, sticky=tk.W)

    attachments_name_var = tk.StringVar()
    attachments_name_var.set("Alpha Numeric")

    def attachments_name_variable(*args):
        attachments_name_var.set(attachments_name_dropdown.get())
        if attachments_name_dropdown.get() == "Custom":
            custom_filename_entry.grid(row=12, column=2, padx = 10, pady = 10,  sticky="ew")
        else:
            custom_filename_entry.grid_remove()

    attachments_name_dropdown = ctk.CTkOptionMenu(frame, command=attachments_name_variable,
                                      values=["Alpha Numeric", "Numeric", "Custom"])
    attachments_name_dropdown.grid(row=12, column=1,
                                    padx=10, pady=10,
                                sticky="ew")
    attachments_name_dropdown.bind("<<ComboboxSelected>>", attachments_name_variable)
    # attachments_name_dropdown = ttk.Combobox(frame, textvariable=attachments_name_var, values=["Alpha Numeric", "Numeric", "Custom"])
    # attachments_name_dropdown.grid(row=12, column=1, pady=5, sticky=tk.W)

    custom_filename_entry = ttk.Entry(frame)
    

    def update_mail_type(*args):
        selected_mail_type = mail_type_dropdown.get()

        if selected_mail_type == "Send After":
            mail_type_var.set("Send After")
            mail_type_number_label.grid(row=14, column=0, padx=10, pady=10,sticky="ew")
            custom_email_type_dropdown.grid(row=14, column=1,
                                    padx=10, pady=10,
                                sticky="ew")
            mail_type_test_label.grid(row=13, column=2,padx=10, pady=10, sticky="ew")
            custom_email_entry.grid(row=14, column=2,padx=10, pady=10, sticky="ew")
        else:
            mail_type_number_label.grid_remove()
            custom_email_type_dropdown.grid_remove()
            mail_type_test_label.grid_remove()
            custom_email_entry.grid_remove()


    # Mail Type
    mail_type_label = ttk.Label(frame,foreground="white",  background="#333333", text="Mail Type :")
    mail_type_label.grid(row=13, column=0, pady=5, sticky=tk.W)

    mail_type_var = tk.StringVar()
    mail_type_var.set("Plain Mail")
    mail_type_var.trace_add("write", update_mail_type)

    # mail_type_dropdown = ttk.Combobox(frame, textvariable=mail_type_var, values=["Plain Mail", "Send After"])
    # mail_type_dropdown.grid(row=13, column=1, pady=5, sticky=tk.W)


    mail_type_dropdown = ctk.CTkOptionMenu(frame, command=update_mail_type,
                                      values=["Plain Mail", "Send After"])
    mail_type_dropdown.grid(row=13, column=1,
                                    padx=10, pady=10,
                                sticky="ew")
    mail_type_dropdown.bind("<<ComboboxSelected>>", update_mail_type)

    custom_email_type_var = tk.StringVar()
    custom_email_type_var.set("25")

    def custom_email_type_variable(*args):
        custom_email_type_var.set(custom_email_type_dropdown.get())

    mail_type_number_label = ttk.Label(frame,foreground="white",  background="#333333", text="After No. of mail :")
    # mail_type_number_label.grid(row=10, column=0, pady=5, sticky=tk.W)

    # custom_email_type_dropdown = ttk.Combobox(frame, state="disabled", textvariable=custom_email_type_var, values=["25", "50", "100", "150", "250", "500"])
    # custom_email_type_dropdown.grid(row=10, column=1, pady=5)
    custom_email_type_dropdown = ctk.CTkOptionMenu(frame, command=custom_email_type_variable,
                                     values=["25", "50", "100", "150", "250", "500"])
    
    custom_email_type_dropdown.bind("<<ComboboxSelected>>", custom_email_type_variable)
    mail_type_test_label = ttk.Label(frame,foreground="white",  background="#333333", text="Send After Mail :")
    # mail_type_test_label.grid(row=10, column=2, pady=5, sticky=tk.W)

    custom_email_entry = ttk.Entry(frame,  width=20)
    # custom_email_entry.grid(row=10, column=3, pady=5)


    def toggle_custom_mail_type(entry1, entry2, var):
        if var.get() == "Send After":
            entry1.config(state="normal")
            entry2.config(state="normal")
        else:
            entry1.delete(0, tk.END)
            entry2.delete(0, tk.END)
            entry1.config(state="disabled")
            entry2.config(state="disabled")

    # Event binding to toggle visibility of the custom_email_type_entry and custom_email_entry
    mail_type_dropdown.bind("<<ComboboxSelected>>", lambda event: toggle_custom_mail_type(custom_email_type_dropdown, custom_email_entry, mail_type_var))

    # Submit Button
    def on_submit_button_click():
        global stop_flag
        stop_flag = False
        form_data = get_form_data(sender_name_type, sender_name_entry, sender_email_entry, subject_name_entry, description_type_var, description_type_input_var, description_text, custom_filename_entry, attachments_name_var, custom_email_type_var, mail_type_var, custom_email_entry, email_text, rotate_sender_name, rotate_subject, rotate_description)
        threading.Thread(target=submit_form, args=(form_data, option, index, frame, listbox,listbox_details, main_window)).start()

    # Create the button and associate the new command
    submit_button = ctk.CTkButton(frame, text="Send", command=on_submit_button_click)

    # submit_button = ttk.Button(frame, text="Submit", command=lambda: submit_form(get_form_data(sender_name_entry,subject_name_entry, description_type_var, description_type_input_var, description_text, custom_filename_entry, attachments_name_var,custom_email_type_var, mail_type_var, custom_email_entry, ), option))
    submit_button.grid(row=15, column=0, pady=10, sticky=tk.W)
    # submit_button.configure(style="Main.TButton")

    gmass_email_type_var = tk.StringVar()
    gmass_email_type_var.set("G Mass")

    def on_gmasssubmit_button_click():
        global stop_flag
        stop_flag = False
        form_data = get_form_data(sender_name_type, sender_name_entry, sender_email_entry, subject_name_entry, description_type_var, description_type_input_var, description_text, custom_filename_entry, attachments_name_var, custom_email_type_var, gmass_email_type_var, custom_email_entry, email_text, rotate_sender_name, rotate_subject, rotate_description)
        threading.Thread(target=submit_form, args=(form_data, option, index, frame, listbox, listbox_details, main_window)).start()
    icon_path = os.path.join(base_path, "images", "OIP.jpg")
    # Create the button and associate the new command
    # submit_button_mass = ctk.CTkButton(frame, text="G Mass", command=on_gmasssubmit_button_click)
    submit_button_mass = ttk.Button(frame, text="", command=on_gmasssubmit_button_click)

    # Load the image and resize it if needed
    icon_image = Image.open(icon_path).resize((80, 30))
    icon_image = ImageTk.PhotoImage(icon_image)

    # Set the image and text on the button
    submit_button_mass.config(image=icon_image)
    submit_button_mass.image = icon_image  # Keep a reference to the image

    submit_button_mass.grid(row=15, column=1)
    # submit_button = ttk.Button(frame, text="G Mass", command=lambda: submit_form(get_form_data(sender_name_entry,subject_name_entry, description_type_var, description_type_input_var, description_text, custom_filename_entry, attachments_name_var,custom_email_type_var, gmass_email_type_var, custom_email_entry), option))
    # submit_button_mass.grid(row=15, column=1, padx=10, pady=10,sticky="ew")
    # submit_button_mass.configure(style="Main.TButton")

    test_email_type_var = tk.StringVar()
    test_email_type_var.set("Testing")

    test_mail_entry = ttk.Entry(frame, width=30)
    test_mail_entry.grid(row=15, column=2, padx=10, pady=10,sticky="ew")

    def on_test_button_click():
        global stop_flag
        stop_flag = False
        form_data = get_form_data(sender_name_type, sender_name_entry, sender_email_entry, subject_name_entry, description_type_var, description_type_input_var, description_text, custom_filename_entry, attachments_name_var, custom_email_type_var, test_email_type_var, test_mail_entry, email_text, rotate_sender_name, rotate_subject, rotate_description)
        threading.Thread(target=submit_form, args=(form_data, option, index, frame, listbox,listbox_details, main_window)).start()

    # Create the button and associate the new command
    submit_button_test = ctk.CTkButton(frame, text="Test", command=on_test_button_click)

    # submit_button_test = ttk.Button(frame, text="Test", command=lambda: submit_form(get_form_data(sender_name_entry,subject_name_entry, description_type_var, description_type_input_var, description_text, custom_filename_entry, attachments_name_var,custom_email_type_var, test_email_type_var, test_mail_entry), option))
    submit_button_test.grid(row=15, column=3, padx=10, pady=10,sticky="ew")

    listbox_details = tk.Listbox(frame, height=10, width=150)
    listbox_details.grid(row=16, column=0, rowspan=3, columnspan=5, pady=10, sticky=tk.W)

    listbox = ttk.Label(frame, foreground="white", background="#333333", text="")
    listbox.grid(row=14, column=8, rowspan=2, pady=10, padx=10, sticky="ew")


    stop_button = ctk.CTkButton(frame, text="Stop", command=stop_execution , fg_color="red")
    stop_button.grid(row=13, column=8, pady=10, padx=10, sticky="ew")
    # stop_button.configure(style="Main.TButton")


    separator = ttk.Separator(frame, orient=tk.VERTICAL)
    separator.grid(row=0, column=7, rowspan=18, sticky="ns", padx=10)
    
    tree_container = tk.Frame(frame, bd=1, relief=tk.SOLID)
    tree_container.place_forget()

    tree_tag = ttk.Treeview(tree_container)

    # Define columns
    tree_tag["columns"] = ("Tag", "Name")

    # Format columns
    tree_tag.column("#0", width=0, stretch=tk.NO)  # Invisible first column
    tree_tag.column("Tag", anchor=tk.W, width=100)
    tree_tag.column("Name", anchor=tk.W, width=150)

    # Create headings
    tree_tag.heading("#0", text="", anchor=tk.W)
    tree_tag.heading("Tag", text="Tag", anchor=tk.W)
    tree_tag.heading("Name", text="Name", anchor=tk.W)

    # Insert data
    data = [("$email", "Email"),
            ("$random", "Random String"),
            ("$number",  "Random No."),
            ("$c_name",  "Username"),
            ("$c_user",  "User Name."),
            ("$invo",  "Random id"),
            ("$date",  "Date"),
            ("$emoji",  "Emoji"),
            ]

    for i, (tag, name) in enumerate(data, start=1):
        tree_tag.insert("", i, values=(tag, name))
    
    # tree_container.grid(row=0, column=5, pady=5, padx=5, sticky=tk.W)
    def on_hover(event):
        x, y, _, _ = tags_label_show.bbox("all")
        tree_container.place(x=860, y=40)
        tree_container.lift()

    def on_leave(event):
        tree_container.place_forget()

    tags_label_show.bind("<Enter>", on_hover)
    tags_label_show.bind("<Leave>", on_leave)
    tree_tag.bind("<Enter>", on_hover)
    tree_tag.bind("<Leave>", on_leave)
    
    def copy_tag_name(event):
        selected_item = tree_tag.selection()
        if selected_item:
            tag_name = tree_tag.item(selected_item)['values'][0]

            # Use tkinter to copy to clipboard
            root.clipboard_clear()
            root.clipboard_append(tag_name)
            root.update()

            print(f"Tag name '{tag_name}' copied to clipboard.")



    # Bind the TreeviewSelect event to the copy_tag_name function
    tree_tag.bind("<<TreeviewSelect>>", copy_tag_name)

    tree_tag.grid(row=2, column=8, columnspan=2, rowspan=4, sticky="nsew")


    clear_button = ctk.CTkButton(frame, text="Clear All Files", command=lambda: delete_files_d(index), fg_color="red")
    clear_button.grid(row=0, column=8, pady=5, sticky=tk.W)
    clear_button = ctk.CTkButton(frame, text="Log Out", command=lambda: sign_out(main_window),  fg_color="red")
    clear_button.grid(row=0, column=9, pady=5, padx=10, sticky=tk.W)


    email_file_label = ttk.Label(frame,  foreground="white", background="#333333", text="Select .txt or .csv file to send as email:").grid(row=1, column=8, pady=5, sticky=tk.W)
    # email_file_label.config(bg='blue')

    # email_file_button = ttk.Button(frame, text="Upload", command=lambda: open_file(frame, email_file_name_label, index))
    # email_file_button.grid(row=2, column=8, sticky=tk.W)
    email_file_button = ctk.CTkButton(frame, command=lambda: open_file(frame, email_file_name_label, index),
                                        text="Upload", fg_color="red")
    email_file_button.grid(row=2, column=8,padx=5, pady=5, sticky="ew")
    # email_file_button.configure(style="Main.TButton")
    email_file_name_label = ttk.Label(frame, foreground="white",  background="#333333", text="")
    email_file_name_label.grid(row=2,  column=9, sticky=tk.W)

    email_text = tk.Text(frame, height=10, width=45, foreground="white", background="#333333")
    email_text.grid(row=3, column=8, columnspan=2,  rowspan=3, sticky=tk.W)

    style = ttk.Style()

    style.configure("Red.TButton", background="red", foreground="red")
    style.configure("Green.TButton", background="green", foreground="green")
    if option == "Google API":
        json_file_label = ttk.Label(frame, foreground="white", background="#333333", text="")
        json_file_label.grid(row=7, column=8, sticky=tk.W)
        upload_button = ctk.CTkButton(frame, text="Upload Google API JSON file", command=lambda: upload_json(frame, json_file_label, index), fg_color="red")
        upload_button.grid(row=6, column=8,padx=10, pady=10,sticky="ew")

        def upload_json(frame, json_file_label, index):


            file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
            if file_path:
                if getattr(sys, 'frozen', False):
                    # Running as a bundled executable
                    current_directory = sys._MEIPASS
                else:
                    # Running as a script
                    current_directory = os.path.dirname(__file__)

                credentials_dir = f"Window{index}"
                
                # Extract the filename from the short path obtained from the file dialog
                file_name = os.path.basename(file_path)
                
                credentials_path = os.path.join(current_directory, credentials_dir, f"credentials_{index}.json")

                # Create the directory if it doesn't exist
                if not os.path.exists(os.path.dirname(credentials_path)):
                    os.makedirs(os.path.dirname(credentials_path), exist_ok=True)

                with open(credentials_path, "wb") as new_file, open(file_path, "rb") as selected_file:
                    new_file.write(selected_file.read())

                json_file_label.config(text=file_name)



    def delete_files_d(index):
        if getattr(sys, 'frozen', False):
            # Running as a bundled executable
            current_directory = sys._MEIPASS
        else:
            # Running as a script
            current_directory = os.path.dirname(__file__)

        tab_directory = f"Window{index}"
        o_directory = os.path.join(current_directory, tab_directory)

        for filename in os.listdir(o_directory):
            file_path = os.path.join(o_directory, filename)
            os.remove(file_path)
            print(f"Deleted file: {filename}")
            # Add logging statements where needed
            logging.debug(f"Attempting to delete file: {file_path}")

        # Delete the entire directory
        try:
            token_file_name = f"token_{index}.json"
            file_path = os.path.join(o_directory, token_file_name)
            
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"Deleted file: {file_path}")

            credentials_file_name = f"credentials_{index}.json"
            file_c_path = os.path.join(o_directory, credentials_file_name)
            
            if os.path.exists(file_c_path):
                os.remove(file_c_path)
                print(f"Deleted file: {file_c_path}")
        except Exception as e:
            print(e)
        try:
            shutil.rmtree(o_directory)
            print(f"Deleted directory: {tab_directory}")
        except Exception as e:
            print(f"Error deleting directory: {str(e)}")

        # listbox.delete(0, tk.END)
        listbox.config(text="")
        if option=="Google API":
            json_file_label.config(text="")
            sender_name_file_name_label.config(text="")
            sender_name_entry.delete(0, tk.END)
            sender_email_entry.delete(0, tk.END)

        clear_all_description_attachments(description_tree, index)
        email_file_name_label.config(text="")
        subject_file_name_label.config(text="")
        
        attachments_name_var.set("Alpha Numeric")
        custom_filename_entry.delete(0, tk.END)
        description_type_var.set("html")
        description_type_input_var.set("Write")
        clear_all_attachments(tree, index)
        description_text.delete(1.0, tk.END)
        
        subject_name_entry.delete(0, tk.END)
        custom_email_type_var.set("25")
        custom_email_entry.delete(0, tk.END)
        test_mail_entry.delete(0, tk.END)
        email_text.delete(1.0, tk.END)

        if option == "SMTP":
            account_list(frame, index, condition=True)
        messagebox.showinfo("Success", f"Successfully deleted all data from Tab {index}")


    if option == "SMTP":
        ttk.Label(frame, foreground="white",  background="#333333", text="SMTP Account:").grid(row=6, column=8, pady=5, sticky=tk.W)

        generateResultsButton = ctk.CTkButton(frame, command=lambda: create_smtp_form(option, frame, frame, root, index),
                                         text="Add Account" , fg_color="red")
        generateResultsButton.grid(row=6, column=9,
                                        
                                        padx=10, pady=10,
                                        sticky="ew")
        
        account_list(frame, index)

    return frame




import logging

logging.basicConfig(level=logging.DEBUG)

def sign_out(main_window):
    logout_url = f'{BASE_API_URL}logout/'
    with open(json_file_path, 'r') as file:
        json_file_path_data = json.load(file)
        print(json_file_path_data)
        bearer = json_file_path_data.get('access_token')
        headers = {
            'Authorization': f'Bearer {bearer}'
        }
        print(headers)

        try:
            response = requests.post(logout_url, headers=headers)
            # response.raise_for_status()
            user_data = response.json()
            print(user_data)
            global logged_in
            logged_in = False
            delete_files_all()
            main_window.destroy()
        except Exception as e:
            print(e)

def delete_files_all():
    current_directory = os.path.dirname(os.path.realpath(__file__))

    for filename in os.listdir(current_directory):
        if os.path.isdir(os.path.join(current_directory, filename)) and filename.startswith("Window"):
            dir_path = os.path.join(current_directory, filename)
            try:
                shutil.rmtree(dir_path)
                print(f"Deleted directory: {filename}")
            except Exception as e:
                print(f"Error deleting directory {filename}: {str(e)}")


def handle_console_output(listbox, message):
    # listbox.insert(tk.END, message)
    # listbox.yview(tk.END)  # Scroll to the end of the listbox
    listbox.config(text=f"{message}")

def handle_console_output_details(listbox_details, message):
    # listbox.insert(tk.END, message)
    # listbox.yview(tk.END)  # Scroll to the end of the listbox
    listbox_details.insert(tk.END, message)

def account_list(frame, index, condition=False):
    file_mail_password = f"Window{index}/mail_password_{index}.csv"
    json_file_path = os.path.join(parent_directory, file_mail_password)
    if os.path.exists(json_file_path):
        ccsv_file_path = os.path.join(parent_directory, file_mail_password)
        smtp_config_data = read_smtp_config_csv(ccsv_file_path)
        style = ttk.Style()
        style.configure("Treeview", background="#333333", foreground="white")
        treee = ttk.Treeview(frame, columns=("Email"), show="headings",style="Treeview")

        # Format columns
        treee.column("Email", anchor=tk.W, width=100)

        # Create headings
        treee.heading("Email", text="Email", anchor=tk.W)

        # Insert data into the Treeview
        for i, (email) in enumerate(smtp_config_data, start=1):
            treee.insert("", i, values=(email.get("email")))

        # Use grid to place the Treeview widget
        accounts_label = ttk.Label(frame,  background="#333333", foreground="white", text="Your SMTP Accounts :")
        accounts_label.grid(row=6, column=8, pady=5, sticky=tk.W)
        treee.grid(row=7, column=8, columnspan=2, rowspan=5, sticky="nsew") 

        clear_all_attachments_button = ctk.CTkButton(frame, text="Clear All Accounts", command=lambda: clear_all_accounts(treee, index),  fg_color="red")
        clear_all_attachments_button.grid(row=12, column=8,padx=10, pady=10,sticky="ew")

        if condition == True:
            clear_all_accounts(treee, index)

        # Function to clear all attachments from the Treeview
        def clear_all_accounts(treee, index):
            for item in treee.get_children():
                values = treee.item(item, 'values')
                username = values[0]

                # Remove the JSON file containing attachment information
                attachements_file_name = f"Window{index}/mail_password_{index}.csv"
                file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), attachements_file_name)
                try:
                    with open(file_path, 'r', newline='') as file:
                        reader = csv.reader(file)
                        header = next(reader)  # Read the header row
                        data = list(reader)
                except FileNotFoundError:
                    # If the file doesn't exist, there's nothing to delete
                    # print("File not found.")
                    return

                # Find the index of the columns for username and password
                try:
                    username_index = header.index("email")
                except ValueError:
                    # print("Column 'email' or 'password' not found in the CSV file.")
                    return

                # Filter out the entry with the provided username and password
                filtered_data = [row for row in data if row[username_index] != username]

                # Write the updated data back to the CSV file
                with open(file_path, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(header)
                    writer.writerows(filtered_data)
                    


                # Remove the attachment from the Treeview
                treee.delete(item)

                
        # Function to clear a selected attachment from the Treeview
        def clear_selected_account(treee, index):
            selected_item = treee.selection()
            if selected_item:
                values = treee.item(selected_item, 'values')
                username = values[0]

                # Remove the selected attachment from the Treeview
                treee.delete(selected_item)

                # Update JSON file without the selected attachment
                # Remove the JSON file containing attachment information
                attachements_file_name = f"Window{index}/mail_password_{index}.csv"
                file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), attachements_file_name)
                try:
                    with open(file_path, 'r', newline='') as file:
                        reader = csv.reader(file)
                        header = next(reader)  # Read the header row
                        data = list(reader)
                except FileNotFoundError:
                    # If the file doesn't exist, there's nothing to delete
                    # print("File not found.")
                    return

                # Find the index of the columns for username and password
                try:
                    username_index = header.index("email")
                except ValueError:
                    # print("Column 'email' or 'password' not found in the CSV file.")
                    return

                # Filter out the entry with the provided username and password
                filtered_data = [row for row in data if row[username_index] != username]

                # Write the updated data back to the CSV file
                with open(file_path, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(header)
                    writer.writerows(filtered_data)




        # Button to clear a selected attachment
        clear_selected_attachment_button = ctk.CTkButton(frame, text="Clear Selected Accounts", command=lambda: clear_selected_account(treee, index),  fg_color="red")
        clear_selected_attachment_button.grid(row=12, column=9 , padx=10, pady=10,sticky="ew")
        # clear_selected_attachment_button.configure(style="Main.TButton")


    # log_out_button = tk.Button(root, text="Log Out", command=log_out)
    # log_out_button.grid(row=0, column=9,  pady=10)

def get_form_data(sender_name_type, sender_name_entry , sender_email_entry, subject_name_entry, description_type_var, description_type_input_var, description_text, custom_filename_entry, attachments_name_var,custom_email_type_entry, mail_type_var, custom_email_entry, email_text, rotate_sender_name, rotate_subject, rotate_description):
    # Retrieve data from the form and return it as a dictionary
    form_data = {
        'subject' : subject_name_entry.get(),
        'sender_email' : sender_email_entry.get(),
        'sender_name' : sender_name_entry.get(),
        'sender_name_type' : sender_name_type.get(),
        'rotate_sender_name' : rotate_sender_name.get(),
        'rotate_subject' :rotate_subject.get(),
        'rotate_description' :rotate_description.get(),
        'description_type' : description_type_var.get(),
        'description_type_input_var' : description_type_input_var.get(),
        'description': description_text.get("1.0", tk.END),
        'attachments_name': custom_filename_entry.get() if attachments_name_var.get() == "Custom" else attachments_name_var.get(),
        'mail_type' : custom_email_type_entry.get() if mail_type_var.get() == "Send After" else mail_type_var.get(),
        'test_mail' : custom_email_entry.get() if mail_type_var.get() == "Send After" or mail_type_var.get() == "Testing" else  mail_type_var.get(),
        'emails' : email_text.get("1.0", tk.END).strip()
    }

    return form_data

def generate_random_alphanumeric(length=8):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def read_emails(file_path):
    try:
        with open(file_path, 'r') as file:
            emails = file.readlines()
    except FileNotFoundError:
        emails = []
    return emails

def write_emails(file_path, emails):
    with open(file_path, 'w') as file:
        file.writelines(emails)

def add_test_mail(emails, test_mail, interval):
    # Add test_mail after every 'interval' lines in the emails list
    e_length = len(emails)
    for i in range(0, e_length, interval):
        emails.insert(i, f"{test_mail}\n")
        e_length = len(emails)

def read_smtp_config_csv(csv_file_path):
    smtp_config_data = []
    try:
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
    except StopIteration:
        # Handle the case where the CSV file is empty
        print("CSV file is empty")

    return smtp_config_data

def submit_form(form_data, option, index, frame, listbox,listbox_details, main_window):
    subject = form_data['subject']
    sender_name_type = form_data['sender_name_type']
    sender_email = form_data['sender_email']
    description_type = form_data['description_type']
    description = form_data['description']
    description_type_input_var = form_data['description_type_input_var']
    attachmentType = form_data['attachments_name']
    customFilename = form_data['attachments_name']
    test_mail = form_data['test_mail']
    rotate_sender_name = form_data['rotate_sender_name']
    rotate_subject = form_data['rotate_subject']
    rotate_description = form_data['rotate_description']
    # attachmentFileType = form_data['attachments_type']
    # invoice = request.FILES.getlist('invoice_file')
    mail_type = form_data['mail_type']
    print(form_data)

    tab_directory = f"Window{index}"
    parent_directory = os.path.dirname(os.path.realpath(__file__))

    # Check if the directory exists, and create it if not
    directory_path = os.path.join(parent_directory, tab_directory)
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)


    script_dir = os.path.dirname(os.path.realpath(__file__))
    email_text = form_data['emails']
    if len(email_text) >= 1:
        emails = email_text.split("\n")  # Split the text into a list of emails
        mails = [email.strip() for email in emails if email.strip()] 
        email_file_name = f"Window{index}/email_{index}.txt"
        emails_path = os.path.join(script_dir, email_file_name)
        with open(emails_path, 'w') as email_file:
            for email in mails:
                email_file.write(f"{email}\n")

    global email_filename

    # Create absolute paths based on the script directory
    if mail_type == 'Plain Mail':
            
        email_file_name = f"Window{index}/email_{index}.txt"
        emails_path = os.path.join(script_dir, email_file_name)    
        if email_filename is not None:
            if email_filename.endswith('.csv'):
                email_file_name = f"Window{index}/email_{index}.csv"
                emails_path = os.path.join(script_dir, email_file_name)    

    elif mail_type == 'G Mass' :
        emails_path = os.path.join(script_dir, 'gmass.txt')
    elif mail_type == 'Send After' : 
        test_email_name = f"Window{index}/test_email_{index}.txt"
        emails_path = os.path.join(script_dir, test_email_name)

    elif mail_type == 'Testing' : 
        test_email_name = f"Window{index}/test_email_{index}.txt"
        emails_path = os.path.join(script_dir, test_email_name)
        write_emails(emails_path, test_mail)
        
    else:
        if email_filename != None:
            if email_filename.endswith(".txt"):
                test_email_name_file = f"Window{index}/test_email_{index}.csv"
                emails_path = os.path.join(script_dir, test_email_name_file)
                parent_directory = os.path.dirname(os.path.realpath(__file__))
                email_file_name = f"Window{index}/email_{index}.txt"
                file_path = os.path.join(parent_directory, email_file_name)
                emails = read_emails(file_path)
                add_test_mail(emails, test_mail, int(mail_type))
                write_emails(emails_path, emails)
            else:
                test_email_name = f"Window{index}/test_email_{index}.csv"
                emails_path = os.path.join(script_dir, test_email_name)
                parent_directory = os.path.dirname(os.path.realpath(__file__))
                email_file_name = f"Window{index}/email_{index}.csv"
                file_path = os.path.join(parent_directory, email_file_name)
                # emails = read_emails(file_path)
                # add_test_mail(emails, test_mail, int(mail_type))
                # write_emails(emails_path, emails)
                process_csv(file_path, emails_path, int(mail_type), test_mail)

        else:
            if emails_path.endswith(".txt"):
                test_email_name = f"Window{index}/test_email_{index}.csv"
                emails_path = os.path.join(script_dir, test_email_name)
                parent_directory = os.path.dirname(os.path.realpath(__file__))
                email_file_name = f"Window{index}/email_{index}.txt"
                file_path = os.path.join(parent_directory, email_file_name)
                emails = read_emails(file_path)
                add_test_mail(emails, test_mail, int(mail_type))
                write_emails(emails_path, emails)
    
    total_mail = 0

    if os.path.exists(emails_path):

        if email_filename != None:
            # emails_path = os.path.join(script_dir, f"Window_{index}", email_filename)
            if emails_path.endswith(".csv"):
                with open(emails_path, 'r', encoding='iso-8859-1') as emails_file:
                    paramFile = emails_file.read()
                    paramFile = io.StringIO(paramFile)
                    portfolio = csv.reader(paramFile)
                    mails = [i[0] for i in portfolio]
                    total_mail = len(mails) - 1

            else:
                with open(emails_path, 'r') as emails_file:
                    mails = list(map(lambda x: x.strip(), emails_file.readlines()))
                    total_mail = len(mails)

        else:
            if emails_path.endswith(".csv"):
                with open(emails_path, 'r', encoding='iso-8859-1') as emails_file:
                    paramFile = emails_file.read()
                    paramFile = io.StringIO(paramFile)
                    portfolio = csv.reader(paramFile)
                    mails = [i[0] for i in portfolio]

            if emails_path.endswith(".txt"):
                with open(emails_path, 'r') as emails_file:
                        mails = list(map(lambda x: x.strip(), emails_file.readlines()))
                        total_mail = len(mails)
    



        
    count = 0
    parent_directory = os.path.dirname(os.path.realpath(__file__))

    attachments_file_path_name = f"Window{index}/attachments_{index}.json"
    attachments_file_path = os.path.join(parent_directory, attachments_file_path_name)
    if os.path.exists(attachments_file_path):
        attachments_file_json_data = read_json_file(attachments_file_path)
    else:
        attachments_file_json_data = {}

    attachments_file_length = len(attachments_file_json_data)

    if description_type_input_var == "Upload":
        description_file_path_name = f"Window{index}/description_{index}.json"
        description_file_path = os.path.join(parent_directory, description_file_path_name)
        if os.path.exists(description_file_path):
            description_file_json_data = read_json_file(description_file_path)
    else:
        description_file_json_data = {}

    description_file_length = len(description_file_json_data)

    # num_entries = len(smtp_config_data)
    if len(subject) == 0:
        subject_file_name = f"Window{index}/subject_{index}.txt"
        subject_file_path = os.path.join(parent_directory,subject_file_name)
        if os.path.exists(subject_file_path):
            with open(subject_file_path, 'r') as subject_file:
                subject_lines = list(map(lambda x: x.strip(), subject_file.readlines()))
    else:
        subject_lines = None


    sender_name_list = []
    if option == "Google API":
        if sender_name_type == "Write":
            sender_name = form_data['sender_name']
            sender_name_list = None
        elif sender_name_type == "Upload":
            sender_file_name = f"Window{index}/sender_name_{index}.txt"
            sender_name_file_path = os.path.join(parent_directory, sender_file_name)
            if os.path.exists(sender_name_file_path):
                with open(sender_name_file_path, 'r') as sender_file:
                    sender_name_list = list(map(lambda x: x.strip(), sender_file.readlines()))
        else:
            sender_name = fetch_random_name(main_window)
    print(sender_name_list)
    SCOPES = ['https://www.googleapis.com/auth/gmail.send']

    creds = None
    parent_directory = os.path.dirname(os.path.realpath(__file__))

    try:
        if option == "Google API":
            if getattr(sys, 'frozen', False):
                # Running as a bundled executable
                current_directory = sys._MEIPASS
            else:
                # Running as a script
                current_directory = os.path.dirname(__file__)
            credentials_dir = f"Window{index}"
            
            cred_file_name = os.path.join(current_directory, credentials_dir, f"credentials_{index}.json")
            token_file = os.path.join(current_directory, f"Window{index}", f"token_{index}.json")

            # cred_file_name = f"Window{index}/credentials_{index}.json"

            # Check for existing credentials and try refreshing if expired
            if os.path.exists(token_file):
                creds = Credentials.from_authorized_user_file(token_file, SCOPES)
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    cred_file_name, SCOPES)
                port = random.randint(30000, 50000)
                creds = flow.run_local_server(host='localhost', port=port)
                # Save credentials for future use
                with open(token_file, 'w') as token:
                    token.write(creds.to_json())

    except Exception as e:
        messagebox.showerror('Error', f'{e} in Tab {index}')
        return

    try:
        threads = []
        lock = threading.Lock()

        while not stop_flag and mails:
            mail = mails.pop(0)
            if mail != "email":
                with lock:
                    parent_directory = os.path.dirname(os.path.realpath(__file__))
                    if option == "SMTP":
                        file_mail_password = f"Window{index}/mail_password_{index}.csv"
                        json_file_path = os.path.join(parent_directory, file_mail_password)
                        if json_file_path:
                            ccsv_file_path = os.path.join(parent_directory, file_mail_password)
                            smtp_config_data = read_smtp_config_csv(ccsv_file_path)
                        

                    if attachmentType == "Alpha Numeric":
                        filename = str(generate_random_alphanumeric())
                    elif attachmentType == "Numeric":
                        filename = str(randint(100, 9999))
                    elif attachmentType == "Custom":
                        filename = str(customFilename) + str(count)
                    else:
                        filename = str(customFilename) + str(count)

                    if attachments_file_length > 0:
                        attachments_file_index = count % attachments_file_length
                        attachments_file_data = attachments_file_json_data[attachments_file_index]
                    else:
                        attachments_file_data = {}

                    if description_file_length > 0:
                        description_file_index = count % description_file_length
                        description_file_data = description_file_json_data[description_file_index]
                        description_data = description_file_data['file_name']
                        folder = f"Window{index}/"
                        description_data_file_path = os.path.join(parent_directory, folder, description_data)
                        description = open(description_data_file_path, 'r').read()
                        description_type = description_file_data['attachment_type']

                    # print(description)
                    smtp_data = {}
                    if option == "SMTP":
                        if len(smtp_config_data) > 0:
                            smtp_data_index = count % len(smtp_config_data)
                            smtp_data = smtp_config_data[smtp_data_index]
                        else:
                            smtp_data = {}
                            break
                        sender_name = smtp_data.get("name", "")
                    else:
                        if len(sender_name_list) > 0:
                            sender_name_index = count % len(sender_name_list)
                            sender_name = sender_name_list[sender_name_index]
                        if rotate_sender_name == True:
                            sender_name = fetch_random_name(main_window)
                            

                    if subject_lines is not None:
                        subject_index = count % len(subject_lines)
                        subject = subject_lines[subject_index]

                    if rotate_subject == True:
                            subject = fetch_random_subject(main_window)

                    if rotate_description == True:
                        description = fetch_random_description(main_window)

                    count += 1

                email_thread = threading.Thread(target=send_mail, args=(option, "Support", mail, sender_email, "obfmnozoghqvgdcz", sender_name, description_type, description, subject, filename, count, attachments_file_data, smtp_data, creds, index, frame, listbox,listbox_details, main_window, total_mail))
                threads.append(email_thread)
                email_thread.start()
                time.sleep(1)


            

        for thread in threads:
            thread.join()

        if stop_flag == True:
            messagebox.showinfo("Success", f"Successfully stopped sending message from Tab {index}")
        else:
            messagebox.showinfo("Success", f"Successfully all mail sent from Tab {index}")


    except Exception as e:
        print(f"Exception in threading: {e}")
        messagebox.showerror('Error', f'{e} in Tab {index}')
            
    if mail_type == 'Plain Mail' or mail_type == 'Send After':
        if getattr(sys, 'frozen', False):
            # Running as a bundled executable
            current_directory = sys._MEIPASS
        else:
            # Running as a script
            current_directory = os.path.dirname(__file__)
        token_file_path = os.path.join(current_directory, f"Window{index}", f"token_{index}.json")
        if os.path.exists(token_file_path):
            os.remove(token_file_path)
        credentials_file_name = f"Window{index}/credentials_{index}.json"
        file_c_path = os.path.join(current_directory, credentials_file_name)
        if os.path.exists(file_c_path):
            os.remove(credentials_file_name)

    #     attachments_file_name = f"attachments_{index}.json"
    #     file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), attachments_file_name)
    #     if os.path.exists(file_path):
    #         attachments_data = read_attachments_json(file_path)
    #         for attachment in attachments_data:
    #             file_name = attachment.get("file_name")
    #             if file_name:
    #                 file_to_delete = os.path.join(os.path.dirname(os.path.realpath(__file__)), f"{file_name}")
    #                 if os.path.exists(file_to_delete):
    #                     os.remove(file_to_delete)
    #                 file_to_delete = os.path.join(os.path.dirname(os.path.realpath(__file__)), f"new_html_{index}_{file_name}")
    #                 if os.path.exists(file_to_delete):
    #                     os.remove(file_to_delete)
    #         os.remove(file_path)

    #     description_file_name = f"description_{index}.json"
    #     file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), description_file_name)
    #     if os.path.exists(file_path):
    #         attachments_data = read_attachments_json(file_path)
    #         for attachment in attachments_data:
    #             file_name = attachment.get("file_name")
    #             if file_name:
    #                 file_to_delete = os.path.join(os.path.dirname(os.path.realpath(__file__)), f"{file_name}")
    #                 if os.path.exists(file_to_delete):
    #                     os.remove(file_to_delete)
    #                 file_to_delete = os.path.join(os.path.dirname(os.path.realpath(__file__)), f"new_html_{index}_{file_name}")
    #                 if os.path.exists(file_to_delete):
    #                     os.remove(file_to_delete)
    #         os.remove(file_path)

    #     subject_file_name = f"subject_{index}.txt"
    #     file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), subject_file_name)
    #     if os.path.exists(file_path):
    #         os.remove(file_path)

    #     sender_name_file_name = f"sender_name_{index}.txt"
    #     file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), sender_name_file_name)
    #     if os.path.exists(file_path):
    #         os.remove(file_path)


def read_attachments_json(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
    except FileNotFoundError:
        data = []
    return data

import ssl

def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller."""
    if getattr(sys, 'frozen', False):
        # Running as compiled (e.g., PyInstaller)
        base_path = os.path.dirname(sys.executable)
    else:
        # Running in a normal Python environment
        base_path = os.path.dirname(os.path.abspath(__file__))

    return os.path.join(base_path, relative_path)


def generate_random_emoji():
    # Define a range of Unicode code points for emojis
    start_code_point = 0x1F600  # Starting code point for emojis
    end_code_point = 0x1F64F   # Ending code point for emojis

    # Generate a random Unicode code point within the specified range
    random_code_point = random.randint(start_code_point, end_code_point)

    # Convert the code point to a Unicode character
    random_emoji = chr(random_code_point)

    return random_emoji




def send_mail(option, name, email, emailId, password, sender_name, description_type, description, subjectWord, file_exe_name, count, attachments_file_data, smtp_data, creds, index, frame, listbox,listbox_details, main_window, total_mails):
    # print(sender_name)
    #=======================================================================================================================
    today = datee.today()
    date_and_time = today.strftime("%d_%B_%Y")
    #=======================================================================================================================
    current_time = datetime.datetime.now()
    date = str(current_time.day) + "-" + str(current_time.month) + "-" + str(current_time.year)
    newMessage = MIMEMultipart()
    #=======================================================================================================================
    # [Invoice Number and Subject]
    #=======================================================================================================================
    invoiceNo = randint(1000000, 9999999)
    transaction_id = randint(10000000000, 99999999999)
    random_string = generate_random_alphanumeric(secrets.randbelow(4) + 10)
    rand_string = ''.join(choices(string.ascii_uppercase, k=5))
    num = randint(111111111, 999999999)
    # subject = subjectWord + rand_string + str(invoiceNo)
    random_id = randint(100000000, 999999999)
    xyz_id = (uuid.uuid4())

    if "@" in email:
        username = email.split("@")[0]
    else:
        username = None

    if "@" in email:
        user_name = email.split("@")[0]
        user_name = re.sub(r'[^a-zA-Z]', '', user_name)
        
        if len(user_name) > 5:
            user_name = user_name[:5] + ' ' + user_name[5:].capitalize()
    else:
        user_name = None

    andom_emoji = generate_random_emoji()
    
    if subjectWord is not None:
        subject = f"{subjectWord}"
        subject = subject.replace('$email', email)
        subject = subject.replace('$number', str(transaction_id))
        subject = subject.replace('$random', str(random_string))
        subject = subject.replace('$c_name', str(username))
        subject = subject.replace('$c_user', str(user_name))
        subject = subject.replace('$invo', str(xyz_id))
        subject = subject.replace('$cus_email', email)
        subject = subject.replace('$date', date)
        subject = subject.replace('$emoji', andom_emoji)

        
    # newMessage['From'] = f"{name}{num}<{emailId}>"
    if option == "Google API":
        newMessage['From'] = f'"{sender_name}" <{emailId}>'
    newMessage['To'] = email

    #=======================================================================================================================
    # Mail PDF File
    if getattr(sys, 'frozen', False):
        # Running as a bundled executable
        parent_directory = sys._MEIPASS
    else:
        # Running as a script
        parent_directory = os.path.dirname(__file__)
    # parent_directory = os.path.dirname(os.path.realpath(__file__))
    
    if len(attachments_file_data) > 0:
        attachmentFileName = attachments_file_data.get("file_name", "")
        # print(attachmentFileName)

        folder = f"Window{index}/"
        new_file_path = os.path.join(parent_directory, folder, attachmentFileName)
        try:
            html = open(new_file_path, 'r').read()


            html = html.replace('$email', email)
            html = html.replace('$random', str(random_string))
            html = html.replace('$number', str(transaction_id))
            html = html.replace('$c_name', str(username))
            html = html.replace('$c_user', str(user_name))
            html = html.replace('$cus_email', email)
            html = html.replace('$invo', str(xyz_id))
            # html = html.replace('$tfn', tfn)
            html = html.replace('$date', date)
            html = html.replace('$emoji', andom_emoji)
        except Exception as e:
            print(e)
    # print(html)
    description = f"""{description}"""
    csv_headers = None
    csv_data = None

    folder = f"Window{index}/"
    csv_file_path_tags = os.path.join(parent_directory, folder, f'email_{index}.csv')

    if os.path.exists(csv_file_path_tags):
        with open(csv_file_path_tags, mode='r') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            headers = csv_reader.fieldnames
            description_data = list(csv_reader)

        # Ensure "email" is present in headers
        if "email" not in headers:
            raise ValueError("CSV file must contain a header named 'email'.")
        print(headers, description_data)
        # Find the index of the "email" header
        email_index = headers.index("email")
        print(email_index)
        # Find the data corresponding to the target email
        if description_data:
            # Find the data corresponding to the target email
            for row in description_data:
                # Check if the row has the expected number of elements
                if email_index < len(row):
                    if row['email'] == email:
                        csv_headers = headers
                        csv_data = row
                        break 

        if csv_headers and csv_data:
            placeholder_mapping = {"$" + header: csv_data[header] for index, header in enumerate(csv_headers)}
            print(placeholder_mapping)
            for placeholder, value in placeholder_mapping.items():
                description = description.replace(placeholder, str(value))
                subject = subject.replace(placeholder, str(value))
                if len(attachments_file_data) > 0:
                    attachmentFileName = attachments_file_data.get("file_name", "")
                    # print(attachmentFileName)

                    folder = f"Window{index}/"
                    new_file_path = os.path.join(parent_directory, folder, attachmentFileName)
                    try:
                        html = open(new_file_path, 'r').read()

                        html = html.replace(placeholder, str(value))
                    except Exception as e:
                        print(e)
        else:
            print("No data found for the target email.")
        
    description = description.replace('$email', email)
    description = description.replace('$number', str(transaction_id))
    description = description.replace('$random', str(random_string))
    description = description.replace('$c_name', str(username))
    description = description.replace('$c_user', str(user_name))
    description = description.replace('$invo', str(xyz_id))
    description = description.replace('$cus_email', email)
    description = description.replace('$date', date)
    description = description.replace('$emoji', andom_emoji)


    if subjectWord is not None:
        newMessage['Subject'] = subject


    #========================================================================================================================
    if description_type == "text":
        newMessage.attach(MIMEText(description, 'plain'))
    elif description_type == "html":
        newMessage.attach(MIMEText(description, 'html'))
    else:
        newMessage.attach(MIMEText(description, 'plain'))
    #=======================================================================================================================
    # saving the changes to html_code.html
    file = None
    if len(attachments_file_data)> 0:
        try:
            try:
                new_file_path = os.path.join(parent_directory, f"Window{index}\\new_html_{index}_{attachmentFileName}")
                
                with open(new_file_path, 'w') as f:
                    f.write(html)
                    f.close
                #=======================================================================================================================

                html_file = os.path.join(parent_directory, f"Window{index}\\new_html_{index}_{attachmentFileName}")
                print(html_file)
            except Exception as e:
                print(e)

            attachmentFileType = attachments_file_data.get("attachment_type", "")
            print(attachmentFileType)

            if attachmentFileType == 'pdf':
                file_name_mail = str(file_exe_name) + ".pdf"
                file =os.path.join(parent_directory, f"Window{index}/" + str(file_exe_name) + ".pdf")
                pdfkit.from_file(html_file, file, configuration=config)

            elif attachmentFileType == 'jpg':
                file_name_mail = str(file_exe_name) + ".jpeg"
                file =os.path.join(parent_directory, f"Window{index}\\" + str(file_exe_name) + ".jpeg")

                a4_width = 650
                a4_height = 970

                # Use subprocess to call the wkhtmltoimage command with A4 size
                subprocess.run([
                    wkhtmltoimage_path,
                    '--width', str(a4_width),
                    '--height', str(a4_height),
                    '--zoom', '0.8',
                    html_file,
                    file
                ], check=True, creationflags=subprocess.CREATE_NO_WINDOW)

            elif attachmentFileType == 'png':
                file_name_mail = str(file_exe_name) + ".png"
                file = os.path.join(parent_directory,f"Window{index}\\" + str(file_exe_name) + ".png")
                a4_width = 650
                a4_height = 970

                # Use subprocess to call the wkhtmltoimage command with A4 size
                subprocess.run([
                    wkhtmltoimage_path,
                    '--width', str(a4_width),
                    '--height', str(a4_height),
                    '--zoom', '0.8',
                    html_file,
                    file
                ], check=True, creationflags=subprocess.CREATE_NO_WINDOW)

            elif attachmentFileType == 'jpgtopdf':
                file_name_mail = str(file_exe_name) + ".pdf"
                filejpg = os.path.join(parent_directory,f"Window{index}\\" + str(file_exe_name) + ".jpeg")
                file = os.path.join(parent_directory,f"Window{index}\\" + str(file_exe_name) + ".pdf")

                a4_width = 650
                a4_height = 970

                # Use subprocess to call the wkhtmltoimage command with A4 size
                subprocess.run([
                    wkhtmltoimage_path,
                    '--width', str(a4_width),
                    '--height', str(a4_height),
                    '--zoom', '0.8',
                    html_file,
                    filejpg
                ], check=True , creationflags=subprocess.CREATE_NO_WINDOW)
                
                images=[filejpg,]
                img = Image.open(filejpg)
                img_width, img_height = img.size
                pdf = canvas.Canvas(file, pagesize=(img_width, img_height))

                pdf.setPageSize((img_width, img_height))
                pdf.drawInlineImage(filejpg, 0, 0, width=img_width, height=img_height)



                # Save the PDF
                pdf.save()
                img.close()
                os.remove(filejpg)

            else:
                folder = f"Window{index}"
                attachmentFileName = attachments_file_data.get("file_name", "")
                new_file_path = os.path.join(parent_directory, folder, f'{attachmentFileName}')
                file_extension = os.path.splitext(attachmentFileName)[1]

                file_name_mail = str(file_exe_name) + f"{file_extension}"
                
                file_name = os.path.join(folder, file_name_mail)


                # Construct the destination file path
                file = os.path.join(parent_directory,  file_name)

                # Copy the data from the original file to the new file
                shutil.copy2(new_file_path, file)

            os.remove(new_file_path)
        except Exception as e:
            print(e)
        #=======================================================================================================================
        
        #=======================================================================================================================
    try:
        if file is not None:
            with open(file, 'rb') as f:
                payload = MIMEBase('application', 'octet-stream', Name=file_name_mail)
                # payload = MIMEBase('application', 'pdf', Name=pdfname)
                payload.set_payload(f.read())
                #=======================================================================================================================
                # enconding the binary into base64
                encoders.encode_base64(payload)
                #=======================================================================================================================
                # add header with pdf name
                payload.add_header('Content-Decomposition',
                                'attachment', filename=file_name_mail)
                newMessage.attach(payload)
        #=======================================================================================================================
        # print(newMessage)
        # mailserver.quit()
        if option == "Google API":
            encoded_message = base64.urlsafe_b64encode(newMessage.as_bytes()).decode()

            create_message = {
                'raw': encoded_message
            }
            service = build('gmail', 'v1', credentials=creds)
            send_message = (service.users().messages().send
                            (userId="me", body=create_message).execute())
            
            print(F'Message Id: {email} , No : {count}')
            # message = f'Message Id: {email} , No : {count}'
            message = f"{count}/{total_mails}"
            handle_console_output(listbox, message)
            message_details = f'Successfully send mail to this Id: {email} , No : {count}'
            handle_console_output_details(listbox_details, message_details)
       
        elif option == "SMTP":
            try:
                smtp_server = smtp_data.get("smtp", "")
                smtp_enable_auth = smtp_data.get("authentication", False)
                smtp_enable_ssl = smtp_data.get("ssl", False)
                smtp_username = smtp_data.get("email", "")
                smtp_password = smtp_data.get("password", "")
                smtp_port = smtp_data.get("port", "")
                print(smtp_server, smtp_enable_auth, smtp_enable_ssl, smtp_username, smtp_password)

                newMessage['From'] = f'"{sender_name}" <{smtp_username}>'
                
                
                if smtp_enable_ssl:
                    if int(smtp_port) == 587:
                        mailserver = smtplib.SMTP(smtp_server, int(smtp_port))
                    else:
                        mailserver = smtplib.SMTP_SSL(smtp_server, int(smtp_port))
                else:
                    mailserver = smtplib.SMTP(smtp_server, int(smtp_port))
                if int(smtp_port) == 587:
                    mailserver.starttls()
                # if smtp_enable_auth:
                mailserver.login(smtp_username, smtp_password)

                mailserver.sendmail(smtp_username, email, newMessage.as_string())

                # Quit the SMTP session
                mailserver.quit()
                print(F'Message Id: {email} , No : {count}')
                message_details = f'Successfully send mail to this Id: {email} , No : {count}'
                handle_console_output_details(listbox_details, message_details)
                message = f"{count}/{total_mails}"
                handle_console_output(listbox, message)

            except smtplib.SMTPResponseException as e:
                print(e)
                error_code = e.smtp_code
                error_message = e.smtp_error
                print(f"send to {email} by {emailId} failed")
                print(f"error code: {error_code}")
                print(f"error message: {error_message}")
                delete_smtp_data_csv(smtp_username, smtp_password, index, frame, listbox_details)
                message = f"error message: {error_message}"
                handle_console_output_details(listbox_details, message)
            except Exception as e:
                print(e)
                # delete_smtp_data_csv(smtp_username, smtp_password, index)
                print("\n")
        
        save_data_url = f'{BASE_API_URL}save_data/'
        with open(json_file_path, 'r') as file:
            json_file_path_data = json.load(file)

        # verify_refresh_token(json_file_path_data.get('refresh_token'), main_window)
        bearer = json_file_path_data.get('access_token')
        headers = {
        'Authorization': f'Bearer {bearer}'
        }


        if option == "SMTP":
            from_email = smtp_username
        else:
            from_email = emailId

        # Include the refresh token in the request data
        data = {
            'from_email': from_email,
            'to_mail': email,
            'country_name' : shared_data['country_name']
        }

        try:
            response = requests.post(save_data_url, json=data, headers = headers)
            response.raise_for_status()
            # print(response)
            # Return the response JSON, which may include updated tokens or user information
            return response.json()
        except requests.RequestException as e:
            print(f"Error verifying refresh token: {e}")
            return
                
        #=======================================================================================================================
        os.remove(file)
    
        
    except HttpError as error:
        # print(F'An error occurred: {error}')
        send_message = None

def verify_refresh_token(refresh_token, main_window):
    # Endpoint for verifying the refresh token
    verify_url = f'{BASE_API_URL}verify-refresh-token/'

    # Include the refresh token in the request data
    public_ip =  get_public_ip()
    data = {'refresh_token': refresh_token, 'user_ip' : public_ip}

    try:
        response = requests.post(verify_url, json=data)
        response.raise_for_status()
        # print(response)
        # Return the response JSON, which may include updated tokens or user information
        return response.json()
    except requests.RequestException as e:
        print(e)
        sign_out(main_window)
        # print(f"Error verifying refresh token: {e}")
        # return None

def read_json_file(file_path):
    # print(file_path)
    # print("\n")
    with open(file_path, 'r') as file:
        data = json.load(file)
        # print(data)
    return data


def delete_smtp_data_csv(username, password, index, frame, listbox_details):
    file_name = f"Window{index}/mail_password_{index}.csv"
    file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), file_name)

    # Read the existing data from the CSV file
    try:
        with open(file_path, 'r', newline='') as file:
            reader = csv.reader(file)
            header = next(reader)  # Read the header row
            data = list(reader)
    except FileNotFoundError:
        # If the file doesn't exist, there's nothing to delete
        # print("File not found.")
        return

    # Find the index of the columns for username and password
    try:
        username_index = header.index("email")
        password_index = header.index("password")
    except ValueError:
        # print("Column 'email' or 'password' not found in the CSV file.")
        return

    # Filter out the entry with the provided username and password
    filtered_data = [row for row in data if row[username_index] != username or row[password_index] != password]

    # Write the updated data back to the CSV file
    with open(file_path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(header)
        writer.writerows(filtered_data)
        account_list(frame, index)

    print("Entry removed successfully.")
    message = f"{username} removed successfully."
    handle_console_output_details(listbox_details, message)



def paypal_form(root, option, index, main_window):
    print(option)
    # Create a frame
    style = ttk.Style()
    style.configure("Main.TFrame", background="#333333")  # Replace "#333333" with your desired color
    root.configure(style="Main.TFrame")
    style.map("Main.TFrame", background=[("selected", "#333333")])
    # main_window.configure(style="Main.TFrame")

    frame = ttk.Frame(root)
    frame.grid(row=0, column=0, padx=20, sticky="nsew")
    style = ttk.Style()
    style.configure("Main.TFrame", background="#333333")  # Replace "#333333" with your desired color
    frame.configure(style="Main.TFrame")
    verify_url = f'{BASE_API_URL}home/'

    canvas = tk.Canvas(frame, bg='black', height=50)
    canvas.grid(row=0, columnspan=6, column=0, sticky="nsew")  # Use grid to span the full window

    # Configure row and column weights to make the canvas expand with the window
    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)
    canvas.config(bg="#333333")

    with open(json_file_path, 'r') as file:
        json_file_path_data = json.load(file)
        print(json_file_path_data)
        bearer = json_file_path_data.get('access_token')
        headers = {
            'Authorization': f'Bearer {bearer}'
        }
        print(headers)

        try:
            response = requests.get(verify_url, headers=headers)
            # response.raise_for_status()
            user_data = response.json()
            print(user_data)
            full_name = user_data.get('full_name', '')
            # Update labels with user information
            full_name_label = ttk.Label(frame,text=f"{full_name} ({get_public_ip()})", foreground="white", background="#333333", font=("Helvetica", 12, "bold")).grid(row=0, column=0, pady=5, padx=5, sticky=tk.W)
            
        except Exception as e:
            sign_out(main_window)
            print(e)

    logo_image_path = os.path.join(base_path, "images", "logo.png")

    logo_image = Image.open(logo_image_path)
    logo_image = logo_image.resize((100, 100))
    logo_image = ImageTk.PhotoImage(logo_image)

    logo_label = ttk.Label(frame, image=logo_image)
    logo_label.image = logo_image 
    logo_label.grid(row=0, column=1)

    clear_button = ctk.CTkButton(frame, text="Log Out", command=lambda: sign_out(main_window),  fg_color="red")
    clear_button.grid(row=0, column=3, pady=5, padx=10, sticky=tk.W)


    style.configure("Main.TButton", background="blue" ,foreground = "blue")

    client_id_label_title = ttk.Label(frame,foreground="white", background="#333333", text="Paypal Client Id:").grid(row=1, column=0,columnspan=2,  pady=5, sticky=tk.W)
    client_id_text = ttk.Entry(frame, width=60)
    client_id_text.grid(row=2, column=0, columnspan=2,  pady=5, sticky="ew")

    client_secret_label_title = ttk.Label(frame,foreground="white", background="#333333", text="Paypal Client Secret").grid(row=1, column=1,  columnspan=2, pady=5, sticky=tk.W)
    client_secret_text = ttk.Entry(frame, width=60)
    client_secret_text.grid(row=2, column=2, columnspan=2,   pady=5, sticky="ew")
 

    with open(json_file_path, 'r') as file:
        json_file_path_data = json.load(file)
        print(json_file_path_data)
        bearer = json_file_path_data.get('access_token')
        headers = {
            'Authorization': f'Bearer {bearer}'
        }
        print(headers)

        try:
            response = requests.get(verify_url, headers=headers)
            # response.raise_for_status()
            user_data = response.json()
            print(user_data)
            full_name = user_data.get('full_name', '')
            # Update labels with user information
            full_name_label = ttk.Label(frame,text=f"{full_name}",  background="#333333" , foreground="white", font=("Helvetica", 12, "bold")).grid(row=0, column=0, pady=5, padx=5, sticky=tk.W)
            
        except Exception as e:
            sign_out(main_window)
            print(e)

    email_file_label = ttk.Label(frame,foreground="white", background="#333333",text="Select .txt or .csv file to send as email:").grid(row=3, column=0, pady=5, sticky=tk.W)
    email_file_button = ctk.CTkButton(frame, text="Upload", command=lambda: open_file(frame, email_file_name_label, index))
    email_file_button.grid(row=3, columnspan=2, column=3, pady=5, sticky="ew")
    email_file_name_label = ttk.Label(frame,foreground="white", background="#333333", text="")
    email_file_name_label.grid(row=3, column=1,  pady=5, sticky="ew")

    email_text = tk.Text(frame, height=5, width=120)
    email_text.grid(row=5, column=0, columnspan=4,  rowspan=2, pady=5, sticky=tk.W)

    subject_label_title = ttk.Label(frame,foreground="white", background="#333333", text="Subject:").grid(row=7, column=0,columnspan=2,  pady=5, sticky=tk.W)
    subject_text = ttk.Entry(frame, width=60)
    subject_text.grid(row=8, column=0, columnspan=2,  pady=5, sticky="ew")

    your_email_label_title = ttk.Label(frame,foreground="white", background="#333333",text="Your Paypal Account Email:").grid(row=7, column=2, columnspan=2,  pady=5, sticky=tk.W)
    your_email_text = ttk.Entry(frame, width=60)
    your_email_text.grid(row=8, column=2, columnspan=2,  pady=5, padx=5, sticky="ew")

    description_label = ttk.Label(frame,foreground="white", background="#333333", text="Description:").grid(row=9, column=0, pady=5, sticky=tk.W)

    description_text = tk.Text(frame, height=5, width=120)
    description_text.grid(row=10, column=0, columnspan=4,  rowspan=2, pady=5, sticky="ew")

    def on_paypal_submit_button_click():
        global stop_flag
        stop_flag = False
        form_data = get_paypal_form_data(client_id_text, client_secret_text, email_text, subject_text, your_email_text, description_text)
        threading.Thread(target=send_invoices_batch, args=(form_data, option, index, frame, main_window, listbox, listbox_details)).start()

    submit_button = ctk.CTkButton(frame, text="Start", command=lambda: on_paypal_submit_button_click())
    submit_button.grid(row=13,  column=0, pady=5, sticky="ew")
    listbox = ttk.Label(frame, foreground="red",  background="#333333", text="")
    listbox.grid(row=13, column=1, pady=5, sticky=tk.W)
    listbox_details = tk.Listbox(frame, height=10, width=120)
    listbox_details.grid(row=14, column=0, rowspan=3, columnspan=4, pady=10, sticky="ew")

    return frame

def get_paypal_form_data(client_id_text, client_secret_text, email_text, subject_text, your_email_text, description_text):
    form_data = {
        'client_id_text' : client_id_text.get(),
        'client_secret_text' : client_secret_text.get(),
        'email_text' : email_text.get("1.0", tk.END),
        'subject_text' : subject_text.get(),
        'your_email_text' : your_email_text.get(),
        'description_text' : description_text.get("1.0", tk.END)
    }

    return form_data

import paypalrestsdk

def send_invoices_batch(form_data, option, index, frame, main_window, listbox, listbox_details):
    print(form_data)

    client_id_text = form_data['client_id_text']
    client_secret_text = form_data['client_secret_text']
    email_text = form_data['email_text']
    subject_text = form_data['subject_text']
    your_email_text = form_data['your_email_text']
    description_text = form_data['description_text']

    paypalrestsdk.configure({
        "mode": "live",  # sandbox or live
        "client_id": str(client_id_text),
        "client_secret": str(client_secret_text)
    })

    invoices = []  # Store Invoice objects for each email
    mails = []  # List to store email addresses

    if email_text != '\n':
        if len(email_text) >= 0:
            emails = email_text.split("\n")  # Split the text into a list of emails
            mails = [email.strip() for email in emails if email.strip()]
            email_file_name = f"Window{index}/email_{index}.txt"
            emails_path = os.path.join(base_path, email_file_name)
            with open(emails_path, 'w') as email_file:
                for email in mails:
                    print(email)
                    email_file.write(f"{email}\n")

    # print(email_file)

    test_email_name = f"Window{index}/email_{index}.txt"
    emails_path = os.path.join(base_path, test_email_name)

    if os.path.exists(emails_path):
        if emails_path.endswith(".txt"):
            with open(emails_path, 'r') as emails_file:
                mails = list(map(lambda x: x.strip(), emails_file.readlines()))
        elif emails_path.endswith(".csv"):
            with open(emails_path, 'r', encoding='iso-8859-1') as emails_file:
                paramFile = emails_file.read()
                paramFile = io.StringIO(paramFile)
                portfolio = csv.reader(paramFile)
                mails = [i[0] for i in portfolio]

    print(mails)
    # Construct and store Invoice objects for each email
    total_mails = len(mails)
    for email in mails:
        invoice = construct_invoice(email, description_text, subject_text, your_email_text)
        print(invoice)
        invoices.append(invoice)
    count = 0
    # Create and send invoices using the paypalrestsdk library
    for invoice in invoices:
        count = count + 1
        try:
            if invoice.create():
                print("INVOICE CREATED:", invoice)
            else:
                print(f"Failed to create invoice {invoice.id}: {invoice.error}")

            paypalrestsdk.configure({
                "mode": "live",  # sandbox or live
                "client_id": str(client_id_text),
                "client_secret": str(client_secret_text)
            })
        except Exception as e:
            print(f"Request Error: {e}")
            message_details = f"Request Error: {e}"
            handle_console_output_details(listbox_details, message_details)

        try:
            data = '{ "send_to_invoicer": true }'
            send_url = f"https://api.paypal.com/v2/invoicing/invoices/{invoice.id}/send"
            headers = {
                "Authorization": f"Bearer {get_access_token(client_id_text, client_secret_text)}",
                "Content-Type": "application/json"
            }
            response = requests.post(send_url, headers=headers, data = data)
            print(response)
            if response.status_code == 202:
                message = f"{count}/{total_mails}"
                handle_console_output(listbox, message)
                print(f"Invoice {invoice.id} sent successfully!")
                message_details = f'Successfully send mail to this Id: {invoice.billing_info['email']} , No : {count}'
                handle_console_output_details(listbox_details, message_details)
            else:
                print(f"Failed to send invoice {invoice.id}: {response.text}")
                message_details =f"Failed to send invoice {invoice.id}: {response.text}"
                handle_console_output_details(listbox_details, message_details)
        except paypalrestsdk.exceptions.PayPalError as e:
            print(f"PayPal Error: {e}")
            message_details = f"PayPal Error: {e}"
            handle_console_output_details(listbox_details, message_details)
        except requests.exceptions.RequestException as e:
            print(f"Request Error: {e}")
            message_details = f"Request Error: {e}"
            handle_console_output_details(listbox_details, message_details)

def construct_invoice(email, note, subject_text, your_email_text):
    # Create an Invoice object using paypalrestsdk
    invoice = paypalrestsdk.Invoice({
        "billing_info": [{
            "email": email,  # Use the provided email
        }],
        "note": note,
        "subject": subject_text,
        "merchant_info": {
            "email": your_email_text,  # Replace with your PayPal business account email
        },
    })

    return invoice

def get_access_token(client_id, secret_key):
    auth_url = "https://api.paypal.com/v1/oauth2/token"
    headers = {
        "Accept": "application/json",
        "Accept-Language": "en_US"
    }
    data = {
        "grant_type": "client_credentials"
    }
    auth = (client_id, secret_key)
    
    response = requests.post(auth_url, headers=headers, data=data, auth=auth)

    try:
        response.raise_for_status()  # Raise an HTTPError for bad responses
        access_token = response.json().get("access_token")
        return access_token
    except requests.exceptions.HTTPError as errh:
        raise Exception(f"HTTP Error: {errh}") from None
    except requests.exceptions.RequestException as err:
        raise Exception(f"Failed to obtain access token: {err}") from None
