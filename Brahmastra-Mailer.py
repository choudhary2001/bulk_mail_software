import tkinter as tk
from tkinter import ttk
from brahmastra import show_main_window 
from ttkthemes import ThemedTk
import threading
from bs4 import BeautifulSoup
from tkinter import ttk, filedialog, messagebox
import os
import json
import csv
import requests
from datetime import datetime, timedelta
from PIL import Image, ImageTk
from tkinter import PhotoImage
import sys 
from shared import shared_data

def get_public_ip():
    try:
        response = requests.get('https://ipinfo.io')
        ip_data = response.json()
        ip_address = ip_data.get('ip', 'Unable to retrieve IP')
        print(ip_data, ip_address)
        return ip_address
    except Exception as e:
        print(f"Error: {e}")
        return None

if getattr(sys, 'frozen', False):
    # If run as a PyInstaller executable, use sys._MEIPASS
    base_path = sys._MEIPASS
else:
    # If run as a script, use the script's directory
    base_path = os.path.dirname(os.path.abspath(__file__))

root = tk.Tk()
root.title(f"Brahmastra-Mailer")
# root.geometry("920x820")
image_path = os.path.join(base_path, "images", "logo.png")
p1 = PhotoImage(file=image_path)
root.iconphoto(False, p1)
# root.resizable(False, False)
root.configure(bg="#333333") 

def create_tab(notebook, tab_title):
    frame = ttk.Frame(notebook)
    change_tab_bg_color(frame) 
    notebook.add(frame, text=tab_title)
    
    # Remove the space between the tab text and the close button
    style = ttk.Style()
    style.layout(f"{notebook.winfo_class()}.TNotebook.Window", [
        ('Notebook.tab', {
            'sticky': 'nswe', 
            'children': [
                ('Notebook.padding', {
                    'side': 'top', 
                    'sticky': 'nswe',
                    'children': [
                        ('Notebook.label', {
                            'side': 'left', 
                            'sticky': ''
                        }),
                        ('Notebook.close', {
                            'side': 'right', 
                            'sticky': ''
                        })
                    ]
                })
            ]
        })
    ])
    return frame

def show_data(tab_frame, data, index):
    form_frame = ttk.LabelFrame(tab_frame, text="Data", padding="20")
    form_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    # Set the background color directly
    # form_frame.configure(bg="#333333")
    style = ttk.Style()
    style.configure("Main.TFrame", background="#333333")  # Replace "#333333" with your desired color
    form_frame.configure(style="Main.TFrame")
    show_main_window(form_frame, tab_frame, root, index)

def add_new_tab(notebook):
    new_tab_title = "Window " + str(notebook.index("end") + 1)
    f = create_tab(notebook, new_tab_title)
    index = notebook.index(f)  
    form_frame = ttk.Frame(f, padding="20")
    form_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    style = ttk.Style()
    style.configure("Main.TFrame", background="#333333")  # Replace "#333333" with your desired color
    form_frame.configure(style="Main.TFrame")
    show_main_window(form_frame, f, root, index+1)
    # handle_protected_action(f, index+1)


BASE_API_URL = "https://brahmastra.site/"

logged_in = False
user_token = None


def country_entry_window( login_window, f):
    country_entry_window = tk.Toplevel(root)
    country_entry_window.title('Country Entry')
    country_entry_window.geometry('300x150')
    country_entry_window.resizable(False, False)
    country_entry_window.grab_set()  # Make the OTP window modal
    country_entry_window.attributes('-topmost', True)
    image_path = os.path.join(base_path, "images", "logo.png")
    p1 = PhotoImage(file=image_path)
    country_entry_window.iconphoto(False, p1)

    ttk.Label(country_entry_window, text='Enter Country:').grid(row=0, column=0, pady=10, padx=10, sticky=tk.W)


    selected_country = tk.StringVar()

    # Create a dropdown to display country names
    country_dropdown = ttk.Combobox(country_entry_window, textvariable=selected_country, state="readonly")
    country_dropdown.grid(row=0, column=1, padx=10, pady=10)

    # country_entry = ttk.Entry(country_entry_window, width=20)
    # country_entry.grid(row=0, column=1, pady=10, padx=10)

    try:
        response = requests.get('https://restcountries.com/v2/all')
        countries_data = response.json()

        # Extract country names from the response
        country_names = [country['name'] for country in countries_data]

        # Update the dropdown with the fetched country names
        country_dropdown['values'] = country_names
    except requests.RequestException as e:
        print('Error fetching countries:', e)

    ttk.Button(country_entry_window, text='Save', command=lambda: save_country(selected_country, login_window, country_entry_window, f)).grid(row=1, column=0, columnspan=2,  pady=10)

    country_entry_window.transient(login_window)

    def on_close():
        # Add your restrictions or validation here
        # For example, you can check if a certain condition is met before closing
        # If the condition is not met, you can show a message or prevent the window from closing
        print("Checking restrictions before closing...")
        # Uncomment the next line to allow closing
        # country_entry_window.destroy()

    # Set the protocol for closing the window
    country_entry_window.protocol("WM_DELETE_WINDOW", on_close)


def save_country(country_entry,  login_window, country_entry_window, f):
    # global country_name
    country = country_entry.get()
    if not country:
        messagebox.showwarning('Country Entry', 'Please enter Country.')
        return
    shared_data['country_name'] = country
    print(country)
    country_entry_window.destroy()


def handle_logout():
    global logged_in
    logged_in = False

def handle_login(username_entry, password_entry, login_window, f):
    global logged_in
    username = username_entry.get()
    password = password_entry.get()
    # token = True
    # token = check_login(username, password, login_window)
    threading.Thread(target=check_login, args=(username, password, login_window, f)).start()

    # if token:
    #     logged_in = True
    #     # form_frame = ttk.Frame(f, padding="20")
    #     # form_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    #     login_window.grid_forget()
        
    #     notebook = ttk.Notebook(f)

    #     # Create tabs
    #     tab1 = create_tab(notebook, "Window 1")

    #     # Data for each tab
    #     data_tab1 = "Data for Window 1"
    #     # Display data on each tab
    #     show_data(tab1, data_tab1, 1)
        
    #     # "+" button to add new tabs
    #     add_tab_button = tk.Button(f, text="+", command=lambda: add_new_tab(notebook))
    #     add_tab_button.grid(row=1, column=0, columnspan=1, pady=5)

    #     # Pack the notebook to the root window
    #     notebook.grid(row=0, column=0, sticky="nsew")
        
    # else:
    #     # messagebox.showerror("Login Failed", "Invalid username or password")
    #     show_login_window(login_window)

def check_login(username, password, login_window, f):
    login_url = f'{BASE_API_URL}accounts/login/'
    data = {'username': username, 'password': password}
    # csrf_token = get_csrf_token(login_url)
    # headers = {'X-CSRFToken': csrf_token}

    data = {'username': username, 'password': password}
    try:
        response = requests.post(login_url, json=data)
        

        if response.status_code == 200:
            otp_entry_window(response.json(), username, login_window, f)
        else:
            messagebox.showerror('Login Failed', 'Invalid username or password')
    except Exception as e:
        # print(e)
        messagebox.showerror('Login Failed', f'Error during login: Please check your username and password.')
        # show_login_window(login_window)

def get_csrf_token(login_url):
    response = requests.get(login_url)
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    csrf_token = soup.find('input', {'name': 'csrfmiddlewaretoken'}).get('value')
    # print(csrf_token)
    return csrf_token

def otp_entry_window(data, username, login_window, f):
    otp_entry_window = tk.Toplevel(root)
    otp_entry_window.title('OTP Entry')
    otp_entry_window.geometry('300x150')
    otp_entry_window.resizable(False, False)
    otp_entry_window.grab_set()  # Make the OTP window modal
    otp_entry_window.attributes('-topmost', True)

    ttk.Label(otp_entry_window, text='Enter OTP:').grid(row=0, column=0, pady=10, padx=10, sticky=tk.W)
    otp_entry = ttk.Entry(otp_entry_window, show='*', width=20)
    otp_entry.grid(row=0, column=1, pady=10, padx=10)

    ttk.Button(otp_entry_window, text='Submit', command=lambda: verify_otp(otp_entry, data, username, login_window, otp_entry_window, f)).grid(row=1, column=0, columnspan=2, pady=10)

def verify_otp(otp_entry, data, username, login_window, otp_entry_window, f):
    otp = otp_entry.get()
    if not otp:
        messagebox.showwarning('OTP Entry', 'Please enter OTP.')
        return

    two_step_url = f'{BASE_API_URL}two_step'
    public_ip = get_public_ip()
    otp_data = {'otp': otp, 'username' :username, 'user_ip' : public_ip, **data}


    response = requests.post(two_step_url, json=otp_data)
    # print(response)
    if response.status_code == 200:
        otp_entry_window.destroy()
        form_frame = ttk.Frame(root, padding="20")
        form_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        country_entry_window(form_frame, f)
        login_window.destroy()
        save_tokens_to_file(response.json())
        logged_in = True
        style = ttk.Style()
        style.configure("Main.TFrame", background="#333333")  # Replace "#333333" with your desired color
        form_frame.configure(style="Main.TFrame")
        # form_frame = ttk.Frame(f, padding="20")
        # form_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        # login_window.grid_forget()
        style = ttk.Style()
        style.configure("Main.TFrame", background="#333333")  # Replace "#333333" with your desired color
        form_frame.configure(style="Main.TFrame")
        notebook = ttk.Notebook(f)
        notebook_style = ttk.Style()
        notebook_style.configure("TNotebook", background="#333333")
        notebook = ttk.Notebook(f, style="TNotebook")
        # Create tabs
        tab1 = create_tab(notebook, "Window 1")

        # Data for each tab
        data_tab1 = "Data for Window 1"
        # Display data on each tab
        show_data(tab1, data_tab1, 1)
        
        # "+" button to add new tabs
        add_tab_button = tk.Button(f, text="+", command=lambda: add_new_tab(notebook))
        add_tab_button.grid(row=1, column=0)

        # Pack the notebook to the root window
        notebook.grid(row=0, column=0, sticky="nsew")
    else:
        messagebox.showerror('Verification Failed', 'Invalid OTP. Please try again.')

def save_tokens_to_file(tokens):
    file_path = os.path.join(base_path, 'brahmastra_mailer_credentials.json')

    try:
        with open(file_path, 'w') as file:
            json.dump(tokens, file)
        # print("Tokens saved successfully.")
    except Exception as e:
        print(f"Error saving tokens: {e}")

def show_login_window(f):
    style = ttk.Style()
    style.configure('My.TEntry', padding=(5, 5, 5, 5), borderwidth=2, relief="solid", width=55)

    # Create a centered frame
    center_frame = ttk.Frame(f, borderwidth=0, relief=tk.FLAT)
    center_frame.grid(row=0, column=0, padx=50, pady=50, sticky="nsew")

    # Add logo
    canvas = tk.Canvas(center_frame, bg='black', height=50)
    canvas.grid(row=0, columnspan=10, column=0, sticky="nsew")  # Use grid to span the full window

    # Configure row and column weights to make the canvas expand with the window
    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)
    canvas.config(bg="#333333")

    logo_image_path = os.path.join(base_path, "images", "logo.png")

    logo_image = Image.open(logo_image_path)
    logo_image = logo_image.resize((200, 200))
    logo_image = ImageTk.PhotoImage(logo_image)

    logo_label = ttk.Label(center_frame, image=logo_image)
    logo_label.image = logo_image  # Keep a reference to the image
    logo_label.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

    # Add login form
    form_frame = ttk.Frame(center_frame, padding="20")
    form_frame.grid(row=1, column=0, columnspan=2)

    ttk.Label(form_frame, text="Username:").grid(row=0, column=0, pady=10, sticky=(tk.W, tk.E))
    username_entry = ttk.Entry(form_frame)
    username_entry.grid(row=0, column=1, pady=10,  sticky=(tk.W, tk.E))

    ttk.Label(form_frame, text="Password:").grid(row=1, column=0, pady=10, sticky=(tk.W, tk.E))
    password_entry = ttk.Entry(form_frame, show="*")
    password_entry.grid(row=1, column=1, pady=10, sticky=(tk.W, tk.E))

    login_button = ttk.Button(form_frame, text="Login", command=lambda: handle_login(username_entry, password_entry, form_frame, f))
    login_button.grid(row=2, column=0, columnspan=2, pady=10, sticky=(tk.W, tk.E))

    center_frame.columnconfigure(0, weight=1)
    center_frame.columnconfigure(1, weight=0)
    center_frame.rowconfigure(1, weight=1)

def on_main_window_close():
    global logged_in
    if logged_in:
        root.destroy()
    else:
        messagebox.showinfo("Access Denied", "Please log in first.")



def get_user_token():
    global user_token
    return user_token




def read_refresh_token_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            # print(data)
            return data.get('refresh_token')
    except FileNotFoundError:
        # print(f"File not found: {file_path}")
        return None

# Replace 'path/to/your/credentials.json' with the actual path to your JSON file
json_file_path = os.path.join(base_path, 'brahmastra_mailer_credentials.json')


def verify_refresh_token(refresh_token):
    # Endpoint for verifying the refresh token
    verify_url = f'{BASE_API_URL}verify-refresh-token/'

    # Include the refresh token in the request data
    public_ip = get_public_ip()
    data = {'refresh_token': refresh_token, 'user_ip' : public_ip}

    try:
        response = requests.post(verify_url, json=data)
        response.raise_for_status()
        # print(response)
        # Return the response JSON, which may include updated tokens or user information
        return response.json()
    except requests.RequestException as e:
        # print(f"Error verifying refresh token: {e}")
        return None



def check_refresh_token_validity(tokens):
    # Check the validity of the refresh token based on its expiration time
    refresh_token_expiration = tokens.get('refresh_token_expiration')

    if refresh_token_expiration:
        expiration_time = datetime.fromisoformat(refresh_token_expiration)
        current_time = datetime.now()

        # Check if the refresh token is still valid (not expired)
        return current_time < expiration_time
    else:
        # Handle the case where the refresh token expiration is not provided
        # print("Refresh token expiration not found.")
        return False

def change_tab_bg_color(tab):
    style = ttk.Style()
    style.configure(f"{tab}.TNotebook.Window", background="#333333")

def handle_protected_action(f):
    json_file_path = os.path.join(base_path, 'brahmastra_mailer_credentials.json')

    refresh_token = read_refresh_token_from_file(json_file_path)

    if refresh_token:
        # Verify the refresh token and check its validity
        verification_result = verify_refresh_token(refresh_token)

        if verification_result:
            form_frame = ttk.Frame(f, padding="20", borderwidth=0, relief=tk.FLAT)

            form_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
            logged_in = True
            country_entry_window(form_frame, f)
            # f.configure(bg='black')
            notebook_style = ttk.Style()
            notebook_style.configure("TNotebook", background="#333333")
            notebook = ttk.Notebook(f, style="TNotebook")

            # Create tabs
            tab1 = create_tab(notebook, "Window 1")

            # Data for each tab
            data_tab1 = "Data for Window 1"
            # Display data on each tab
            show_data(tab1, data_tab1, 1)
            change_tab_bg_color(tab1) 
            # "+" button to add new tabs
            add_tab_button = ttk.Button(f, text="+", command=lambda: add_new_tab(notebook))
            add_tab_button.grid(row=1, column=0)

            # Pack the notebook to the root window
            notebook.grid(row=0, column=0, sticky="nsew")
            
            return

    show_login_window(f)



import shutil
def delete_files():
    current_directory = os.path.dirname(os.path.realpath(__file__))

    for filename in os.listdir(current_directory):
        if os.path.isdir(os.path.join(current_directory, filename)) and filename.startswith("Window"):
            dir_path = os.path.join(current_directory, filename)
            try:
                shutil.rmtree(dir_path)
                print(f"Deleted directory: {filename}")
            except Exception as e:
                print(f"Error deleting directory {filename}: {str(e)}")

def on_close():
    # Call the function to delete files when the window is closed
    delete_files()
    root.destroy()
root.protocol("WM_DELETE_WINDOW", on_close)

def main():

    handle_protected_action(root)


    root.rowconfigure(0, weight=1)
    root.columnconfigure(0, weight=1)
    root.columnconfigure(1, weight=0)

    # error_label = ttk.Label(root, text="", foreground="red")
    # error_label.grid(row=1, column=0, pady=(0, 10))
    # success_label = ttk.Label(root, text="", foreground="green")
    # success_label.grid(row=2, column=0, pady=(0, 10))

    root.update_idletasks()
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width - root.winfo_width()) // 2
    y = (screen_height - root.winfo_height()) // 2
    root.geometry("+{}+{}".format(x, y))

    root.mainloop()

if __name__ == "__main__":
    main()
