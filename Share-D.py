from tkinter import *
from tkinter import messagebox, filedialog
from subprocess import PIPE, Popen
import http.server, os, sys, re, subprocess, threading, psutil, socket, time, traceback
#importing modules

# Run ipconfig and capture its output
ipconfig_output = subprocess.check_output(["ipconfig"]).decode("utf-8")
# Use regular expressions to find IPv4 addresses and default gateway
ipv4_pattern = r"IPv4 Address[^\d]+(\d+\.\d+\.\d+\.\d+)"
default_gateway_pattern1 = r"Default Gateway[^\d]+(\d+\.\d+\.\d+\.\d+)"
default_gateway_pattern = r"  +(\d+\.\d+\.\d+\.\d+)"

ipv4_addresses = re.findall(ipv4_pattern, ipconfig_output)
default_gateway_match = re.search(default_gateway_pattern, ipconfig_output)
if default_gateway_match==None:
    default_gateway_match1 = re.search(default_gateway_pattern1, ipconfig_output)
    default_gateway_match = default_gateway_match1
# or default_gateway_match1
if default_gateway_match :
    default_gateway = default_gateway_match.group(1)
    # Check if the default gateway is a valid IPv4 address
    if re.match(r"\d+\.\d+\.\d+\.\d+", default_gateway):
        default_gateway_octets = default_gateway.split(".")[0:3]

        for ipv4_address in ipv4_addresses:
            ipv4_octets = ipv4_address.split(".")[0:3]
            if ipv4_octets == default_gateway_octets:
                ipv4=ipv4_address
else:
    time.sleep(2)
    messagebox.showwarning("Warning", ":( You are not connected to any network!\nPlease check your IP")

def about():
        #About
        messagebox.showinfo("About", "Share-D means share directory (Using HTTP).\nThis software is coded by Vyankatesh Pipalwa.")


def how():
        #How to
        messagebox.showinfo("How to use","1) Browse directory to share\n\n2) Add IP address in the field if it is empty\n\n3) Add port number if you want change default one\n\n4) Start the server\n\n5) Visit http://IP:PORT")


def compati():
        #Compatibility
        messagebox.showinfo("Compatibility","This software is compatible with all versions of windows operating systems.")


def github():
        #My github
        os.system("start \"\" https://github.com/F745H")


def website():
        #My website
        os.system("start \"\" https://f745h.github.io/")


def kill_process_using_port(port):
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        try:
            pinfo = proc.info
            if 'pid' in pinfo and 'name' in pinfo:
                pid = pinfo['pid']
                process_name = pinfo['name'].lower()
                connections = psutil.Process(pid).connections()
                
                for conn in connections:
                    if conn.status == psutil.CONN_LISTEN and conn.laddr.port == port:
                        # Kill the process
                        try:
                            os.system(f"taskkill /F /PID {pid}")
                        except Exception as e:
                            messagebox.showwarning("Warning", f"Error terminating process with PID {pid}: {str(e)}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass


def start_server(directory, port, address):
    global httpd
    if len(directory)==0:
        messagebox.showwarning("Warning", "Please browse directory first!")
        exit()
    elif len(address)==0:
        messagebox.showwarning("Warning", "Please insert IP address first!")
        exit()
    elif len(port)==0:
        messagebox.showwarning("Warning", "Please insert port number first!")
        exit()
    port=int(port)
    # Check if the port is already in use
    kill_process_using_port(port)
    os.chdir(directory)
    server_address = (address, port)
    httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
    messagebox.showinfo("Done",f"Server started at http://{address}:{port}/ \nVisit the web address to access {directory}")
    httpd.serve_forever()

def stop_server():
    global httpd  # Use the global HTTP server instance
    try:
        if httpd:
            httpd.shutdown()
            httpd.server_close()
            messagebox.showinfo("Done","Server stopped.")
    except:
            messagebox.showwarning("Warning","No active server running.")

# Function to browse for a directory
def browse_directory():
    selected_directory = filedialog.askdirectory()
    directory_entry.delete(0, END)
    directory_entry.insert(0, selected_directory)


# Function to open ipconfig on cmd
def ipconf():
    os.system("start cmd.exe @cmd /k ipconfig")


def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


container = Tk()
#Created container

#Title
container.title("Share-D")
#Width X Height
container.geometry("490x400")
#Background color
container.config(bg="#8B8989")
#Icon
iconPath = resource_path("logoV2.ico")
container.iconbitmap(iconPath)

# Create and configure labels and entry fields
directory_label = Label(container, text="Select directory to share:", bg="snow4")
directory_label.grid(row=0, column=1, padx=20, pady=20)
directory_entry = Entry(container, width=22)
directory_entry.grid(row=2, column=1, padx=20, pady=20)

port_label = Label(container, text="Enter a port number:", bg="snow4")
port_label.grid(row=3, column=1, padx=20, pady=20)
port_entry = Entry(container, width=8)
port_entry.insert(0, "8000")
port_entry.grid(row=4, column=1, padx=20, pady=20)

ip_label = Label(container, text="Enter the IPv4 address:", bg="snow4")
ip_label.grid(row=2, column=2, padx=20, pady=20)
ip_entry = Entry(container)
if "ipv4" in locals():
    ip_entry.insert(0, ipv4)
ip_entry.grid(row=3, column=2, padx=20, pady=20)

# Create and configure buttons
browse_button = Button(container, text="Browse", command=browse_directory)
browse_button.grid(row=1, column=1, padx=20, pady=20)

def start_server_thread():
    threading.Thread(target=lambda: start_server(directory_entry.get(), port_entry.get(), ip_entry.get())).start()

Ipconfig_label = Label(container, text="Press to check your IP:", bg="snow4")
Ipconfig_label.grid(row=0, column=2, padx=20, pady=20)
Ipconfig = Button(container, text="Ipconfig", command=ipconf)
Ipconfig.grid(row=1, column=2, padx=20, pady=20)

note_label = Label(container, text="Note: After server started if you click again on \nstart server button, program will terminate itself", bg="snow4")
note_label.grid(row=5, column=1, padx=10, pady=10)
Stop = Button(container, text="Stop Server", command=stop_server)
Stop.grid(row=5, column=2, padx=20, pady=20)

start_button = Button(container, text="Start Server", command=start_server_thread)
start_button.grid(row=4, column=2, padx=20, pady=20)

#Menu section
menu = Menu(container)
container.config(menu=menu)
filemenu = Menu(menu)
menu.add_cascade(label='File', menu=filemenu)
filemenu.add_command(label='Browse', command=browse_directory)
filemenu.add_command(label='Exit', command=container.quit)
helpmenu = Menu(menu)
menu.add_cascade(label='Help', menu=helpmenu)
helpmenu.add_command(label='Compatibility', command=compati)
helpmenu.add_command(label='How', command=how)
helpmenu.add_command(label='About', command=about)
helpmenu.add_command(label='Visit my Github', command=github)
helpmenu.add_command(label="Visit my Website", command=website)
#Loop
container.mainloop()