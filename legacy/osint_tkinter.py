import tkinter as tk
from tkinter import messagebox, scrolledtext
import webbrowser
import threading
import random


# Try to import the whois function from the whois module.
try:
    from whois import whois as perform_whois_lookup
except ImportError:
    perform_whois_lookup = None


def search_in_domain(domain, target):
    """
    Constructs a Google search query restricted to the given domain,
    then opens it in the default web browser.
    """
    query = f"site:{domain} {target}"
    url = "https://www.google.com/search?q=" + query.replace(" ", "+")
    webbrowser.open(url)


def run_osint():
    target = target_entry.get().strip()
    if not target:
        messagebox.showwarning("Input Error", "Please enter a target name or domain.")
        return

    # Create a new popup window for domain search buttons.
    domains_window = tk.Toplevel(root)
    domains_window.title("OSINT Domain Search")
    domains_window.geometry("500x600")
    domains_window.configure(bg="#1abc9c")  # Primary background

    header = tk.Label(domains_window, text="OSINT Domain Search",
                      font=("Helvetica", 20, "bold"), bg="#27ae60", fg="white")
    header.pack(pady=10, fill='x')

    # Create a canvas with a vertical scrollbar.
    canvas = tk.Canvas(domains_window, bg="#1abc9c", highlightthickness=0)
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar = tk.Scrollbar(domains_window, orient="vertical", command=canvas.yview)
    scrollbar.pack(side="right", fill="y")
    canvas.configure(yscrollcommand=scrollbar.set)

    # Frame to hold the domain buttons inside the canvas.
    buttons_frame = tk.Frame(canvas, bg="#1abc9c")
    canvas.create_window((0, 0), window=buttons_frame, anchor="nw")

    def on_configure(event):
        canvas.configure(scrollregion=canvas.bbox("all"))

    buttons_frame.bind("<Configure>", on_configure)

    osint_domains = [
        "twitter.com", "facebook.com", "linkedin.com", "github.com", "instagram.com",
        "reddit.com", "youtube.com", "pinterest.com", "tumblr.com", "snapchat.com",
        "vk.com", "quora.com", "medium.com", "weibo.com", "stackoverflow.com",
        "blogspot.com", "flickr.com", "twitch.tv", "dailymotion.com", "vimeo.com",
        "streamable.com", "soundcloud.com", "amazon.com", "ebay.com", "craigslist.org",
        "skype.com", "telegram.org", "foursquare.com", "tripadvisor.com", "zillow.com",
        "indeed.com", "glassdoor.com", "expedia.com", "booking.com", "yelp.com",
        "wikipedia.org", "imdb.com", "goodreads.com", "last.fm", "mixcloud.com",
        "netflix.com", "hulu.com"
    ]
    for domain in osint_domains:
        btn_text = f"Search '{target}' on {domain}"
        domain_button = tk.Button(buttons_frame, text=btn_text,
                                  command=lambda d=domain: search_in_domain(d, target),
                                  bg="#2ecc71", fg="white", relief="raised", bd=3,
                                  activebackground="#16a085", font=("Helvetica", 11))
        domain_button.pack(pady=5, fill='x')


def dork_search(filetype, target):
    """
    Constructs a Google dork query for a given file type and target,
    then opens it in the default web browser.
    """
    query = f"filetype:{filetype} {target}"
    url = "https://www.google.com/search?q=" + query.replace(" ", "+")
    webbrowser.open(url)


def run_dork_search():
    target = target_entry.get().strip()
    if not target:
        messagebox.showwarning("Input Error", "Please enter a target name or domain.")
        return

    dork_window = tk.Toplevel(root)
    dork_window.title("Google Dork File Search")
    dork_window.geometry("500x600")
    dork_window.configure(bg="#1abc9c")

    header = tk.Label(dork_window, text="Google Dork File Search",
                      font=("Helvetica", 20, "bold"), bg="#27ae60", fg="white")
    header.pack(pady=10, fill='x')

    canvas = tk.Canvas(dork_window, bg="#1abc9c", highlightthickness=0)
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar = tk.Scrollbar(dork_window, orient="vertical", command=canvas.yview)
    scrollbar.pack(side="right", fill="y")
    canvas.configure(yscrollcommand=scrollbar.set)

    dork_frame = tk.Frame(canvas, bg="#1abc9c")
    canvas.create_window((0, 0), window=dork_frame, anchor="nw")

    def on_configure(event):
        canvas.configure(scrollregion=canvas.bbox("all"))

    dork_frame.bind("<Configure>", on_configure)

    file_types = [
        ("PDF", "pdf"), ("PPT", "ppt"), ("PPTX", "pptx"), ("DOC", "doc"),
        ("DOCX", "docx"), ("XLS", "xls"), ("XLSX", "xlsx"), ("TXT", "txt"),
        ("CSV", "csv"), ("HTML", "html"), ("XML", "xml"), ("JSON", "json"),
        ("MP3", "mp3"), ("MP4", "mp4"), ("AVI", "avi"), ("MOV", "mov"),
        ("ZIP", "zip"), ("RAR", "rar"), ("7Z", "7z"), ("ISO", "iso")
    ]

    for label, ext in file_types:
        btn_text = f"Search {label} files for '{target}'"
        button = tk.Button(dork_frame, text=btn_text,
                           command=lambda ft=ext: dork_search(ft, target),
                           bg="#2ecc71", fg="white", relief="raised", bd=3,
                           activebackground="#16a085", font=("Helvetica", 11))
        button.pack(pady=5, fill='x')


def perform_whois():
    target = target_entry.get().strip()
    if not target:
        messagebox.showwarning("Input Error", "Please enter a target name or domain.")
        return
    threading.Thread(target=perform_whois_thread, args=(target,), daemon=True).start()


def perform_whois_thread(target):
    if perform_whois_lookup is None:
        result_str = ("Error: 'python-whois' module not installed.\n"
                      "Please install it using 'pip install python-whois'.")
    else:
        try:
            result = perform_whois_lookup(target)
            result_str = str(result)
        except Exception as e:
            result_str = f"Error performing whois lookup: {e}"
    root.after(0, display_whois_result, result_str)


def display_whois_result(result_str):
    whois_window = tk.Toplevel(root)
    whois_window.title("Whois Lookup Results")
    whois_window.geometry("600x400")
    whois_window.configure(bg="#1abc9c")

    header = tk.Label(whois_window, text="Whois Lookup Results",
                      font=("Helvetica", 18, "bold"), bg="#27ae60", fg="white")
    header.pack(pady=10, fill='x')

    text_area = scrolledtext.ScrolledText(whois_window, wrap=tk.WORD, font=("Helvetica", 10),
                                          bg="white", fg="black")
    text_area.pack(padx=10, pady=10, fill="both", expand=True)
    text_area.insert(tk.END, result_str)
    text_area.config(state="disabled")


def map_lookup():
    target = target_entry.get().strip()
    if not target:
        messagebox.showwarning("Input Error", "Please enter a location for map lookup.")
        return
    query = target.replace(" ", "+")
    url = f"https://www.google.com/maps/search/{query}"
    webbrowser.open(url)


def random_cyber_tip():
    tips = [
        "Always use multi-factor authentication.",
        "Keep your software updated.",
        "Use strong, unique passwords for each account.",
        "Regularly backup your data.",
        "Be cautious of phishing emails.",
        "Use a reputable antivirus solution.",
        "Keep your operating system patched.",
        "Monitor your network for unusual activity.",
        "Secure your Wi-Fi network.",
        "Educate yourself about common cybersecurity threats."
    ]
    tip = random.choice(tips)
    messagebox.showinfo("Random Cybersecurity Tip", tip)
    # Redirect to the Have I Been Pwned website.
    webbrowser.open("https://haveibeenpwned.com/")


def clear_fields():
    target_entry.delete(0, tk.END)


# Main window setup.
root = tk.Tk()
root.title("OSINT - Open Source Intelligence")
root.geometry("600x600")
root.configure(bg="#1abc9c")

header_main = tk.Label(root, text="OSINT - Open Source Intelligence",
                       font=("Helvetica", 24, "bold"), bg="#27ae60", fg="white")
header_main.pack(pady=10, fill='x')

instruction = tk.Label(root, text="Enter target name, domain, or location and choose your options below:",
                       font=("Helvetica", 12), bg="#1abc9c", fg="white")
instruction.pack(pady=5)

target_label = tk.Label(root, text="Target:", font=("Helvetica", 12), bg="#1abc9c", fg="white")
target_label.pack(pady=(20, 5))
target_entry = tk.Entry(root, width=60, font=("Helvetica", 14))
target_entry.pack(pady=5)

# Container for action buttons arranged in a calculator-like grid.
buttons_frame = tk.Frame(root, bg="#1abc9c")
buttons_frame.pack(pady=15)

# Configure grid for 2 rows x 3 columns.
for i in range(3):
    buttons_frame.grid_columnconfigure(i, weight=1)

# Row 0: three buttons.
run_button = tk.Button(buttons_frame, text="Run OSINT", command=run_osint,
                       font=("Helvetica", 12, "bold"), bg="#2ecc71", fg="white",
                       relief="raised", bd=4, activebackground="#27ae60")
run_button.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

whois_button = tk.Button(buttons_frame, text="Whois Lookup", command=perform_whois,
                         font=("Helvetica", 12, "bold"), bg="#2ecc71", fg="white",
                         relief="raised", bd=4, activebackground="#27ae60")
whois_button.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")

dork_button = tk.Button(buttons_frame, text="Google Dork Search", command=run_dork_search,
                        font=("Helvetica", 12, "bold"), bg="#2ecc71", fg="white",
                        relief="raised", bd=4, activebackground="#27ae60")
dork_button.grid(row=0, column=2, padx=5, pady=5, sticky="nsew")

# Row 1: three buttons.
map_button = tk.Button(buttons_frame, text="Map Lookup", command=map_lookup,
                       font=("Helvetica", 12, "bold"), bg="#2ecc71", fg="white",
                       relief="raised", bd=4, activebackground="#27ae60")
map_button.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

clear_button = tk.Button(buttons_frame, text="Clear", command=clear_fields,
                         font=("Helvetica", 12, "bold"), bg="#2ecc71", fg="white",
                         relief="raised", bd=4, activebackground="#27ae60")
clear_button.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")

random_button = tk.Button(buttons_frame, text="Random Cyber Tip (HIBP)", command=random_cyber_tip,
                          font=("Helvetica", 12, "bold"), bg="#2ecc71", fg="white",
                          relief="raised", bd=4, activebackground="#27ae60")
random_button.grid(row=1, column=2, padx=5, pady=5, sticky="nsew")

credits_text = (
    "This project was made as educational purpose \nto demonstrate the working of how OSINT works\n\n"
    "Made by- Sanket Subhralok Mohapatra\n"
)
credits_label = tk.Label(root, text=credits_text, font=("Helvetica", 14),
                         bg="#1abc9c", fg="white", justify="center")
credits_label.pack(side=tk.BOTTOM, pady=10)

root.mainloop()
