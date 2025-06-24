import requests
from bs4 import BeautifulSoup
import re
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog, ttk
from urllib.parse import urljoin, urlparse
import threading
import time
import webbrowser
from requests.exceptions import RequestException
import socket
import ssl
import datetime

# Enhanced payloads for better vulnerability detection
XSS_PAYLOADS = [
    "<script>alert('XSS1')</script>",
    "<img src=x onerror=alert('XSS2')>",
    "<svg/onload=alert('XSS3')>",
    "'\"><script>alert('XSS4')</script>",
    "{javascript:alert('XSS5')}",
    "`\"'><iframe src=javascript:alert('XSS6')>"
]

SQLI_PAYLOADS = [
    "' OR '1'='1'-- ",
    "' OR SLEEP(5)-- ",
    "1; DROP TABLE users--",
    "1' UNION SELECT 1,2,3--",
    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))--",
    "1' OR 1=1; EXEC xp_cmdshell('dir')--"
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "http://malicious-site.com",
    "javascript:alert('redirect')"
]

class VulnerabilityScanner:
    def __init__(self):
        self.app = tk.Tk()
        self.app.title("DarkScorpion - Advanced Web Vulnerability Scanner")
        self.app.geometry("900x700")
        self.app.configure(bg="#121212")
        self.app.resizable(True, True)
        
        # Set application icon
        try:
            self.app.iconbitmap("scorpion_icon.ico")  # Placeholder - in real app you'd have an icon file
        except:
            pass
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#1e1e1e')
        self.style.configure('TLabel', background='#1e1e1e', foreground='#e0e0e0')
        self.style.configure('TButton', background='#2a2a2a', foreground='#e0e0e0', 
                            font=('Segoe UI', 10), borderwidth=1)
        self.style.map('TButton', background=[('active', '#3a3a3a')])
        self.style.configure('TEntry', fieldbackground='#2a2a2a', foreground='#ffffff')
        self.style.configure('TCombobox', fieldbackground='#2a2a2a', foreground='#ffffff')
        self.style.configure('Treeview', background='#2a2a2a', foreground='#e0e0e0', 
                           fieldbackground='#2a2a2a', borderwidth=0)
        self.style.map('Treeview', background=[('selected', '#4a4a4a')])
        self.style.configure('Treeview.Heading', background='#1a1a1a', foreground='#e0e0e0')
        self.style.configure('Vertical.TScrollbar', background='#1a1a1a', troughcolor='#121212')
        
        # Create main layout
        self.create_widgets()
        
    def create_widgets(self):
        # Header frame
        header_frame = ttk.Frame(self.app, padding=10)
        header_frame.pack(fill=tk.X)
        
        # Title
        title_label = tk.Label(header_frame, text="DARKSCORPION", font=("Arial", 24, "bold"), 
                             fg="#ff5555", bg="#1e1e1e")
        title_label.pack(side=tk.LEFT)
        
        subtitle_label = tk.Label(header_frame, text="Advanced Web Vulnerability Scanner", 
                               font=("Arial", 10), fg="#aaaaaa", bg="#1e1e1e")
        subtitle_label.pack(side=tk.LEFT, padx=10, pady=(10, 0))
        
        # Input frame
        input_frame = ttk.Frame(self.app, padding=10)
        input_frame.pack(fill=tk.X)
        
        tk.Label(input_frame, text="Target URL:", font=("Arial", 10, "bold"), 
               bg="#1e1e1e", fg="#e0e0e0").grid(row=0, column=0, sticky='w', pady=5)
        
        self.url_entry = ttk.Entry(input_frame, width=70, font=("Arial", 10))
        self.url_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        self.url_entry.insert(0, "https://")
        
        # Scan options
        options_frame = ttk.Frame(self.app, padding=10)
        options_frame.pack(fill=tk.X)
        
        tk.Label(options_frame, text="Scan Options:", font=("Arial", 10, "bold"), 
               bg="#1e1e1e", fg="#e0e0e0").grid(row=0, column=0, sticky='w', pady=5)
        
        self.xss_var = tk.BooleanVar(value=True)
        self.sqli_var = tk.BooleanVar(value=True)
        self.redirect_var = tk.BooleanVar(value=True)
        self.headers_var = tk.BooleanVar(value=True)
        self.ssl_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="XSS", variable=self.xss_var).grid(row=0, column=1, padx=5, sticky='w')
        ttk.Checkbutton(options_frame, text="SQL Injection", variable=self.sqli_var).grid(row=0, column=2, padx=5, sticky='w')
        ttk.Checkbutton(options_frame, text="Open Redirect", variable=self.redirect_var).grid(row=0, column=3, padx=5, sticky='w')
        ttk.Checkbutton(options_frame, text="Security Headers", variable=self.headers_var).grid(row=0, column=4, padx=5, sticky='w')
        ttk.Checkbutton(options_frame, text="SSL/TLS", variable=self.ssl_var).grid(row=0, column=5, padx=5, sticky='w')
        
        # Button frame
        button_frame = ttk.Frame(self.app, padding=10)
        button_frame.pack(fill=tk.X)
        
        self.scan_btn = ttk.Button(button_frame, text="Start Scan", command=self.start_scan_thread, width=15)
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.save_btn = ttk.Button(button_frame, text="Save Report", command=self.save_report, width=15, state=tk.DISABLED)
        self.save_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(button_frame, text="Clear Results", command=self.clear_results, width=15)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress frame
        progress_frame = ttk.Frame(self.app, padding=10)
        progress_frame.pack(fill=tk.X)
        
        self.status_label = tk.Label(progress_frame, text="Ready", font=("Arial", 9), 
                                   fg="#aaaaaa", bg="#1e1e1e", anchor='w')
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate', length=300)
        self.progress_bar.pack(side=tk.RIGHT, padx=10)
        
        # Results notebook
        notebook_frame = ttk.Frame(self.app)
        notebook_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        self.notebook = ttk.Notebook(notebook_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Report tab
        report_frame = ttk.Frame(self.notebook, padding=5)
        report_frame.pack(fill=tk.BOTH, expand=True)
        self.notebook.add(report_frame, text="Scan Report")
        
        self.report_text = scrolledtext.ScrolledText(report_frame, wrap=tk.WORD, bg="#2a2a2a", 
                                                   fg="#e0e0e0", insertbackground='white',
                                                   font=("Consolas", 10))
        self.report_text.pack(fill=tk.BOTH, expand=True)
        self.report_text.tag_configure("critical", foreground="#ff5555")
        self.report_text.tag_configure("warning", foreground="#ffaa00")
        self.report_text.tag_configure("info", foreground="#55aaff")
        self.report_text.tag_configure("success", foreground="#55ff55")
        
        # Vulnerabilities tab
        vuln_frame = ttk.Frame(self.notebook, padding=5)
        vuln_frame.pack(fill=tk.BOTH, expand=True)
        self.notebook.add(vuln_frame, text="Vulnerabilities")
        
        # Create treeview for vulnerabilities
        self.vuln_tree = ttk.Treeview(vuln_frame, columns=('Severity', 'Type', 'Location'), show='headings')
        self.vuln_tree.heading('Severity', text='Severity', anchor=tk.W)
        self.vuln_tree.heading('Type', text='Type', anchor=tk.W)
        self.vuln_tree.heading('Location', text='Location', anchor=tk.W)
        
        self.vuln_tree.column('Severity', width=80, minwidth=80)
        self.vuln_tree.column('Type', width=150, minwidth=150)
        self.vuln_tree.column('Location', width=500, minwidth=500)
        
        vsb = ttk.Scrollbar(vuln_frame, orient="vertical", command=self.vuln_tree.yview)
        hsb = ttk.Scrollbar(vuln_frame, orient="horizontal", command=self.vuln_tree.xview)
        self.vuln_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.vuln_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        # Configure grid weights
        vuln_frame.columnconfigure(0, weight=1)
        vuln_frame.rowconfigure(0, weight=1)
        
        # Status bar
        self.status_bar = tk.Label(self.app, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W,
                                 bg="#1a1a1a", fg="#aaaaaa", font=("Arial", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Initialize variables
        self.scanning = False
        self.vulnerabilities = []
        
    def start_scan_thread(self):
        if self.scanning:
            return
            
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        if not url.startswith("http"):
            messagebox.showerror("Invalid URL", "URL must start with http:// or https://")
            return
            
        # Clear previous results
        self.clear_results()
        
        # Update UI
        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.save_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Scanning...")
        self.progress_bar['value'] = 0
        self.status_bar.config(text=f"Scanning {url}...")
        
        # Start scan in background thread
        threading.Thread(target=self.run_scan, args=(url,), daemon=True).start()
    
    def run_scan(self, url):
        try:
            report = []
            start_time = time.time()
            
            # Validate URL
            parsed = urlparse(url)
            if not parsed.scheme:
                url = 'http://' + url
                parsed = urlparse(url)
            
            # Add header to report
            report.append(f"Scan Report for: {url}")
            report.append(f"Scan started at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            report.append("-" * 80)
            
            # Check robots.txt
            self.update_status("Checking robots.txt...")
            robots_url = urljoin(url, '/robots.txt')
            try:
                robots_res = requests.get(robots_url, timeout=10, verify=False)
                if robots_res.status_code == 200:
                    report.append("[INFO] Found robots.txt")
            except RequestException:
                pass
            self.progress_bar['value'] = 10
            
            # Main page scan
            self.update_status("Fetching target page...")
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = requests.get(url, headers=headers, timeout=15, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            self.progress_bar['value'] = 20
            
            # SSL/TLS check
            if self.ssl_var.get():
                self.update_status("Checking SSL/TLS configuration...")
                ssl_report = self.check_ssl(parsed.netloc)
                report.extend(ssl_report)
            
            # Cookie security check
            self.update_status("Checking cookies...")
            for cookie in response.cookies:
                issues = []
                if not cookie.secure: 
                    issues.append("Secure flag missing")
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append("HttpOnly flag missing")
                if cookie.domain and cookie.domain.startswith('.'):
                    issues.append("Overly broad domain scope")
                    
                if issues:
                    report.append(f"[!] Cookie security issue: {cookie.name} - {', '.join(issues)}")
                    self.add_vulnerability("Medium", "Cookie Misconfiguration", f"Cookie: {cookie.name}")
            self.progress_bar['value'] = 30
            
            # Form analysis
            self.update_status("Analyzing forms...")
            forms = soup.find_all('form')
            report.append(f"\nFound {len(forms)} form(s) on {url}")
            
            for i, form in enumerate(forms):
                action = form.get('action', '').strip()
                method = form.get('method', 'get').lower()
                inputs = form.find_all(['input', 'textarea', 'select'])
                form_details = {}
                
                for tag in inputs:
                    name = tag.get('name')
                    if name:
                        form_details[name] = tag.get('value', '')
                
                if not action:
                    target_url = url
                else:
                    target_url = urljoin(url, action)
                
                # SQL Injection test
                if self.sqli_var.get():
                    for payload in SQLI_PAYLOADS:
                        test_data = {key: payload for key in form_details}
                        try:
                            if method == 'post':
                                vuln_test = requests.post(target_url, data=test_data, timeout=10, verify=False)
                            else:
                                vuln_test = requests.get(target_url, params=test_data, timeout=10, verify=False)
                            
                            if re.search(r"error|syntax|mysql|oracle|sqlite|exception", vuln_test.text, re.IGNORECASE):
                                report.append(f"[CRITICAL] Potential SQLi in form {i+1} (Payload: {payload[:20]}...)")
                                self.add_vulnerability("Critical", "SQL Injection", f"Form {i+1} at {target_url}")
                                break
                        except RequestException:
                            continue
                
                # XSS test
                if self.xss_var.get():
                    for payload in XSS_PAYLOADS:
                        xss_data = {key: payload for key in form_details}
                        try:
                            if method == 'post':
                                xss_test = requests.post(target_url, data=xss_data, timeout=10, verify=False)
                            else:
                                xss_test = requests.get(target_url, params=xss_data, timeout=10, verify=False)
                            
                            if payload in xss_test.text:
                                report.append(f"[CRITICAL] Potential XSS in form {i+1} (Payload: {payload[:20]}...)")
                                self.add_vulnerability("Critical", "Cross-Site Scripting", f"Form {i+1} at {target_url}")
                                break
                        except RequestException:
                            continue
                
                # Open redirect check
                if self.redirect_var.get():
                    for param in form_details:
                        if 'url' in param.lower() or 'redirect' in param.lower():
                            for payload in OPEN_REDIRECT_PAYLOADS:
                                test_data = {param: payload}
                                try:
                                    if method == 'post':
                                        redirect_test = requests.post(target_url, data=test_data, allow_redirects=False, timeout=10, verify=False)
                                    else:
                                        redirect_test = requests.get(target_url, params=test_data, allow_redirects=False, timeout=10, verify=False)
                                    
                                    if 300 <= redirect_test.status_code < 400:
                                        location = redirect_test.headers.get('Location', '')
                                        if payload in location:
                                            report.append(f"[HIGH] Open redirect in form {i+1} parameter '{param}'")
                                            self.add_vulnerability("High", "Open Redirect", f"Form parameter: {param}")
                                            break
                                except RequestException:
                                    continue
            self.progress_bar['value'] = 70
            
            # Link analysis for open redirects
            if self.redirect_var.get():
                self.update_status("Checking links...")
                links = soup.find_all('a', href=True)
                redirect_links = [link for link in links if 'url=' in link['href'] or 'redirect=' in link['href']]
                
                for link in redirect_links[:10]:  # Limit to first 10 links
                    href = link['href']
                    for payload in OPEN_REDIRECT_PAYLOADS:
                        test_url = href.replace('=XXX', f'={payload}').replace('=x', f'={payload}')
                        try:
                            redirect_test = requests.get(urljoin(url, test_url), allow_redirects=False, timeout=10, verify=False)
                            if 300 <= redirect_test.status_code < 400:
                                location = redirect_test.headers.get('Location', '')
                                if location and payload in location:
                                    report.append(f"[HIGH] Open redirect in link: {href[:50]}...")
                                    self.add_vulnerability("High", "Open Redirect", f"Link: {href[:50]}...")
                                    break
                        except RequestException:
                            continue
            self.progress_bar['value'] = 80
            
            # Security headers check
            if self.headers_var.get():
                self.update_status("Checking security headers...")
                security_headers = [
                    'Content-Security-Policy',
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'Strict-Transport-Security',
                    'Referrer-Policy'
                ]
                missing_headers = [h for h in security_headers if h not in response.headers]
                
                if missing_headers:
                    report.append(f"[MEDIUM] Missing security headers: {', '.join(missing_headers)}")
                    self.add_vulnerability("Medium", "Missing Security Headers", ", ".join(missing_headers))
            self.progress_bar['value'] = 90
            
            # Finalize report
            scan_time = time.time() - start_time
            report.append("\n" + "-" * 80)
            report.append(f"Scan completed in {scan_time:.2f} seconds")
            
            if not self.vulnerabilities:
                report.append("\n[SUCCESS] No critical vulnerabilities found!")
                self.add_vulnerability("Info", "Scan Complete", "No critical vulnerabilities found")
            else:
                report.append(f"\n[WARNING] Found {len(self.vulnerabilities)} potential security issues")
            
            # Display report
            self.display_report("\n".join(report))
            self.progress_bar['value'] = 100
            self.status_bar.config(text=f"Scan completed. Found {len(self.vulnerabilities)} issues")
            
        except Exception as e:
            self.display_report(f"[ERROR] Scan failed: {str(e)}")
            self.status_bar.config(text=f"Scan failed: {str(e)}")
        finally:
            self.scanning = False
            self.scan_btn.config(state=tk.NORMAL)
            self.save_btn.config(state=tk.NORMAL)
            self.status_label.config(text="Scan Complete")
    
    def check_ssl(self, hostname):
        """Check SSL/TLS configuration of the target"""
        report = []
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    expires = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_remaining = (expires - datetime.datetime.now()).days
                    
                    if days_remaining < 30:
                        report.append(f"[HIGH] SSL Certificate expires in {days_remaining} days")
                        self.add_vulnerability("High", "SSL Expiration", f"Expires in {days_remaining} days")
                    else:
                        report.append(f"[INFO] SSL Certificate valid for {days_remaining} days")
                    
                    # Check TLS version
                    tls_version = ssock.version()
                    if tls_version == "TLSv1":
                        report.append("[MEDIUM] Using outdated TLSv1 protocol")
                        self.add_vulnerability("Medium", "Outdated TLS", "TLSv1")
                    elif tls_version == "TLSv1.1":
                        report.append("[LOW] Using outdated TLSv1.1 protocol")
                        self.add_vulnerability("Low", "Outdated TLS", "TLSv1.1")
                    else:
                        report.append(f"[INFO] Using {tls_version} protocol")
                    
        except Exception as e:
            report.append(f"[ERROR] SSL/TLS check failed: {str(e)}")
        
        return report
    
    def add_vulnerability(self, severity, vuln_type, location):
        """Add vulnerability to treeview"""
        self.vulnerabilities.append((severity, vuln_type, location))
        self.vuln_tree.insert('', 'end', values=(severity, vuln_type, location))
        
        # Color coding based on severity
        if severity == "Critical":
            self.vuln_tree.item(self.vuln_tree.get_children()[-1], tags=('critical',))
        elif severity == "High":
            self.vuln_tree.item(self.vuln_tree.get_children()[-1], tags=('high',))
        elif severity == "Medium":
            self.vuln_tree.item(self.vuln_tree.get_children()[-1], tags=('medium',))
        elif severity == "Low":
            self.vuln_tree.item(self.vuln_tree.get_children()[-1], tags=('low',))
        
        # Configure tag colors
        self.vuln_tree.tag_configure('critical', background='#331111', foreground='#ff5555')
        self.vuln_tree.tag_configure('high', background='#332211', foreground='#ffaa00')
        self.vuln_tree.tag_configure('medium', background='#333311', foreground='#ffff55')
        self.vuln_tree.tag_configure('low', background='#113322', foreground='#55ff55')
    
    def display_report(self, report):
        """Display formatted report in text widget"""
        self.report_text.config(state=tk.NORMAL)
        self.report_text.delete(1.0, tk.END)
        
        for line in report.split('\n'):
            if line.startswith("[CRITICAL]"):
                self.report_text.insert(tk.END, line + "\n", "critical")
            elif line.startswith("[HIGH]"):
                self.report_text.insert(tk.END, line + "\n", "warning")
            elif line.startswith("[MEDIUM]") or line.startswith("[LOW]"):
                self.report_text.insert(tk.END, line + "\n", "info")
            elif line.startswith("[SUCCESS]"):
                self.report_text.insert(tk.END, line + "\n", "success")
            elif line.startswith("[INFO]"):
                self.report_text.insert(tk.END, line + "\n", "info")
            else:
                self.report_text.insert(tk.END, line + "\n")
        
        self.report_text.config(state=tk.DISABLED)
    
    def update_status(self, message):
        """Update status in a thread-safe way"""
        self.status_bar.config(text=message)
        self.app.update()
    
    def save_report(self):
        """Save scan report to file"""
        content = self.report_text.get(1.0, tk.END)
        if not content.strip():
            messagebox.showinfo("Empty Report", "No scan results to save")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("HTML Files", "*.html"), ("All Files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(content)
                messagebox.showinfo("Success", "Report saved successfully")
            except Exception as e:
                messagebox.showerror("Save Error", str(e))
    
    def clear_results(self):
        """Clear scan results"""
        self.report_text.config(state=tk.NORMAL)
        self.report_text.delete(1.0, tk.END)
        self.report_text.config(state=tk.DISABLED)
        
        # Clear vulnerabilities tree
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
            
        self.vulnerabilities = []
        self.status_bar.config(text="Ready")
    
    def run(self):
        self.app.mainloop()

if __name__ == "__main__":
    scanner = VulnerabilityScanner()
    scanner.run()