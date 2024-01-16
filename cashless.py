import http.server, http, json
import datetime, multiprocessing
import os, socketserver, sys, ssl
from library.pylog import pylog, logman
from library.jmod import jmod

settings_dir = "settings.json"
app_settings = { # Initial settings for the app. Changes later
    "webgui": {
        "localonly": True, # Restricts access to localhost only
        "running": False,
        "port": 8080
    },
    "logman": {
        "enabled": False, # Used to enable/disable logging
        "logform": "%loglevel% - %time% - %file% | "
    }
}
if not os.path.exists(settings_dir): # Creates settings file if it doesn't exist
    with open(settings_dir, "w+") as settings_file:
        json.dump(app_settings, settings_file, indent=4, separators=(',', ': '))

logwriter = {
    'enabled': jmod.getvalue(key="logman.enabled", json_dir="settings.json", default=False, dt=app_settings),
    'logform': jmod.getvalue(key="logman.logform", json_dir="settings.json", default="%loglevel% - %time% - %file% | ", dt=app_settings)
}

# Sets up logging
if logwriter['enabled']:
    pylogger = pylog(
        logform=logwriter['logform'],
        filename='logs/%DATENOW%.log'
    )

if __name__ == "__main__":
    logmanager = multiprocessing.Process(target=logman, args=())
    logmanager.start()

def getvar(key):
    return jmod.getvalue(key=key, json_dir=settings_dir, default=None, dt=app_settings)

class webserver:
    def __init__(self, content_dir="library/webgui/", port:int=8080, do_ssl:bool=False) -> None:
        self.port = port if port is None else getvar("webgui.port")
        self.do_ssl = do_ssl
        self.content_dir = content_dir
        os.makedirs(self.content_dir, exist_ok=True)

    def generate_ssl(self, certfile_dir, keyfile_dir, hostname="localhost"):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509 import NameOID
        from cryptography.hazmat.primitives import serialization
        # Generate a self-signed certificate if it doesn't exist
        os.makedirs(os.path.dirname(certfile_dir), exist_ok=True)
        if not os.path.isfile(certfile_dir) or not os.path.isfile(keyfile_dir):
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            os.makedirs(os.path.dirname(certfile_dir), exist_ok=True)

            name = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"{}".format(hostname)),
            ])

            cert = x509.CertificateBuilder().subject_name(
                name
            ).issuer_name(
                name
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).sign(key, hashes.SHA256())

            # Write our certificate out to disk.
            with open(certfile_dir, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            # Write our key out to disk
            with open(keyfile_dir, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))

    def run(self):
        '''
        Runs the webserver.
        If app_name is tuple/list, then it will use the first item as the config path and the second as the app name
        if app_name is str, it'll use the app_name as the app name and the config path will be instances/{app_name}/config.json

        silent = True will redirect stdout and stderr to /dev/null
        '''
        debug = False
        weblog = pylog(logform="%loglevel% - %time% - %file% | ")

        # Loads settings
        default_index = "index.html"
        csp_directives = ["Content-Security-Policy", "default-src 'self';","script-src 'self';","style-src 'self';","img-src 'self';","font-src 'self'"]
        add_sec_heads = True

        allow_external_ips = jmod.getvalue( # Gets localonly mode. If its not localonly, then its Remote mode
            key="webgui.localonly",
            json_dir=settings_dir,
            default=True,
            dt=app_settings
        ) is False
        content_dir = self.content_dir

        # Define a custom request handler with logging
        class CustomHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                self.content_directory = content_dir
                super().__init__(*args, directory=self.content_directory, **kwargs)

            if add_sec_heads:
                def add_security_headers(self):
                    # Add security headers based on user configuration
                    self.send_header("Content-Security-Policy", csp_directives)
                    self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

            def do_GET(self):
                self.log_request_action()
                if not allow_external_ips:
                    # If the request is not from localhost, return a 403
                    if self.client_address[0] != "127.0.0.1":
                        self.send_error(403, "Forbidden", "External IP addresses are not allowed")
                        return
                else:
                    # If the request is from localhost and thats not allowed, return a 403
                    if self.client_address[0] == "127.0.0.1":
                        self.send_error(403, "Forbidden", "Localhost is not allowed. Use domain to access instead")
                        return

                # Handle directory listing.
                if self.path.endswith("/"):
                    # If the path is a directory and not the root, return a 403
                    if self.path != "/":
                        self.send_error(403, "Directory listing is disabled", "Directory Listing is Forcefully disabled")
                        return

                # Check if the requested path is the root directory
                if self.path == "/":
                    # Serve the default_index as the landing page
                    # Get the absolute path of the default index file
                    default_index_path = os.path.abspath(os.path.join(self.content_directory, default_index))
                    
                    # Check if the default index file exists
                    if os.path.exists(default_index_path):
                        # Open the default index file and read its content
                        with open(default_index_path, 'rb') as index_file:
                            content = index_file.read()
                            
                            # Send a HTTP 200 OK response
                            self.send_response(200)
                            
                            # Set the Content-Type header to text/html
                            self.send_header("Content-type", "text/html")
                            self.end_headers()
                            
                            # Write the content to the response body
                            self.wfile.write(content)
                    else:
                        # If the default index file doesn't exist
                        self.send_error(404, "File not found", "The default index file was not found")
                else:
                    self.send_error(403, "Forbidden", "This website has only 1 page")

            def log_request_action(self):
                # Get client address and requested file
                client_address = self.client_address[0]
                requested_file = self.path
                # Open the log file and write the request information
                if requested_file == "/":
                    if client_address != "127.0.0.1" and allow_external_ips is False:
                        weblog.info(f"IP {client_address} requested {requested_file} (the landing page) but was denied due to it not being localhost and being local only mode")
                    elif client_address == "127.0.0.1" and allow_external_ips is True:
                        weblog.info(f"IP {client_address} requested {requested_file} (the landing page) but was denied due to being localhost on remote only mode")
                    else:
                        weblog.info(f"IP {client_address} requested {requested_file} (the landing page)")
                else:
                    if client_address != "127.0.0.1" and allow_external_ips is False:
                        weblog.info(f"IP {client_address} requested {requested_file} but was denied due to it not being localhost and being local only mode")
                    elif client_address == "127.0.0.1" and allow_external_ips is True:
                        weblog.info(f"IP {client_address} requested {requested_file} but was denied due to being localhost on remote only mode")
                    else:
                        weblog.info(f"IP {client_address} requested {requested_file}")

        # Redirect stdout and stderr to /dev/null if silent is True
        if not debug:
            sys.stdout = open(os.devnull, "w")
            sys.stderr = open(os.devnull, "w")

        try:
            # Create a socket server with the custom handler
            with socketserver.TCPServer(("", self.port), CustomHandler) as httpd:

                # Sets server to running in JSON file
                jmod.setvalue(
                    key="webgui.running",
                    json_dir=settings_dir,
                    value=True,
                    dt=settings_dir
                )

                if allow_external_ips is True:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    cert_dir = os.path.abspath('ssl/webgui-api.pem')
                    private_dir = os.path.abspath('ssl/webgui-api.key')

                    self.generate_ssl(cert_dir, private_dir)

                    context.load_cert_chain(cert_dir, private_dir)
                    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
                    weblog.info(f"WebGUI is running with SSL on Remote mode.")
                else:
                    weblog.info(f"WebGUI is running without SSL on Closed mode.")

                # Start the server and keep it running until interrupted
                weblog.info(f"WebGUI is now running on port {self.port}")
                try:
                    httpd.serve_forever()
                except KeyboardInterrupt:
                    weblog.info("WebGUI has been stopped.")
                    return True
                # Once it reaches here, it stops.
                weblog.info("WebGUI has been stopped.")
                return True
        except OSError as err:
            weblog.error(f"WebGUI failed to start!", err)
            print(f"WebGUI failed to start: {err}\nIs there already something running on port {self.port}?")
            
if __name__ == "__main__":
    server = webserver(
        port=8080,
        do_ssl=False
    )

    webgui_proc = multiprocessing.Process(
        target=server.run, args=()
    )
    webgui_proc.start()
    print(f"http{'s' if getvar('webgui.localonly') is False else ''}://localhost:{getvar('webgui.port')}")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        webgui_proc.terminate()
        webgui_proc.join()
        logmanager.terminate()
        logmanager.join()
        print("WebGUI has been stopped.")