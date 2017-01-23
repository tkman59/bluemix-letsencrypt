import yaml
import os
import time
import threading
import SimpleHTTPServer
import SocketServer
from letsencrypt import main as cli

cwd = os.getcwd()
logs = cwd+"/logs"
conf = cwd+"/conf"
work = cwd+"/work"
host = cwd+"/host"

port = int(os.getenv('PORT', '5000'))

# Before we switch directories, set up our args using the domains.yml settings file.
with open('domains.yml') as data_file:
    settings = yaml.safe_load(data_file)

print(settings)

# Format commands
args = ["certonly", "--non-interactive", "--text", "--debug", "--agree-tos", "--logs-dir", logs, "--work-dir", work, "--config-dir", conf, "--webroot", "-w", host]

# Are we testing - i.e. getting certs from staging?
if 'staging' in settings and settings['staging'] is True:
    args.append("--staging")

args.append("--email")
args.append(settings['email'])

for entry in settings['domains']:
    domain = entry['domain']
    for host in entry['hosts']:
        args.append("-d")
        if host == '.':
            fqdn = domain
        else:
            fqdn = host + '.' + domain
        args.append(fqdn)

print("Args: ", args)

os.chdir('host')

Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
httpd = SocketServer.TCPServer(("", port), Handler)

# Start a thread with the server
server_thread = threading.Thread(target=httpd.serve_forever)

# Exit the server thread when the main thread terminates
server_thread.daemon = True
server_thread.start()
print("Server loop listening on port ", port, ". Running in thread: ", server_thread.name)

print("Starting Let's Encrypt process...")

cli.main(args)

print("Done.")
print("Fetch the certs and logs via cf ssh ...")
print("You can get them with these commands: ")

host = settings['domains'][0]['hosts'][0]
domain = settings['domains'][0]['domain']
path = host + "." + domain

if host == '.':
    path = domain

print("cf ssh letsencrypt -c 'cat ~/app/conf/live/" + path + "/cert.pem' > cert.pem")
print("cf ssh letsencrypt -c 'cat ~/app/conf/live/" + path + "/chain.pem' > chain.pem")
print("cf ssh letsencrypt -c 'cat ~/app/conf/live/" + path + "/fullchain.pem' > fullchain.pem")
print("cf ssh letsencrypt -c 'cat ~/app/conf/live/" + path + "/privkey.pem' > privkey.pem")
print()
print("REMEMBER TO STOP THE SERVER WITH cf stop letsencrypt")

# Sleep for a week
time.sleep(604800)

print("Done.  Killing server...")

# If we kill the server and end, CF should restart us and we'll try to get certificates again
httpd.shutdown()
httpd.server_close()
