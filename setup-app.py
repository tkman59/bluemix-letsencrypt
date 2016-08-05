import yaml
from subprocess import call, Popen, PIPE
import time


def get_cert(appname, domain, certname):
    """get_cert wraps the `cf files` command to retrive only the literal file
    contents of the certificate that was requested, without the status code at
    the beginning. It then writes the certificate to a file in the current
    working directory with the same name that the certificate had on the
    server.
    """
    command = "cf files %s app/conf/live/%s/%s" % (appname, domain, certname)
    print("Running: %s" % command)
    pipe = Popen(command, shell=True, stdout=PIPE)
    output = pipe.stdout.readlines()
    cert = ''.join(output[3:])
    with open(certname, 'w') as outfile:
        print("Writing cert to %s" % certname)
        outfile.write(cert)

with open('domains.yml') as data_file:
    settings = yaml.safe_load(data_file)

with open('manifest.yml') as manifest_file:
    manifest = yaml.safe_load(manifest_file)

print(settings)
appname = manifest['applications'][0]['name']

# Push the app, but don't start it yet
call(["cf", "push", "--no-start"])

# For each domain, map a route for the specific letsencrypt check path
# '/.well-known/acme-challenge/'
for entry in settings['domains']:
    domain = entry['domain']
    for host in entry['hosts']:
        if host == '.':
            call(["cf", "map-route", appname, domain, "--path", "/.well-known/acme-challenge/"])
        else:
            call(["cf", "map-route", appname, domain, "--hostname", host, "--path", "/.well-known/acme-challenge/"])

# Now the app can be started
call(["cf", "start", appname])

# Tail the application log
print("Parsing log files.")
end_token = "cf stop letsencrypt"  # Seeing this in the log means certs done
log_pipe = Popen("cf logs %s --recent" % appname, shell=True,
                 stdout=PIPE, stderr=PIPE)
log_lines = log_pipe.stdout.readlines()
print("Waiting for certs (could take several minutes)")
while end_token not in ''.join(log_lines):
    # Keep checking the logs for cert readiness
    print("Certs not ready yet, retrying in 5 seconds.")
    print("Digest: %s" % ''.join(log_lines))
    time.sleep(5)
    log_pipe = Popen("cf logs %s --recent" % appname, shell=True,
                     stdout=PIPE, stderr=PIPE)
    log_lines = log_pipe.stdout.readlines()
# Now that certs should be ready, parse for the commands to fetch them
command_lines = []
for line in log_lines:
    if "cf files" in line:
        print(line)
        command_lines.append(line)

# Hack to wait for app to finish. Replace with parsing cf log
domain_with_first_host = "%s.%s" % (settings['domains'][0]['hosts'][0], domain)
print(domain_with_first_host)

# Pull all of the certs as local files
get_cert(appname, domain_with_first_host, 'cert.pem')
get_cert(appname, domain_with_first_host, 'chain.pem')
get_cert(appname, domain_with_first_host, 'privkey.pem')
