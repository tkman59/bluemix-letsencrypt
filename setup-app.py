import requests
import yaml
from subprocess import call, Popen, PIPE
import sys
import time


# Define some helper functions

def domain_has_ssl(domain, print_info=False):
    """domain_has_ssl uses the two most-reliable ways to check for an SSL on
    a domain name within bluemix. It calls the Bluemix CLI to ask for
    certificate details, and it attempts to connect to that domain with HTTPS.
    If either succeeds, it returns True. Otherwise, it returns false. Note
    that it is possible to get false negatives, but not false positives.
    The print_info parameter can be used to dump the certificate information
    from Bluemix to stdout.
    """
    pipe = Popen("bx security cert %s" % domain,
                 stdout=PIPE, shell=True)
    output = pipe.stdout.read()
    cert_exists = "OK" in output
    if print_info and cert_exists:
        print(output)
    return cert_exists or check_ssl(domain)


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
    cert = ''.join(output[3:-1])  # Strip leading and trailing characters
    with open(certname, 'w') as outfile:
        print("Writing cert to %s" % certname)
        outfile.write(cert)


def check_ssl(ssl_domain):
    """check_ssl makes an HTTPS request to a given domain name and
    returns a boolean for whether the SSL on the domain is present
    and valid.
    """
    try:
        target = "https://%s" % ssl_domain
        print("Making GET request to %s" % target)
        requests.get(target)
        return True
    except requests.exceptions.SSLError as err:
        print(err)
        return False

# Begin Script

with open('domains.yml') as data_file:
    settings = yaml.safe_load(data_file)

with open('manifest.yml') as manifest_file:
    manifest = yaml.safe_load(manifest_file)

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
end_token = "cf stop %s" % appname  # Seeing this in the log means certs done
log_pipe = Popen("cf logs %s --recent" % appname, shell=True,
                 stdout=PIPE, stderr=PIPE)
log_lines = log_pipe.stdout.readlines()
print("Waiting for certs (could take several minutes)")
while end_token not in ''.join(log_lines):
    # Keep checking the logs for cert readiness
    print("Certs not ready yet, retrying in 5 seconds.")
    time.sleep(5)
    log_pipe = Popen("cf logs %s --recent" % appname, shell=True,
                     stdout=PIPE, stderr=PIPE)
    log_lines = log_pipe.stdout.readlines()

# Figure out which domain name to look for
primary_domain = settings['domains'][0]['domain']

# Now that certs should be ready, parse for the commands to fetch them
cmds = []
for line in log_lines:
    if ("cf files %s" % appname) in line and primary_domain in line:
        cmds.append(line)

# Preprocess and transform commands
for idx, cmd in enumerate(cmds):
    # Break each command into chunks and ignore everything before
    # 'cf files ...'
    parts = [s.strip() for s in cmd.split(' ') if s != ''][3:]
    # Join the parts back together. This is necessary so that
    # it's easy to find all of the unique commands
    cmds[idx] = ' '.join(parts)

# Toss them in a set to keep only unique commands, then convert
# to a list again so that they can be broken into sublists
cmds = list(set(cmds))

# Extract the parts of each command that are of interest
cmds = [cmd.split(' ') for cmd in cmds]
for idx, cmd in enumerate(cmds):
    components = {}
    components['appname'] = cmd[2]
    components['domain'] = cmd[3].split('/')[-2]
    components['certname'] = cmd[3].split('/')[-1]
    # Fetch the certificate
    get_cert(**components)

domain_with_first_host = "%s.%s" % (settings['domains'][0]['hosts'][0],
                                    primary_domain)
# Hostname is sometimes '.', which requires special handling
if domain_with_first_host.startswith('..'):
    domain_with_first_host = domain_with_first_host[2:]

# Check if there is already an SSL in place
if domain_has_ssl(domain_with_first_host, True):
    print("\n\n***IMPORTANT***")
    print("This domain name already has an SSL in bluemix. You must"
          + " first remove the old SSL before adding a new one. This"
          + " means that your application will have a window of time"
          + " without an SSL. If that is unacceptable for your"
          + " application, use the Bluemix Web UI to update your"
          + " SSL. If you can afford the SSL downtime, follow the"
          + " instructions below. You may see error messages when"
          + " running these commands. You only need to be concerned if"
          + " the last command produces an error instead of displaying"
          + " a table of information about your new SSL.\n")
    print("\n(See Warning Above) If you wish to continue, run:\n"
          + ("bx security cert-remove %s; " % domain_with_first_host)
          + ("bx security cert-add %s -c cert.pem -k privkey.pem; "
             % domain_with_first_host)
          + ("bx security cert %s\n" % domain_with_first_host))
    sys.exit(1)

failure = True
count = 0
while(failure and count < 3):
    # Upload new cert
    print("Attempting certificate upload...")
    call("bx security cert-add %s -c cert.pem -k privkey.pem -i chain.pem"
         % domain_with_first_host, shell=True)
    failure = not domain_has_ssl(domain_with_first_host, True)
    count = count + 1
    time.sleep(5)

print("Warning: Please note that your SSL certificate, its corresponding"
      + " PRIVATE KEY, and its intermediate certificates have been downloaded"
      + " to the current working directory. If you need to remove them, use"
      + " `rm *.pem`")
if failure:
    print("Unable to upload certificates")
    sys.exit(1)
print("Upload Succeeded")
