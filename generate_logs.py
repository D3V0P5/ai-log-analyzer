#!/usr/bin/env python
import random
import datetime
from pathlib import Path

# Create logs directory
Path("synthetic_logs").mkdir(exist_ok=True)

# Log templates (safe, fake data)
templates = [
    'Failed password for {} from {} port {} ssh2',
    'Accepted password for {} from {} port {} ssh2',
    'Invalid user {} from {} port {}',
    'Connection closed by {} port {} [preauth]',
    'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={}  user={}',
    'sudo: {} : TTY=pts/0 ; PWD=/home/{} ; USER=root ; COMMAND={}',
    'Firewall: {} {} from {} to {} port {}',
    'Process {} (PID:{}) exceeded memory limit ({}MB > {}MB)',
    'Backup completed: {} bytes written in {} seconds',
    'API request {} from {} returned {} in {}ms'
]

# Fake data pools
users = ['admin', 'root', 'jsmith', 'mwilson', 'kbrown', 'nobody', 'www-data', 'deployer']
ips = ['10.0.0.{}'.format(i) for i in range(1, 255)] + \
      ['192.168.1.{}'.format(i) for i in range(1, 255)] + \
      ['172.16.0.{}'.format(i) for i in range(1, 50)] + \
      ['203.0.113.{}'.format(i) for i in range(1, 50)]  # Reserved for documentation
ports = [22, 80, 443, 3306, 5432, 8080, 8443, 27017]
commands = ['systemctl restart nginx', 'rm -rf /tmp/*', 'docker ps', 'cat /etc/passwd', 'whoami', 'apt update']
actions = ['ALLOW', 'DENY', 'DROP', 'REJECT']
protocols = ['TCP', 'UDP', 'ICMP']
methods = ['GET', 'POST', 'PUT', 'DELETE']
status_codes = [200, 201, 400, 401, 403, 404, 500, 502, 503]

def generate_log_line(timestamp):
    template = random.choice(templates)
    
    if 'Failed password' in template:
        return template.format(random.choice(users), random.choice(ips), random.choice(ports))
    elif 'Accepted password' in template:
        return template.format(random.choice(users), random.choice(ips), random.choice(ports))
    elif 'Invalid user' in template:
        return template.format(random.choice(['test', 'ftpuser', 'oracle', 'git', random.choice(users)]), random.choice(ips), random.choice(ports))
    elif 'Connection closed' in template:
        return template.format(random.choice(ips), random.choice(ports))
    elif 'authentication failure' in template:
        return template.format(random.choice(ips), random.choice(users))
    elif 'sudo:' in template:
        user = random.choice(users[:5])
        return template.format(user, user, random.choice(commands))
    elif 'Firewall:' in template:
        return template.format(random.choice(actions), random.choice(protocols), random.choice(ips), random.choice(ips), random.choice(ports))
    elif 'exceeded memory' in template:
        proc = random.choice(['nginx', 'mysql', 'node', 'python3', 'java'])
        return template.format(proc, random.randint(1000, 9999), random.randint(500, 2000), random.randint(256, 1024))
    elif 'Backup completed' in template:
        return template.format(random.randint(1000000, 999999999), random.randint(1, 300))
    else:  # API request
        return template.format(random.choice(methods), random.choice(ips), random.choice(status_codes), random.randint(10, 5000))

# Generate multiple log files
for file_num in range(1, 6):
    log_file = f"synthetic_logs/access_{file_num}.log"
    with open(log_file, 'w') as f:
        # Generate 100-500 lines per file
        for _ in range(random.randint(100, 500)):
            timestamp = datetime.datetime.now() - datetime.timedelta(seconds=random.randint(0, 86400*7))
            timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
            log_line = generate_log_line(timestamp)
            f.write(f"{timestamp_str} {log_line}\n")
    print(f"Generated: {log_file}")

print("\nDone! Files in synthetic_logs/")