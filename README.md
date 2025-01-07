Python3/Scapy based implementation of the TCP sockstress denial of service exploit.

Original Python2 implementation by Justin 'pan0pt1c0n' Hutchens.

## Installation
~~~
$ git clone https://github.com/movatica/python-sockstress.git
$ cd python-sockstress
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip install -r requirements.txt
~~~


## Usage
~~~
sock_stress.py [-h] [-t THREADS] target port

TCP sockstress implementation for CVE-2008-4609.

positional arguments:
  target                target ipv4 address.
  port                  target Port - must be reachable!

options:
  -h, --help            show this help message and exit
  -t THREADS, --threads THREADS
                        number of threads to run in parallel (default: 20)
~~~

## Further reading
* https://en.wikipedia.org/wiki/Sockstress
* https://nvd.nist.gov/vuln/detail/cve-2008-4609
