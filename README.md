# dnstool.py

- dns enumeration tool in python3

- the tool's functionality:
	- dns enumeration
	- adding or updating dns entries
	- zonetransfer attacks


```
usage: dnstool.py [-h] [--target TARGET] [--zonetransfer] [--record RECORD] [--all] [-update] [--entry ENTRY] [--map MAP] [-add] [--file FILE]

options:
  -h, --help            show this help message and exit
  --target TARGET, -t TARGET
                        the target domain name OR ip address
  --zonetransfer, -zt   attempt to make a zone transfer on the given domain
  --record RECORD, -r RECORD
                        the record to resolve (example: A, NS, CNAME, SOA , PTR, MX, TXT, AAAA)
  --all                 alias for (ANY) record, returns all the available records
  -update               update an entry [requires the (--entry) flag and (--record) flag]
  --entry ENTRY, -e ENTRY
                        entry to update [to be used only with the --update/--add flag]
  --map MAP, -m MAP     mapping target to map the newly added entry to [to be used only with the --update/--add flag]
  -add                  add a new entry to the dns server
  --file FILE, -f FILE  enumerate mutliple domains from file

Examples:

dnstool.py -t zonetransfer.me -r A --> returns the A record	

dnstool.py -t zonetransfer.me -zt  --> attempts zonetransfer against the target (using the dig utility)

dnstool.py -update -t domain.com -r A -e subdomain.domain.com --map ip_address --> will attempt to update the A record of the subdomain
on the dns server to the mapped (ip_address) # useful in a dns cache poison attack 

dnstool.py -add -t domain.com -r A -e subdomain.domain.com --map ip_address --> will attempt to add a new A record of the subdomain 
on the dns server to the mapped (ip_address)

dnstool.py --file domains.txt --all --> will return all available records for every domain in the file
```

# installing the required dependencies:

- dnspython: `# python3 -m pip install dnspython`
- dig: `apt install dnsutils`





- thanks to  <a href="https://twitter.com/Cyberkid012">@Cyberkid012</a> for testing the tool <3 