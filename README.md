# sub-enum
Yet another tool for subdomains enumeration.
```
Usage: sub-enum [options...] <domain>
 -h	display this help and exit
 -e	E-mail DNS entries (MX, SPF, DMARC)
 -g	Google search
 -t	Certificate transparancy check (crt.sh)
 -z	Zone transfering
 -p	PTR lookup
 -w	HTTP headers and HTML page source analyzing
 -W	Web archive
 -a	Use public APIs
 -O	Markdown output
 -L	Limit DNS resolve output
```

# Example
![Example](https://github.com/abletsoff/sub-enum/blob/main/poc.png?raw=true)

# API
Create `api-keys.txt` file with the following syntax:
```
SecurityTrails:your_api_key
```
