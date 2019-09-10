# tiffy

Generate Feeds from TIE Content

# Requirements
## Base
- Python 3.7
- TIE API Key http://tie.dcso.de  

## Packages
- PyTest https://pytest.org
- pytest-testdox https://github.com/renanivo/pytest-testdox
- Requests http://python-requests.org
- PyYAML http://pyyaml.org
- Click http://click.pocoo.org/
- PyMISP https://github.com/MISP/PyMISP
- python-dateutil https://dateutil.readthedocs.io

# Install
```bash
$ git clone https://github.com/DCSO/tiffy.git
$ pip3 install -r requirements.txt
```

## Configuration
The command line client expects a configuration file in the `tiffy/settings` directory where you have to
define the required API key and URL. To create the config file, just copy the `config.sample.yml` file to `config.yml`
and edit it.

```bash
$ cp settings/config.sample.yml settings/config.yml

$ vim settings/config.yml
```

# HowTo
To start the generator just run:
```bash
$ ./tiffy.py
```
The generator will now process all IOCs as attributes beginning from the current system date.

If no first seen date is set, the generator will always use the current system date as default.

To process attributes from or until a specific date you can use the `--first-seen YYYY-MM-DD` or 
`--last-seen YYYY-MM-DD` option. You can also combine both parameters.
```bash
$ ./tiffy.py --first-seen 2019-03-13

$ ./tiffy.py --last-seen 2019-07-13

$ ./tiffy.py --first-seen 2019-03-13 --last-seen 2019-07-13
```

## Using the source, actor, category or family parameter
Sometimes it's necessary to get all IOC's from a specific attacker group or tool family. In most cases these are known 
under more than one name. Because of this, tiffy offers the capability to search for these values.

You can pass one or multiple values either as a single string or a comma delimited list of strings

Query family based IOC's
```bash
$ ./tiffy.py --family example

$ ./tiffy.py --family example1,example2
```

Query actor based IOC's
```bash
$ ./tiffy.py --actor example

$ ./tiffy.py --actor example1,example2
```

Query category based IOC's
```bash
$ ./tiffy.py --category example

$ ./tiffy.py --category example1,example2
```

Query source based IOC's
```bash
$ ./tiffy.py --source example

$ ./tiffy.py --source example1,example2
```

##Using severity and confidence parameters

tiffy is also able to filter ioc's based on min or max severity/confidence. If you pass only a min-value, tiffy
will search all values at or above the value. If you pass only a max-value, ioc's at or below the value will be returned.
When passing min and max-value, all ioc's between these values are used.

Query severity based IOC's
```bash
$ ./tiffy.py --min-severity 2                          #gets all ioc's from and including severity 2    

$ ./tiffy.py --max-severity 4                          #gets all ioc's up to and including severity 4

$ ./tiffy.py --min-severity 2 --max-severity 4         #gets all ioc's from severity 2 to severity 4
```

Query confidence based IOC's
```bash
$ ./tiffy.py --min-confidence 2                        #gets all ioc's from and including confidence 2    

$ ./tiffy.py --max-confidence 4                        #gets all ioc's up to and including confidence 4

$ ./tiffy.py --min-confidence 2 --max-confidence 4     #gets all ioc's from confidence 2 to confidence 4
```

## Setting default tags for the MISP-Event

You can pass tags for the newly created event. Tags are passed as MISP-compatible JSON Strings and will be added 
to the base event. Double quotes need to be escaped. If no tags are passed tlp.amber will be used as default.

```bash
$ ./tiffy.py --event-tags {\"name\":\"tlp:amber\"}
```

## Setting the Output Format

You can choose the output format of the feed. Currently only MISP-JSON is supported but more formats will follow.

```bash
$ ./tiffy.py --output-format MISP
````

## Disable the Default Filter

tiffy will use the default TIE filter. You can disable this behaviour by passing the `--no-filter` parameter.

```bash
$ ./tiffy.py --no-filter
````

## Additional Parameters

tiffy offers some additional parameters:
- `--loglvl` sets the log level. Values are 0 - NOTSET / 10 - DEBUG / 20 - INFO / 30 - WARNING / 40 - ERROR / 50 - CRITICAL
- `--disable_console_log` disables log output to the console
- `--disable_file_log` disables logging to file

```bash
$ ./tiffy.py --loglvl 10

$ ./tiffy.py --disable_console_log

$ ./tiffy.py --disable_file_log
````

## Using a proxy
tiffy offers various ways for the use of a proxy. First, if the system variable `HTTP_PROXY` or `HTTPS_PROXY` is 
set, tiffy will automatically use the given information's.

If no system variable is used, tiffy will check if the parameter `--proxy_http` or `--proxy_https` is set. If so, tiffy will use the parameter for pulling informations. 

You can use only `--proxy_http` or `--proxy_https` or both
```bash
$ ./tiffy.py --proxy_http "http://10.8.0.1:8000"
$ ./tiffy.py --proxy_http "http://10.8.0.1:8000 --proxy_https "http://10.8.0.1:8443"
```
With HTTP Basic Auth
```bash
$ ./tiffy.py --proxy_http "http://user:pass@10.8.0.1:8000"
```

###Disable Certificate Verification

If your Proxy is using SSL-Interception, it might be necessary to disable
the certificate verification for requests. Use the `--disable_cert_verify` flag
in this case.

```bash
$ ./tiffy.py --proxy_http "http://10.8.0.1:8000" --disable_cert_verify
```

## Setting up Feed
if tiffy ran successfully at least once, the directory `tiffy/feed` will be present. In this directory are all files needed for a MISP Feed. You need to upload these files onto a file server like nginx or apache.

We used nginx as an example. Upload the files into a directory on the nginx server and add a server configuration in the nginx.conf to make the directory accessible.

```
server {
		listen 8001;  #port the nginx should listen on and provide the feed
	    root /path/to/feed/directory;
	    	autoindex on;        # tells nginx to automatically index the files so that they can be accessed
	    location / {
	    	autoindex on;        # tells nginx to automatically index the files so that they can be accessed
	    }
	}
```

After setting up the file server, the feed can be added to MISP. From the main menu, go to `Sync Actions`-> `List Feeds`. In the menu on the left, select `Add Feed`. 

Set the feed to enabled and activate lookup and caching. Name the feed and the provider and set input source to Network. In the url field, add the url to the feed directory on your file server.

![alt text](https://raw.githubusercontent.com/DCSO/tiffy/master/images/add_feed.png "Add Feed")

After setting up the feed and enabling it, the events will be imported into MISP. To manually start an import, click the download icon on the TIE feed in the feed list. To see all events and import single events contained in the feed, click on the magnifying glass icon.

![alt text](https://raw.githubusercontent.com/DCSO/tiffy/master/images/options.png "Options")

# License

This software is released under a BSD 3-Clause license.
Please have a look at the LICENSE file included in the repository.

Copyright (c) 2019, DCSO Deutsche Cyber-Sicherheitsorganisation GmbH
