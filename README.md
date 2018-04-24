CloudGenix - get-all-interface-info
---

Quick script to dump an entire CloudGenix user's network/site configuration summary to a single CSV.

#### Requirements
* Active CloudGenix Account
* Python >= 2.7 or >=3.6
* Python modules:
    * cloudgenix >=4.4.5b2 - <https://github.com/CloudGenix/sdk-python>
    * progressbar2 >=3.34.3 - <https://github.com/WoLpH/python-progressbar>

#### License
MIT

#### Usage Example:
```bash
mb-pro:get-all-interface-info aaron$ ./get-all-interface-info.py 
CloudGenix Site Interface info -> CSV Generator v4.5.5b2 (https://api.elcapitan.cloudgenix.com)

login: aaron@democompany.com
Password: 

Creating ./democompanyinc_interfaces_2017-12-20-21-28-58.csv for data output...
Caching Sites..
Caching Elements..
Caching WAN Networks..
Caching Circuit Catagories..
Caching Network Contexts..
Caching Policysets..
Caching Security Policysets..
Caching Security Zones..
Filling Network Site->Element->Interface table..
100%|###################################################################################################|Time: 0:01:39
Querying all interfaces for current status..
100%|###################################################################################################|Time: 0:08:54
mb-pro:get-all-interface-info aaron$ 
```

#### Version
Version | Changes
------- | --------
**1.1.0**| `pip install cloudgenix_get_all_interface_info` support, python3 support
**1.0.0**| Initial Release.