Prisma SD-WAN - get-all-interface-info
---

Quick script to dump an entire Prisma SD-WAN network/site configuration summary to a single CSV.


#### Requirements
* Active Prisma SASE Account with SD-WAN.
* Prisma SASE "Service Account" credentials that has been assigned appropriate permissions to read Prisma SD-WAN configuration.
  * Service account credentials can be entered interactive, script arguments, environment varibales, or via a `prisma_sase_settings.py` setting file in the current working directory.
* Python >=3.6
* Python modules:
    * prisma-sase >=4.4.5b2 - <https://github.com/PaloAltoNetworks/prisma-sase-sdk-python>
    * progressbar2 >=3.34.3 - <https://github.com/WoLpH/python-progressbar>

#### License
MIT

#### Usage Example:
```bash
mb-pro:get-all-interface-info aaron$ ./get-all-interface-info.py 
Prisma SD-WAN Site Interface info -> CSV Generator v6.3.1b1 (https://api.sase.paloaltonetworks.com)

Please enter Prisma SASE Service Account (not user account) info to login.
Prisma SASE Client ID: aaron-script-test@55512124.iam.panserviceaccount.com
Prisma SASE Client Secret: 
Prisma SASE TSG ID: 55512124
Creating ./democompanyinc_interfaces_2024-02-01-18-07-34.csv for data output...
Caching Sites..
Caching Elements..
Caching WAN Networks..
Caching Circuit Catagories..
Caching Network Contexts..
Caching Policysets..
Caching Security Policysets..
Caching Security Zones..
Filling Network Site->Element->Interface table..
100%|############################################################################################################################################################################|Time:  0:00:01
Querying all interfaces for current status..
100%|############################################################################################################################################################################|Time:  0:00:21
mb-pro:get-all-interface-info aaron$ 
```

#### Version
Version | Changes
------- | --------
**2.0.1**| Refactor utility to use Prisma SASE SDK instead of legacy CloudGenix SDK.
**1.1.1**| Minor edits to support commas in Site & Element names. Added AUTH TOKEN support.
**1.1.0**| `pip install cloudgenix_get_all_interface_info` support, python3 support
**1.0.0**| Initial Release.