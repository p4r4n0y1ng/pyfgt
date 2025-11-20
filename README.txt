## Synopsis

Represents the base components of the Fortinet FortiGate REST interface. This code is based on the fortigate code provided in the ftntlib package as provided on the Fortinet Developer Network (FNDN) that was originally written by multiple personnel to include Ashton Turpin. It has since been modified by several others within Fortinet. This has now been streamlined and modified to utilize the standard **\**kwargs** functionality as well as has been modified extensively to be more scalable and provide context management and other aspects to inlcude handling the API Key functionality added with recent versions of FortiOS code.

## Code Example

Standard format for a FortiGate REST is utilized.

**Of Importance** is that this package uses context behavior for the FortiGate instance, so the **with** keyword can be utilized. This ensures that the FortiGate instance is logged into upon instantiation and is logged out of once the scope of the **with** statement is completed. For instance, to instantiate a FortiGate instance with the IP address of 10.1.1.1, with the user name admin and a password of <blank>, the user would simply type:

```
with FortiGate("10.1.1.1", "admin", "") as fgt_instance:
```

The context manager does not HAVE to be utilized obviously. However, if it is not utilized, the *login* and *logout* functionality is not handled for the caller. It is expected that these methods will be called if the context manager is not utilized. Note*, the API Key functionality vice password will be discussed later in this doc. An example of not using the context manager would be:

```
fgt_instance = FortiGate("10.1.1.1", "admin", "")
fgt_instance.login()
*something of importance accomplished here*
fgt_instance.logout()
```

Continuing, when a FortiGate instance is instantiated, the following attributes are configured (or can be configured by the user). The list provided lists the defaults.

```
- passwd (default None)
- apikeyused (default False)
- debug (default False),
- use_ssl (default True),
- verify_ssl (default False),
- timeout (default 300)
```
For instance, to instantiate a FortiGate instance with the IP address of 10.1.1.1, with the user name admin and a password of <blank>, that uses http instead of https, is in debug mode, and warns after the verification of the SSL certificate upon each request and has a timeout of 100 the user would simply type:

```
with FortiGate("10.1.1.1", "admin", "", debug=True, use_ssl=False, debug=True, disable_request_warnings=False, timeout=100) as fgt_instance:
```

API Key utilization will be discussed later, but it is important here to understand that to use an API Key instead of a password, the only thing that needs to happen is that the attribute must be specifically called out in the instantiation. Although username is not required using an API Key, it IS required in this library as it maintains uniformity an example of the same call as above except using an API Key administrative capability would be:

```
with FortiGate("10.1.1.1", "admin", apikey="12345678910", debug=True, use_ssl=False, debug=True, disable_request_warnings=False, timeout=100) as fgt_instance:
```

Obviously these same parameters would be used in the standard call if the context manager is not utilized so:

```
fgt_instance = FortiGate("10.1.1.1", "admin", "", debug=True, use_ssl=False, debug=True, disable_request_warnings=False, timeout=100)
```

or

```
fgt_instance = FortiGate("10.1.1.1", "admin", apikey="12345678910", debug=True, use_ssl=False, debug=True, disable_request_warnings=False, timeout=100)
```

While this module is meant to be utilized with another caller-written abstraction, there is no reason that this module could not be utilized by itself to make detailed, multi-parameter calls. To that end, a capability has been provided that enables keyword/value arguments to be passed into any of the *get*, *delete* ,*post* or *put* helper methods. Since there are many keywords in the FortiGate body that require a dash (and since the dash character is not allowed as a keyword argument handled by the **\**kwargs** pointer), a facility has been added such that a keyword with a double underscore **__** is automatically translated into a dash **-** when the keyword/value pair is put into the body of the call. An example follows (notice the double underscores in the keyword items, these will be translated to dashes when the call is made):

```
fgt.post("/cmdb/vpn.ipsec/phase1-interface", p1name1", "port1", "1.1.1.1", 2, "2.2.2.2", "topsecret", "vdom=root", dpd="on-demand", proposal="aes128-sha1", keylife=28800, authmethod="psk", dpd__retryinterval=10, peertype="any")
```

This facility is helpful, but a more obvious way to make these kind of calls with a little more clarity is shown below in the **Tests** section where a standard dictionary is utilized effectively. In that case, the double underscore translations are not needed and dashes will work perfectly fine (see below).

Another facility has been put in place to allow for querystrings to be applied when the FGT call is made. If a user wants to ensure a certain VDOM is addressed, the call would have ?vdom=vdomname at the end of the URL endpoint called in basic querystring format. However, the FGT API can utilize filter and format functions as well that can be used effectively and are even further requirements for a querystring option. In this library, the **\*args** pointer is utilized and uses each string provided in the list to append to the URL called. An example of this would be to perform a get function to find an address object named *test_object* in vdom *root*. The call would be made like this:

```
fgt.get("/cmdb/firewall/address", "vdom=root", "format=name", "filter=name==test_object")
```

Since these arguments are not named and are not in key value format they are sent in on the *\*args* pointer and used as querystrings. Output would be as expected:

```
(200, {'http_method': 'GET', 'revision': '31.0.74.9539865665020633197.1533399174', 'results': [{'q_origin_key': 'test_object', 'name': 'test_object'}], 'vdom': 'root', 'path': 'firewall', 'name': 'address', 'status': 'success', 'http_status': 200, 'serial': 'FGVM020000118048', 'version': 'v6.0.2', 'build': 163})
```

Notice only the name attribute (and the key of course) and the specific object is returned as requested.

## Exceptions

The module provides the following exceptions for use:

1. FGTBaseException(Exception)
2. FGTValidSessionException(FGTBaseException)
3. FGTValueError(ValueError)
4. FGTResponseNotFormedCorrect(KeyError)
5. FGTConnectionError(ReqConnError)
6. FGTConnectTimeout(ReqConnTimeout):

**FGTBaseException** is the Base exception for the module and can be used to catch all things outside of the ValueError and Keyerror issues.

a caller could then write the following and have the equivalent of a standard *except* call with no exception mentioned. This ensures scalability:
```
try:
    Doing Something Here
except FGTBaseException:
    Do something with Exception
```

**FGTValidSessionException** has been added and is raised if any call is attempted without a valid connection being made to a FGT. In the past, other than to check the \_\_str()\_\_ value of the object after the login return, the code would continue to try to make calls despite having no valid session. Any call attempted now on an invalid session will have this error thrown. As a caveat - if the API Key version of this is used (which does not use the session concept) and not a user and password, a session is faked and as such this error would not be thrown.

**FGTValueError** is a standard ValueError and is caught in special cases where a connection attempt is made or a call is made with an invalid value. An example of this would be a connection to a FGT instance with a *timeout* value of <= 0.

**FGTResponseNotFormedCorrect** will be raised when response received back from the FGT instance does not have a correct return attribute in a response. FGT responses without these attributes are ill-formed and will raise this error. The only exception to this is the response from a valid *login()* call. This exception is suppressed for this, and a valid response is crafted for login to ensure a stable, standard, and constant response back from the module.

**FGTConnectionError** and **FGTConnectTimeout** are raised when a *requests.exception.ConnectionError* or *requests.exceptions.ConnectTimeout* exception is caught. This ensures calling code does not need to import/depend on the requests module to handle requests connection exceptions. *FGTConnectionError* will most likely be thrown at *login()* and are likely due to an incorrect hostname, or IP Address of the FGT appliance.  

Exceptions are allowed to propogate up to the caller and are only caught in certain cases where they will be needed in case verbose mode is asked for and the caller wants a print out of the exception. After the print is accomplished that same exception will be raised and propogated so it can be either caught and handled by the caller or used as a debug tool.

## Responses

A standard, response mechanism is provided from this module so calling objects know what to expect back. Unless an exception is thrown, this module will return a 2 object tuple consisting of the status code of the response back, followed by a valid JSON message or the entire JSON response. Since login does not provide a constant response from a FGT appliance, one is provided by this module to ensure a caller knows what will be returned and in what format. An example response of a login, get call, and then logout process is below:

```
(0, {"status_code": response.status_code, "message": "Login Successful"})

(200, {'http_method': 'GET', 'revision': '29.0.74.9539865665020633197.1533399174', 'results': [{'q_origin_key': 'FIREWALL_AUTH_PORTAL_ADDRESS', 'name': 'FIREWALL_AUTH_PORTAL_ADDRESS', 'uuid': 'f7b74268-9800-51e8-aac3-47267065c700', 'subnet': '0.0.0.0 0.0.0.0', 'type': 'ipmask', 'start-ip': '0.0.0.0', 'end-ip': '0.0.0.0', 'fqdn': '', 'country': '', 'wildcard-fqdn': '', 'cache-ttl': 0, 'wildcard': '0.0.0.0 0.0.0.0', 'sdn': '', 'tenant': '', 'organization': '', 'epg-name': '', 'subnet-name': '', 'sdn-tag': '', 'policy-group': '', 'comment': '', 'visibility': 'disable', 'associated-interface': '', 'color': 0, 'filter': '', 'obj-id': '', 'list': [], 'tagging': [], 'allow-routing': 'disable'}, {'q_origin_key': 'SSLVPN_TUNNEL_ADDR1', 'name': 'SSLVPN_TUNNEL_ADDR1', 'uuid': 'f7b7b7d4-9800-51e8-4681-39920a003592', 'subnet': '10.212.134.200 10.212.134.210', 'type': 'iprange', 'start-ip': '10.212.134.200', 'end-ip': '10.212.134.210', 'fqdn': '', 'country': '', 'wildcard-fqdn': '', 'cache-ttl': 0, 'wildcard': '10.212.134.200 10.212.134.210', 'sdn': '', 'tenant': '', 'organization': '', 'epg-name': '', 'subnet-name': '', 'sdn-tag': '', 'policy-group': '', 'comment': '', 'visibility': 'enable', 'associated-interface': 'ssl.root', 'color': 0, 'filter': '', 'obj-id': '', 'list': [], 'tagging': [], 'allow-routing': 'disable'}, {'q_origin_key': 'all', 'name': 'all', 'uuid': 'f7b74128-9800-51e8-be0f-fdd4904c302f', 'subnet': '0.0.0.0 0.0.0.0', 'type': 'ipmask', 'start-ip': '0.0.0.0', 'end-ip': '0.0.0.0', 'fqdn': '', 'country': '', 'wildcard-fqdn': '', 'cache-ttl': 0, 'wildcard': '0.0.0.0 0.0.0.0', 'sdn': '', 'tenant': '', 'organization': '', 'epg-name': '', 'subnet-name': '', 'sdn-tag': '', 'policy-group': '', 'comment': '', 'visibility': 'enable', 'associated-interface': '', 'color': 0, 'filter': '', 'obj-id': '', 'list': [], 'tagging': [], 'allow-routing': 'disable'}, {'q_origin_key': 'autoupdate.opera.com', 'name': 'autoupdate.opera.com', 'uuid': 'f75a0a80-9800-51e8-7b08-7e7dc2a4c3ab', 'subnet': '0.0.0.0 0.0.0.0', 'type': 'fqdn', 'start-ip': '0.0.0.0', 'end-ip': '0.0.0.0', 'fqdn': 'autoupdate.opera.com', 'country': '', 'wildcard-fqdn': 'autoupdate.opera.com', 'cache-ttl': 0, 'wildcard': '0.0.0.0 0.0.0.0', 'sdn': '', 'tenant': '', 'organization': '', 'epg-name': '', 'subnet-name': '', 'sdn-tag': '', 'policy-group': '', 'comment': '', 'visibility': 'enable', 'associated-interface': '', 'color': 0, 'filter': '', 'obj-id': '', 'list': [], 'tagging': [], 'allow-routing': 'disable'}, {'q_origin_key': 'google-play', 'name': 'google-play', 'uuid': 'f75a14bc-9800-51e8-aeb1-59e60755753e', 'subnet': '0.0.0.0 0.0.0.0', 'type': 'fqdn', 'start-ip': '0.0.0.0', 'end-ip': '0.0.0.0', 'fqdn': 'play.google.com', 'country': '', 'wildcard-fqdn': 'play.google.com', 'cache-ttl': 0, 'wildcard': '0.0.0.0 0.0.0.0', 'sdn': '', 'tenant': '', 'organization': '', 'epg-name': '', 'subnet-name': '', 'sdn-tag': '', 'policy-group': '', 'comment': '', 'visibility': 'enable', 'associated-interface': '', 'color': 0, 'filter': '', 'obj-id': '', 'list': [], 'tagging': [], 'allow-routing': 'disable'}, {'q_origin_key': 'none', 'name': 'none', 'uuid': 'f75a0648-9800-51e8-13ca-d6da511600b3', 'subnet': '0.0.0.0 255.255.255.255', 'type': 'ipmask', 'start-ip': '0.0.0.0', 'end-ip': '255.255.255.255', 'fqdn': '', 'country': '', 'wildcard-fqdn': '', 'cache-ttl': 0, 'wildcard': '0.0.0.0 255.255.255.255', 'sdn': '', 'tenant': '', 'organization': '', 'epg-name': '', 'subnet-name': '', 'sdn-tag': '', 'policy-group': '', 'comment': '', 'visibility': 'enable', 'associated-interface': '', 'color': 0, 'filter': '', 'obj-id': '', 'list': [], 'tagging': [], 'allow-routing': 'disable'}, {'q_origin_key': 'swscan.apple.com', 'name': 'swscan.apple.com', 'uuid': 'f75a1818-9800-51e8-97cd-d9102cc59904', 'subnet': '0.0.0.0 0.0.0.0', 'type': 'fqdn', 'start-ip': '0.0.0.0', 'end-ip': '0.0.0.0', 'fqdn': 'swscan.apple.com', 'country': '', 'wildcard-fqdn': 'swscan.apple.com', 'cache-ttl': 0, 'wildcard': '0.0.0.0 0.0.0.0', 'sdn': '', 'tenant': '', 'organization': '', 'epg-name': '', 'subnet-name': '', 'sdn-tag': '', 'policy-group': '', 'comment': '', 'visibility': 'enable', 'associated-interface': '', 'color': 0, 'filter': '', 'obj-id': '', 'list': [], 'tagging': [], 'allow-routing': 'disable'}, {'q_origin_key': 'update.microsoft.com', 'name': 'update.microsoft.com', 'uuid': 'f75a1b2e-9800-51e8-9692-587a860fbeda', 'subnet': '0.0.0.0 0.0.0.0', 'type': 'fqdn', 'start-ip': '0.0.0.0', 'end-ip': '0.0.0.0', 'fqdn': 'update.microsoft.com', 'country': '', 'wildcard-fqdn': 'update.microsoft.com', 'cache-ttl': 0, 'wildcard': '0.0.0.0 0.0.0.0', 'sdn': '', 'tenant': '', 'organization': '', 'epg-name': '', 'subnet-name': '', 'sdn-tag': '', 'policy-group': '', 'comment': '', 'visibility': 'enable', 'associated-interface': '', 'color': 0, 'filter': '', 'obj-id': '', 'list': [], 'tagging': [], 'allow-routing': 'disable'}], 'vdom': 'root', 'path': 'firewall', 'name': 'address', 'status': 'success', 'http_status': 200, 'serial': 'FGVM020000118048', 'version': 'v6.0.2', 'build': 163})

(0, {"status_code": response.status_code, "message": "Logout Successful"})
``` 

## Motivation

This package supports Ansible requirements and proper mod_utils utilization, however, it can be utilized for contact with any Fortinet FortiGate appliance or VM asset. 

## Installation

Installation of this package will be via the pip interface

## Tests

Utilizing the library is relatively simple.

Assuming you are within the with context and still using **fgt_instance** as before, to get all address objects in the **root** vdom, the following would be used:

```
fgt_instance.get("cmdb/firewall/address", "vdom=root")
```

To **add** an address group with a member address object of autoupdate.opera.com, the following would be used:

```
data = {
            "name": "test_group",
            "member": [{"name": "autoupdate.opera.com"}, ],
        }
fgt_instance.post("/cmdb/firewall/addrgrp", **data)
```

Notice how the **data** dictionary is created and then sent in as **\**data**. This would allow for if there are dashes in the keys of the dictionary that is required. If you did not want to use the double underscore method of alleviating this problem, the above method is the way to handle that as the building of the JSON within the object doesn't have the issue. The call could have been:

```
fgt_instance.post("/cmdb/firewall/addrgrp", name="test_group", member=[{"name": "autoupdate.opera.com"}, ])
```

Notice that all you have to do is send in the data that needs to be sent to the FortiGate appliance in the **\**kwargs** field - this makes calls extremely simple - send in a URL and the keyword arguments and the rest is taken care of.
