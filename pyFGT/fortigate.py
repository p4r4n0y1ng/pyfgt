#!/usr/bin/env python

import logging
import json
import requests
from requests.exceptions import ConnectionError as ReqConnError, ConnectTimeout as ReqConnTimeout

log = logging.getLogger("fortigate")


class FGTBaseException(Exception):
    """Wrapper to catch the unexpected"""

    def __init__(self, msg=None, *args, **kwargs):
        if msg is None:
            msg = "An exception occurred within pyfmg"
        super(FGTBaseException, self).__init__(msg, *args, **kwargs)


class FGTValidSessionException(FGTBaseException):
    """Raised when a call is made, but there is no valid login instance"""

    def __init__(self, method, url, *args, **kwargs):
        msg = "A call using the {method} method was requested to {url} on a FortiOS instance that had no " \
              "valid session or was not connected. Paramaters were:\n{params}". \
            format(method=method, url=url, params=kwargs)
        super(FGTValidSessionException, self).__init__(msg, *args, **kwargs)


class FGTValueError(ValueError):
    """Catch value errors such as bad timeout values"""

    def __init__(self, *args, **kwargs):
        super(FGTValueError, self).__init__(*args, **kwargs)


class FGTResponseNotFormedCorrect(KeyError):
    """Used only if a response does not have a standard format as based on FGT response guidelines"""

    def __init__(self, *args, **kwargs):
        super(FGTResponseNotFormedCorrect, self).__init__(*args, **kwargs)


class FGTConnectionError(ReqConnError):
    """Wrap requests Connection error so requests is not a dependency outside this module"""

    def __init__(self, *args, **kwargs):
        super(FGTConnectionError, self).__init__(*args, **kwargs)


class FGTConnectTimeout(ReqConnTimeout):
    """Wrap requests Connection timeout error so requests is not a dependency outside this module"""

    def __init__(self, *args, **kwargs):
        super(FGTConnectTimeout, self).__init__(*args, **kwargs)


class FortiGate(object):

    def __init__(self, host, user, passwd=None, debug=False, use_ssl=True, verify_ssl=False, timeout=300,
                 disable_request_warnings=False, apikey=None):
        super(FortiGate, self).__init__()
        self._host = host
        self._user = user
        self._req_id = 0
        self._url = None
        self._session = None
        self._sid = None
        self._timeout = timeout
        self._debug = debug
        self._use_ssl = use_ssl
        self._verify_ssl = verify_ssl
        self._apikeyused = True if passwd is None and apikey is not None else False
        self._passwd = passwd if passwd is not None else apikey
        if disable_request_warnings:
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    @property
    def api_key_used(self):
        return self._apikeyused

    @api_key_used.setter
    def api_key_used(self, val):
        self._apikeyused = val

    @property
    def debug(self):
        return self._debug

    @debug.setter
    def debug(self, val):
        self._debug = val

    @property
    def req_id(self):
        return self._req_id

    @req_id.setter
    def req_id(self, val):
        self._req_id = val

    def _update_request_id(self, reqid=0):
        self.req_id = reqid if reqid != 0 else self.req_id + 1

    @property
    def sid(self):
        return self._sid

    @sid.setter
    def sid(self, val):
        self._sid = val

    @property
    def verify_ssl(self):
        return self._verify_ssl

    @verify_ssl.setter
    def verify_ssl(self, val):
        self._verify_ssl = val

    @property
    def timeout(self):
        return self._timeout

    @timeout.setter
    def timeout(self, val):
        self._timeout = val

    @staticmethod
    def jprint(json_obj):
        try:
            return json.dumps(json_obj, indent=2, sort_keys=True)
        except TypeError as te:
            return json.dumps({"Type Information": te.message})

    def dprint(self, msg, s=None):
        if self.debug:
            print(msg)
            if s is not None:
                print(self.jprint(s) + "\n")
        pass

    def _set_sid(self, response):
        if self.api_key_used:
            self.sid = "apikeyusednosidavailable"
            return
        for cookie in response.cookies:
            if cookie.name == "ccsrftoken":
                csrftoken = cookie.value[1:-1]
                self._session.headers.update({"X-CSRFTOKEN": csrftoken})
            if "APSCOOKIE_" in cookie.name:
                self.sid = cookie.value

    def _set_url(self, url, *args):
        if "logincheck" in url or "logout" in url:
            self._url = "{proto}://{host}/{url}".format(proto="https" if self._use_ssl else "http",
                                                        host=self._host, url=url)
        else:
            if url[0] == "/":
                url = url[1:]
            self._url = "{proto}://{host}/api/v2/{url}".format(proto="https" if self._use_ssl else "http",
                                                               host=self._host, url=url)
            if len(args) > 0:
                self._url = "{url}?".format(url=self._url)
                try:
                    self._url = self._url + "&".join(args)
                except:
                    pass

    def __handle_login_values(self, response):
        # response first character defines if login was successful
        # 0 Log in failure. Most likely an incorrect username/password combo.
        # 1 Successful log in*
        # 2 Admin is now locked out
        # 3 Two-factor Authentication is needed**
        try:
            if response.status_code == 200:
                if response.text == "" or response.text[0] == "0":
                    return -1, {"status_code": response.status_code,
                                "message": "Failed Login - Most likely incorrect username/password used"}
                elif response.text[0] == "1":
                    self._set_sid(response)
                    return 0, {"status_code": response.status_code, "message": "Login Successful"}
                elif response.text[0] == "2":
                    return -1, {"status_code": response.status_code, "message": "Admin Locked Out"}
                elif response.text[0] == "3":
                    return -1, {"status_code": response.status_code, "message": "Two-factor Required"}
                else:
                    return -1, {"status_code": response.status_code, "message": "Unknown Error Occurred"}
            else:
                return -1, {"status_code": response.status_code,
                            "message": "Login Failed Status Code {} Returned".format(response.status_code)}
        except IndexError as err:
            self.dprint("Index error in response: {err_type} {err}\n\n".format(err_type=type(err), err=err))
            raise FGTResponseNotFormedCorrect(err)

    def __handle_response_login(self, response):
        login_response = self.__handle_login_values(response)
        self.dprint("RESPONSE:", login_response[1])
        return login_response

    def __handle_response_logout(self, response):
        self._sid = None
        self._req_id = 0
        if response.status_code == 200:
            self.dprint("RESPONSE:", {"status_code": response.status_code, "message": "Logout Successful"})
            return 0, {"status_code": response.status_code, "message": "Logout Successful"}
        else:
            self.dprint("RESPONSE:", {"status_code": response.status_code, "message": "Logout Failed"})
            return -1, {"status_code": response.status_code, "message": "Logout Failed"}

    def _handle_response(self, resp):
        if "logincheck" in self._url:
            return self.__handle_response_login(resp)
        elif "logout" in self._url:
            return self.__handle_response_logout(resp)
        else:
            try:
                response = resp.json()
            except:
                return -1, resp
            try:
                if "text" in response:
                    if type(response["text"]["results"]) is list:
                        result = response["text"]["results"][0]
                    else:
                        result = response["text"]["results"]
                    self.dprint("RESPONSE:", result)
                    if "http_status" in response:
                        return response["http_status"], result
                    else:
                        return response["status"], result
                else:
                    if "http_status" in response:
                        self.dprint("RESPONSE:", response)
                        return response["http_status"], response
                    else:
                        self.dprint("RESPONSE:", response)
                        return response["status"], response
            except IndexError as err:
                self.dprint("Index error in response: {err_type} {err}\n\n".format(err_type=type(err), err=err))
                raise FGTResponseNotFormedCorrect(err)
            except Exception as e:
                print("Response parser error: {err_type} {err}".format(err_type=type(e), err=e))
                return -1, e

    def _post_request(self, method, url, params):

        class InterResponse(object):
            def __init__(self):
                self.status_code = 200
                self.text = "1"

        if self.sid is None and "logincheck" not in url:
            raise FGTValidSessionException(method, params)
        self._update_request_id()
        if self.api_key_used:
            headers = {"content-type": "application/json",
                       "Authorization": "Bearer {apikey}".format(apikey=self._passwd)}
            self._session.headers.update(headers)
        else:
            headers = {"content-type": "application/json"}
            self._session.headers.update(headers)
        try:
            if "logincheck" in self._url:
                if self.api_key_used:
                    iresponse = InterResponse()
                    return self._handle_response(iresponse)
                else:
                    method_to_call = getattr(self._session, method)
                    json_request = "username={uname}&secretkey={pword}&ajax=1".format(uname=self._user,
                                                                                      pword=self._passwd)
                    self.dprint("{method} REQUEST: {url} for user {uname} with password {passwd} ".
                                format(method=method.upper(), url=self._url, uname=self._user, passwd=self._passwd))
                    response = method_to_call(self._url, headers=headers, data=json_request, verify=self.verify_ssl,
                                              timeout=self.timeout)
            elif "logout" in self._url:
                if self.api_key_used:
                    iresponse = InterResponse()
                    return self._handle_response(iresponse)
                else:
                    self._session.headers = None
                    method_to_call = getattr(self._session, method)
                    self.dprint("{method} REQUEST: {url}".format(method=method.upper(), url=self._url, uname=self._user,
                                                                 passwd=self._passwd))
                    response = method_to_call(self._url, headers=headers, verify=self.verify_ssl, timeout=self.timeout)
            else:
                json_request = {}
                if params is not None:
                    json_request = params
                method_to_call = getattr(self._session, method)
                self.dprint("{method} REQUEST: {url}".format(method=method.upper(), url=self._url), json_request)
                response = method_to_call(self._url, headers=headers, data=json.dumps(json_request),
                                          verify=self.verify_ssl, timeout=self.timeout)
        except ReqConnError as err:
            self.dprint("Connection error: {err_type} {err}\n\n".format(err_type=type(err), err=err))
            raise FGTConnectionError(err)
        except ValueError as err:
            self.dprint("Value error: {err_type} {err}\n\n".format(err_type=type(err), err=err))
            raise FGTValueError(err)
        except KeyError as err:
            self.dprint("Key error in response: {err_type} {err}\n\n".format(err_type=type(err), err=err))
            raise FGTResponseNotFormedCorrect(err)
        except Exception as err:
            self.dprint("Response parser error: {err_type} {err}".format(err_type=type(err), err=err))
            raise FGTBaseException(err)
        return self._handle_response(response)

    def login(self):
        self._session = requests.session()
        login_response = self.post("logincheck")
        if login_response[0] == 0:
            return self
        elif login_response[0] == -1 and login_response[1]["message"] == "Two-factor Required":
            # todo send a login again after getting the 2FA key
            pass
        else:
            self._sid = None
            return self

    def logout(self):
        return self.post("logout")

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()

    def common_datagram_params(self, url, *args, **kwargs):
        self._set_url(url, *args)
        params = {}
        if kwargs:
            keylist = list(kwargs)
            for k in keylist:
                kwargs[k.replace("__", "-")] = kwargs.pop(k)
            params.update(kwargs)
        return params

    def get(self, url, *args, **kwargs):
        return self._post_request("get", url, self.common_datagram_params(url, *args, **kwargs))

    def post(self, url, *args, **kwargs):
        return self._post_request("post", url, self.common_datagram_params(url, *args, **kwargs))

    def put(self, url, *args, **kwargs):
        return self._post_request("put", url, self.common_datagram_params(url, *args, **kwargs))

    def delete(self, url, *args, **kwargs):
        return self._post_request("delete", url, self.common_datagram_params(url, *args, **kwargs))

    def __str__(self):
        if self.sid is not None:
            return "FortiOS instance connnected to {host}.".format(host=self._host)
        return "FortiOS object with no valid connection to a FortiOS appliance."

    def __repr__(self):
        if self.sid is not None:
            return "{classname}(host={host}, pwd omitted, debug={debug}, use_ssl={use_ssl}, " \
                   "verify_ssl={verify_ssl}, timeout={timeout})".format(classname=self.__class__.__name__,
                                                                        host=self._host, debug=self._debug,
                                                                        use_ssl=self._use_ssl, timeout=self._timeout,
                                                                        verify_ssl=self._verify_ssl)
        return "FortiOS object with no valid connection to a FortiOS appliance."
