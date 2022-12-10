#!/usr/bin/env python

import logging
import json
import requests
import uuid
from requests.exceptions import ConnectionError as ReqConnError, ConnectTimeout as ReqConnTimeout


class FGTBaseException(Exception):
    """Wrapper to catch the unexpected"""

    def __init__(self, msg):
        super(FGTBaseException, self).__init__(msg)


class FGTValidSessionException(FGTBaseException):
    """Raised when a call is made, but there is no valid login instance"""

    def __init__(self, method, url, **kwargs):
        if kwargs:
            msg = "A call using the {method} method was requested to {url} on a FortiOS instance that had no " \
                  "valid session or was not connected. Parameters were:\n{params}". \
                format(method=method, url=url, params=kwargs)
        else:
            msg = "A call using the {method} method was requested to {url} on a FortiOS instance that had no " \
                  "valid session or was not connected.". \
                format(method=method, url=url)
        super(FGTValidSessionException, self).__init__(msg)


class FGTValueError(ValueError):
    """Catch value errors such as bad timeout values"""

    def __init__(self, msg):
        super(FGTValueError, self).__init__(msg)


class FGTResponseNotFormedCorrect(KeyError):
    """Used only if a response does not have a standard format as based on FGT response guidelines"""

    def __init__(self, msg):
        super(FGTResponseNotFormedCorrect, self).__init__(msg)


class FGTConnectionError(ReqConnError):
    """Wrap requests Connection error so requests is not a dependency outside this module"""

    def __init__(self, msg):
        super(FGTConnectionError, self).__init__(msg)


class FGTConnectTimeout(ReqConnTimeout):
    """Wrap requests Connection timeout error so requests is not a dependency outside this module"""

    def __init__(self, *args, **kwargs):
        super(FGTConnectTimeout, self).__init__(*args, **kwargs)


class RequestResponse(object):
    """Simple wrapper around the request response object so debugging and logging can be done with simplicity"""

    def __init__(self):
        self._request_string = "REQUEST:"
        self._response_string = "RESPONSE:"
        self._request_json = None
        self._response_json = None
        self._error_msg = None

    def reset(self):
        self.error_msg = None
        self.response_json = None
        self.request_json = None
        self._request_string = "REQUEST:"

    @property
    def request_string(self):
        return self._request_string

    @request_string.setter
    def request_string(self, val):
        self._request_string = val

    @property
    def response_string(self):
        return self._response_string

    @property
    def request_json(self):
        return self._request_json

    @request_json.setter
    def request_json(self, val):
        self._request_json = val

    @property
    def response_json(self):
        return self._response_json

    @response_json.setter
    def response_json(self, val):
        self._response_json = val

    @property
    def error_msg(self):
        return self._error_msg

    @error_msg.setter
    def error_msg(self, val):
        self._error_msg = val


class FortiGate(object):

    def __init__(self, host, user=None, passwd=None, debug=False, use_ssl=True, verify_ssl=False, timeout=300,
                 disable_request_warnings=False, apikey=None, old_password="", new_password=""):
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
        self._old_passwd = old_password
        self._new_passwd = new_password
        self._api_key_used = True if passwd is None and apikey is not None else False
        self._passwd = passwd if passwd is not None else apikey
        self._req_resp_object = RequestResponse()
        self._logger = None
        self._fgt_login = None

        if disable_request_warnings:
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    @property
    def api_key_used(self):
        return self._api_key_used

    @api_key_used.setter
    def api_key_used(self, val):
        self._api_key_used = val

    @property
    def old_password(self):
        return self._old_passwd

    @old_password.setter
    def old_password(self, val):
        self._old_passwd = val

    @property
    def new_password(self):
        return self._new_passwd

    @new_password.setter
    def new_password(self, val):
        self._new_passwd = val

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

    @property
    def fgt_session(self):
        if self._session is None:
            with requests.sessions.session() as sess:
                self._session = sess
        return self._session

    @property
    def req_resp_object(self):
        return self._req_resp_object

    def getLog(self, loggername="fortinet", lvl=logging.INFO):
        if self._logger is not None:
            return self._logger
        else:
            self._logger = logging.getLogger(loggername)
            self._logger.setLevel(lvl)
            return self._logger

    def resetLog(self):
        self._logger = None

    def addHandler(self, handler):
        if self._logger is not None:
            self._logger.addHandler(handler)

    def removeHandler(self, handler):
        if self._logger is not None:
            self._logger.removeHandler(handler)

    def dlog(self):
        if self._logger is not None:
            if self.req_resp_object.error_msg is not None:
                self._logger.log(logging.INFO, self.req_resp_object.error_msg)
                return
            self._logger.log(logging.INFO, self.req_resp_object.request_string)
            if self.req_resp_object.request_json is not None:
                self._logger.log(logging.INFO, self.jprint(self.req_resp_object.request_json))
            self._logger.log(logging.INFO, self.req_resp_object.response_string)
            if self.req_resp_object.response_json is not None:
                self._logger.log(logging.INFO, self.jprint(self.req_resp_object.response_json))

    @staticmethod
    def jprint(json_obj):
        try:
            return json.dumps(json_obj, indent=2, sort_keys=True)
        except TypeError as te:
            return json.dumps({"Type Information": te.args})

    def dprint(self):
        self.dlog()
        if not self.debug:
            return
        if self.req_resp_object.error_msg is not None:
            print(self.req_resp_object.error_msg)
            return
        print("-" * 100 + "\n")
        print(self.req_resp_object.request_string)
        if self.req_resp_object.request_json is not None:
            print(self.jprint(self.req_resp_object.request_json))
        print("\n" + self.req_resp_object.response_string)
        if self.req_resp_object.response_json is not None:
            print(self.jprint(self.req_resp_object.response_json))
        print("\n" + "-" * 100 + "\n")

    def _set_url(self, url, *args):
        if self.api_key_used:
            self.fgt_session.headers.update({"Authorization": "Bearer {apikey}".
                                            format(apikey=self._passwd if self.api_key_used else "")})
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

    def _handle_response(self, resp):
        try:
            response = resp.json()
        except:
            # response is not able to be decoded into json return 100 as a code and the entire response object
            return 100, resp
        try:
            if "text" in response:
                if type(response["text"]["results"]) is list:
                    result = response["text"]["results"][0]
                else:
                    result = response["text"]["results"]
                self.req_resp_object.response_json = result
                self.dprint()
                if "http_status" in response:
                    return response["http_status"], result
                else:
                    return response["status"], result
            else:
                self.req_resp_object.response_json = response
                self.dprint()
                if "http_status" in response:
                    return response["http_status"], response
                else:
                    return response["status"], response
        except IndexError as err:
            msg = "Index error in response: {err_type} {err}\n\n".format(err_type=type(err), err=err)
            self.req_resp_object.error_msg = msg
            self.dprint()
            raise FGTResponseNotFormedCorrect(msg)
        except Exception as e:
            print("Response parser error: {err_type} {err}".format(err_type=type(e), err=e))
            return -1, e

    def add_header(self, header_dict):
        if isinstance(header_dict, dict):
            self.fgt_session.headers.update(header_dict)

    def remove_header(self, key_to_remove):
        self.fgt_session.headers.pop(key_to_remove, None)

    def _post_request(self, method, url, params):
        self.req_resp_object.reset()
        if self.sid is None:
            raise FGTValidSessionException(method, params)
        self._update_request_id()
        json_request = {}
        response = None
        try:
            if params is not None:
                json_request = params
            method_to_call = getattr(self.fgt_session, method)
            self.req_resp_object.request_string = "{method} REQUEST: {url}".format(method=method.upper(), url=self._url)
            self.req_resp_object.request_json = json_request
            if len(json_request) == 0:
                response = method_to_call(self._url, headers=self.fgt_session.headers, verify=self.verify_ssl,
                                          timeout=self.timeout)
            else:
                response = method_to_call(self._url, headers=self.fgt_session.headers, data=json.dumps(json_request),
                                          verify=self.verify_ssl, timeout=self.timeout)
        except ReqConnError as err:
            msg = "Connection error: {err_type} {err}\n\n".format(err_type=type(err), err=err)
            self.req_resp_object.error_msg = msg
            self.dprint()
            raise FGTConnectionError(msg)
        except ValueError as err:
            msg = "Value error: {err_type} {err}\n\n".format(err_type=type(err), err=err)
            self.req_resp_object.error_msg = msg
            self.dprint()
            raise FGTValueError(msg)
        except KeyError as err:
            msg = "Key error in response: {err_type} {err}\n\n".format(err_type=type(err), err=err)
            self.req_resp_object.error_msg = msg
            self.dprint()
            raise FGTResponseNotFormedCorrect(msg)
        except Exception as err:
            msg = "Response parser error: {err_type} {err}".format(err_type=type(err), err=err)
            self.req_resp_object.error_msg = msg
            self.dprint()
            raise FGTBaseException(msg)
        return self._handle_response(response)

    def login(self):
        self._session = self.fgt_session
        self._fgt_login = self.FortiGateLogin(self._host, self._user, self._passwd, self._api_key_used, self._use_ssl,
                                              self.verify_ssl, self.timeout, self.old_password, self.new_password,
                                              self._req_resp_object, self.fgt_session, self.dprint)
        if self._fgt_login.login_code == 5:
            self._passwd = self._fgt_login.session_key
            self.api_key_used = True
            self.sid = self._fgt_login.session_id
            self.req_id = self._fgt_login.request_id
        elif self._fgt_login.login_code == 1:
            # legacy login taking place
            self.api_key_used = False
            self.sid = self._fgt_login.session_id
            self.req_id = self._fgt_login.request_id
        return self

    def logout(self):
        self.req_resp_object.reset()
        self._update_request_id()
        if self.api_key_used:
            self.fgt_session.headers.update({"Authorization": "Bearer {apikey}".
                                            format(apikey=self._passwd if self.api_key_used else "")})
            self._url = "{proto}://{host}/api/v2/authentication".\
                format(proto="https" if self._use_ssl else "http", host=self._host)
            self.req_resp_object.request_string = "{method} REQUEST: {url}".format(method="DELETE", url=self._url)
        else:
            self._url = "{proto}://{host}/logout".format(proto="https" if self._use_ssl else "http", host=self._host)
            self.req_resp_object.request_string = "{method} REQUEST: {url}".format(method="POST", url=self._url)
        try:
            self.sid = None
            self.req_id = 0
            if self.api_key_used:
                response = self.fgt_session.delete(self._url, verify=self._verify_ssl, timeout=self._timeout)
                self.req_resp_object.response_json = response.json()
                self.dprint()
            else:
                # legacy logout taking place
                response = self.fgt_session.post(self._url, verify=self._verify_ssl, timeout=self._timeout)
                if response.status_code == 200:
                    logout_json = {"status_code": response.status_code, "message": "Logout Successful"}
                    self.req_resp_object.response_json = logout_json
                    self.dprint()
                else:
                    logout_json = {"status_code": response.status_code, "message": "Logout Failed"}
                    self.req_resp_object.response_json = logout_json
                    self.dprint()
        except Exception as err:
            msg = "Response parser error: {err_type} {err}".format(err_type=type(err), err=err)
            self.req_resp_object.error_msg = msg
            self.dprint()
            raise FGTBaseException(msg)

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()

    def common_datagram_params(self, url, *args, **kwargs):
        self._set_url(url, *args)
        params = {}
        if kwargs:
            key_list = list(kwargs)
            for k in key_list:
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

    class FortiGateLogin(object):

        def __init__(self, host, user, passwd, api_key_used, use_ssl, verify_ssl, timeout,
                     old_password, new_password, req_resp_obj: RequestResponse, session_ptr: requests.sessions.Session,
                     print_ptr):
            self._url = "{proto}://{host}/api/v2/authentication".format(proto="https" if use_ssl else "http", host=host)
            self._host = host
            self._user = user
            self._timeout = timeout
            self._verify_ssl = verify_ssl
            self._use_ssl = use_ssl
            self._api_key = passwd
            self._passwd = passwd
            self._api_key_used = api_key_used
            self._old_passwd = old_password
            self._new_passwd = new_password
            self._session_key = None
            self._session_id = None
            self._req_id = 0
            self._login_message = "NA"
            self._login_error = ""
            self._login_code = 1
            self._req_resp_obj = req_resp_obj
            self._session_ptr = session_ptr
            self._print_ptr = print_ptr

            self._do_login()

        def _update_request_id(self):
            self._req_id += 1

        @property
        def session_key(self):
            return self._session_key

        @property
        def session_id(self):
            return self._session_id

        @property
        def request_id(self):
            return self._req_id

        @property
        def login_message(self):
            return self._login_message

        @property
        def login_code(self):
            return self._login_code

        @property
        def login_error(self):
            return self._login_error

        def _send_login_info(self, json_request):
            login_response = self._post_login_request(json_request)
            try:
                self._req_resp_obj.response_json = login_response.json()
                self._print_ptr()
            except json.JSONDecodeError as err:
                # possible legacy login will get a 401 here with no JSON response
                self._req_resp_obj.response_json = {"status": login_response.status_code,
                                                    "reason": login_response.reason}
                self._print_ptr()
            return login_response

        def _do_login(self):
            if self._api_key_used:
                self._session_key = self._passwd
                self._login_message = "API Key used at login"
                self._session_id = str(uuid.uuid4())
                self._login_code = 5
                return

            json_request = {
                "username": self._user,
                "secretkey": self._passwd,
                "ack_pre_disclaimer": True,
                "ack_post_disclaimer": True,
                "request_key": True
            }
            response = self._send_login_info(json_request)
            if 400 <= response.status_code < 500:
                # likely an old FGT - have to default back to old login ways
                json_request = {
                    "username": self._user,
                    "secretkey": self._old_passwd,
                    "is_deprecated_login": True
                }
                self._send_login_info(json_request)
            else:
                if self.login_code == 5:
                    self._session_id = str(uuid.uuid4())
                elif self._login_code == 4:
                    json_request = {
                        "username": self._user,
                        "secretkey": self._old_passwd,
                        "new_password1": self._new_passwd,
                        "new_password2": self._new_passwd,
                        "ack_pre_disclaimer": True,
                        "ack_post_disclaimer": True,
                        "request_key": True
                    }
                    self._send_login_info(json_request)
                    if self.login_code == 5:
                        self._session_id = str(uuid.uuid4())

        def _set_login_values_deprecated(self, response):
            # response first character defines if login was successful
            # 0 Log in failure. Most likely an incorrect username/password combo.
            # 1 Successful log in - will actually represent legacy login since this is an internal only result
            # 2 Admin is now locked out
            # 3 Two-factor Authentication is needed - will not be implemented

            if response.status_code == 200:
                if response.text == "" or response.text[0] == "0":
                    self._login_code = -1
                    self._login_message = "Failed Login - Most likely incorrect username/password used"
                    self._session_key = ""
                    self._login_error = "Failed Login - Most likely incorrect username/password used"
                elif response.text[0] == "1":
                    self._session_id = ""
                    for cookie in response.cookies:
                        if cookie.name == "ccsrftoken":
                            csrftoken = cookie.value[1:-1]
                            self._session_ptr.headers.update({"X-CSRFTOKEN": csrftoken})
                        if "APSCOOKIE_" in cookie.name:
                            self._session_id = cookie.value
                    self._login_code = 1
                    self._login_message = "LOGIN_SUCCESS"
                    self._session_key = "LegacyLogin_Key"
                    self._login_error = ""
                else:
                    self._login_code = 0
                    self._login_message = "LOGIN_INVALID"
                    self._session_key = ""
                    self._login_error = "Invalid Login. A response that was not expected was returned during login"
            else:
                self._login_code = 0
                self._login_message = "LOGIN_INVALID"
                self._session_key = ""
                self._login_error = "Invalid Login. A response with status code {code} was returned".\
                    format(code=response.status_code)

        def _set_login_values(self, response):
            # status code defines if login was successful
            # -2 Log in failure - LOGIN_ACCEPT_PRE_LOGIN_DISCLAIMER
            # -1 LOGIN_FAILED
            # 0 LOGIN_INVALID
            # 1 Internal Use Only
            # 2 LOGIN_TFA - login process is still in progress - Unless push notifications are enabled, the next API
            # call must include the session key/cookie and the parameter token_code set to the token code.
            # 3 LOGIN_ACCEPT_POST_LOGIN_DISCLAIMER - login is still in progress - The post disclaimer must be accepted.
            # In the next API call, the session key/cookie and ack_post_disclaimer=true must be provided. By default, in
            # this module it IS set to True
            # 4 LOGIN_CHANGE_PWD_NEEDED - the login is still in progress - A password change is required. In the next
            # API call, the session key/cookie, secretkey=<old-password>, new_password1=<new-password>,
            # and new_password2=<new-password> must be provided.
            # 5 LOGIN_SUCCESS
            # response looks like this
            # {
            #     "status_code": 5,
            #     "status_message": "LOGIN_SUCCESS",
            #     "session_key": "3z6j7GhyxjGtcjNj0Gw797zb403Qgq",
            #     "session_key_timeout": "5"
            # }

            if response.status_code == 200:
                self._login_code = response.json().get("status_code", 1)
                self._login_message = "NA" if response.json().get("status_code", 1) == 1 else \
                    response.json().get("status_message", "")
                self._session_key = response.json().get("session_key", "")
                self._login_error = response.json().get("error", "")
            elif 400 <= response.status_code < 500:
                # look for legacy login issues
                self._login_code = "NA"
                self._login_message = "Possible legacy login requirement encountered"
                self._login_code = 1
                self._session_key = None
                self._login_error = ""
            else:
                msg = "Login failed and received a status code of {status}".format(status=response.status_code)
                raise FGTConnectionError(msg)

        def _post_login_request_deprecated(self):
            self._url = "{proto}://{host}/logincheck".format(proto="https" if self._use_ssl else "http",
                                                             host=self._host)
            self._req_resp_obj.reset()
            self._update_request_id()
            self._session_ptr.headers.update({"Content-Type": "application/json"})
            response = None
            try:
                json_request = "username={uname}&secretkey={pword}&ajax=1".format(uname=self._user, pword=self._passwd)
                self._req_resp_obj.request_string = "{method} REQUEST: {url} for user {uname} with " \
                                                    "password {passwd}".format(method="POST", url=self._url,
                                                                               uname=self._user, passwd=self._passwd)
                response = self._session_ptr.post(self._url, verify=self._verify_ssl, timeout=self._timeout,
                                                  data=json_request)
                # set the properties of the login object so the FGT can read them
                self._set_login_values_deprecated(response)
                return response
            except FGTConnectionError as err:
                self._req_resp_obj.error_msg = str(err)
                self._print_ptr()
                raise FGTConnectionError(self._req_resp_obj.error_msg)
            except ReqConnError as err:
                msg = "Connection error: {err_type} {err}\n\n".format(err_type=type(err), err=err)
                self._req_resp_obj.error_msg = msg
                self._print_ptr()
                raise FGTConnectionError(msg)
            except json.JSONDecodeError as err:
                msg = "JSON decode error in response: {err_type} {err}\n\n".format(err_type=type(err), err=err)
                self._req_resp_obj.error_msg = msg
                self._print_ptr()
                raise FGTValueError(msg)
            except ValueError as err:
                msg = "Value error: {err_type} {err}\n\n".format(err_type=type(err), err=err)
                self._req_resp_obj.error_msg = msg
                self._print_ptr()
                raise FGTValueError(msg)
            except KeyError as err:
                msg = "Key error in response: {err_type} {err}\n\n".format(err_type=type(err), err=err)
                self._req_resp_obj.error_msg = msg
                self._print_ptr()
                raise FGTResponseNotFormedCorrect(msg)
            except IndexError as err:
                msg = "Index error in response: {err_type} {err}\n\n".format(err_type=type(err), err=err)
                self._req_resp_obj.error_msg = msg
                self._print_ptr()
                raise FGTResponseNotFormedCorrect(msg)
            except Exception as err:
                msg = "Response parser error: {err_type} {err}".format(err_type=type(err), err=err)
                self._req_resp_obj.error_msg = msg
                self._print_ptr()
                raise FGTBaseException(msg)

        def _post_login_request(self, json_request):
            if json_request.get("is_deprecated_login", False):
                # legacy login found
                response = self._post_login_request_deprecated()
                return response
            else:
                self._req_resp_obj.reset()
                self._update_request_id()
                self._session_ptr.headers.update({"Content-Type": "json", "accept": "application/json"})
                response = None
                try:
                    self._req_resp_obj.request_string = "{method} REQUEST: {url} for user {uname} with " \
                                                        "password {passwd}".format(method="POST", url=self._url,
                                                                                   uname=self._user, passwd=self._passwd)
                    response = self._session_ptr.post(self._url, verify=self._verify_ssl, timeout=self._timeout,
                                                      json=json_request)

                    # set the properties of the login object so the FGT can read them
                    self._set_login_values(response)
                    return response
                except FGTConnectionError as err:
                    self._req_resp_obj.error_msg = str(err)
                    self._print_ptr()
                    raise FGTConnectionError(self._req_resp_obj.error_msg)
                except ReqConnError as err:
                    msg = "Connection error: {err_type} {err}\n\n".format(err_type=type(err), err=err)
                    self._req_resp_obj.error_msg = msg
                    self._print_ptr()
                    raise FGTConnectionError(msg)
                except json.JSONDecodeError as err:
                    msg = "JSON decode error in response: {err_type} {err}\n\n".format(err_type=type(err), err=err)
                    self._req_resp_obj.error_msg = msg
                    self._print_ptr()
                    raise FGTValueError(msg)
                except ValueError as err:
                    msg = "Value error: {err_type} {err}\n\n".format(err_type=type(err), err=err)
                    self._req_resp_obj.error_msg = msg
                    self._print_ptr()
                    raise FGTValueError(msg)
                except KeyError as err:
                    msg = "Key error in response: {err_type} {err}\n\n".format(err_type=type(err), err=err)
                    self._req_resp_obj.error_msg = msg
                    self._print_ptr()
                    raise FGTResponseNotFormedCorrect(msg)
                except Exception as err:
                    msg = "Response parser error: {err_type} {err}".format(err_type=type(err), err=err)
                    self._req_resp_obj.error_msg = msg
                    self._print_ptr()
                    raise FGTBaseException(msg)
