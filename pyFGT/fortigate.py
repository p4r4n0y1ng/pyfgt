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
            msg = f"A call using the {method} method was requested to {url} on a FortiOS instance that had no " \
                  f"valid session or was not connected. Parameters were:\n{kwargs}"
        else:
            msg = f"A call using the {method} method was requested to {url} on a FortiOS instance that had no " \
                  f"valid session or was not connected."
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
            self.fgt_session.headers.update({"Authorization": f"Bearer {self._fgt_login.api_key}"})
        elif self._fgt_login.session_token is not None:
            self.fgt_session.headers.update({"Authorization": f"Bearer {self._fgt_login.session_token}"})
        else:
            #CSRF token being used
            self.fgt_session.headers.update({"X-CSRFTOKEN": self._fgt_login.csrf_token})
        if url[0] == "/":
            url = url[1:]
        proto = "https" if self._use_ssl else "http"
        self._url = f"{proto}://{self._host}/api/v2/{url}"
        if len(args) > 0:
            self._url = f"{self._url}?"
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
            msg = f"Index error in response: {type(err)} {err}\n\n"
            self.req_resp_object.error_msg = msg
            self.dprint()
            raise FGTResponseNotFormedCorrect(msg)
        except Exception as e:
            print(f"Response parser error: {type(e)} {e}")
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
            self.req_resp_object.request_string = f"{method.upper()} REQUEST: {self._url}"
            self.req_resp_object.request_json = json_request
            if len(json_request) == 0:
                response = method_to_call(self._url, headers=self.fgt_session.headers, verify=self.verify_ssl,
                                          timeout=self.timeout)
            else:
                response = method_to_call(self._url, headers=self.fgt_session.headers, data=json.dumps(json_request),
                                          verify=self.verify_ssl, timeout=self.timeout)
        except ReqConnError as err:
            msg = f"Connection error: {type(err)} {err}\n\n"
            self.req_resp_object.error_msg = msg
            self.dprint()
            raise FGTConnectionError(msg)
        except ValueError as err:
            msg = f"Value error: {type(err)} {err}\n\n"
            self.req_resp_object.error_msg = msg
            self.dprint()
            raise FGTValueError(msg)
        except KeyError as err:
            msg = f"Key error in response: {type(err)} {err}\n\n"
            self.req_resp_object.error_msg = msg
            self.dprint()
            raise FGTResponseNotFormedCorrect(msg)
        except Exception as err:
            msg = f"Response parser error: {type(err)} {err}"
            self.req_resp_object.error_msg = msg
            self.dprint()
            raise FGTBaseException(msg)
        return self._handle_response(response)

    def login(self):
        self._session = self.fgt_session
        self._fgt_login = self.FortiGateLogin(self._host, self._user, self._passwd, self._api_key_used, self._use_ssl,
                                              self.verify_ssl, self.timeout, self._req_resp_object, self.fgt_session, self.dprint)
        
        self.sid = self._fgt_login.session_id
        self.req_id = self._fgt_login.request_id
        return self

    def logout(self):
        self.req_resp_object.reset()
        self._update_request_id()
        if self._fgt_login.session_token is None and self._fgt_login.csrf_token is None and not self._fgt_login._api_key_used:
            # houston we have a problem - why are we here
            logout_json = {"status_code": -1, "message": "No current token or API Key to utilize to logout with. This code should not have been reached. If session alive it will be closed"}
            self.req_resp_object.response_json = logout_json
            self.dprint()
            try:
                self._session.close()
            except:
                pass
            return
        if self._fgt_login.session_token is not None:
            self.fgt_session.headers.update({"Authorization": f"Bearer {self._fgt_login.api_key if self._api_key_used else self._fgt_login.session_token}"})
            proto = "https" if self._use_ssl else "http"
            self._url = f"{proto}://{self._host}/api/v2/authentication"
            self.req_resp_object.request_string = f"DELETE REQUEST: {self._url}"
        elif self._fgt_login._api_key_used:
            # api key used
            self.req_resp_object.request_string = f"API Key Utilized - Session Closure occurring"
        else:
            # legacy logout
            proto = "https" if self._use_ssl else "http"
            self._url = f"{proto}://{self._host}/logout"
            self.req_resp_object.request_string = f"POST REQUEST: {self._url}"
        try:
            self.sid = None
            self.req_id = 0
            if self._fgt_login.session_token is not None:
                response = self.fgt_session.delete(self._url, verify=self._verify_ssl, timeout=self._timeout)
                self.req_resp_object.response_json = response.json()
            elif self._fgt_login._api_key_used:
                # api key logout - session just needs to die which is done in the finally
                logout_json = {"status_code": 200, "message": "Logout Successful - API Key Used. Session will be closed."}
                self.req_resp_object.response_json = logout_json
            else:
                # legacy logout taking place
                response = self.fgt_session.post(self._url, verify=self._verify_ssl, timeout=self._timeout)
                if response.status_code == 200:
                    logout_json = {"status_code": response.status_code, "message": "Logout Successful"}
                    self.req_resp_object.response_json = logout_json
                else:
                    logout_json = {"status_code": response.status_code, "message": "Logout Failed"}
                    self.req_resp_object.response_json = logout_json
        except Exception as err:
            msg = f"Response parser error: {type(err)} {err}"
            self.req_resp_object.error_msg = msg
            raise FGTBaseException(msg)
        finally:
            self.dprint()
            self._session.close()
            self._fgt_login._api_key = None
            self._fgt_login._csrf_token = None
            self._fgt_login._session_token = None

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
            return f"FortiOS instance connnected to {self._host}."
        return "FortiOS object with no valid connection to a FortiOS appliance."

    def __repr__(self):
        if self.sid is not None:
            return f"{self.__class__.__name__}(host={self._host}, pwd omitted, debug={self._debug}, use_ssl={self._use_ssl}, " \
                   f"verify_ssl={self._verify_ssl}, timeout={self._timeout})"
        return "FortiOS object with no valid connection to a FortiOS appliance."

    class FortiGateLogin(object):

        def __init__(self, host, user, passwd, api_key_used, use_ssl, verify_ssl, timeout,
                     req_resp_obj: RequestResponse, session_ptr: requests.sessions.Session,
                     print_ptr):
            proto = "https" if use_ssl else "http"
            self._url = f"{proto}://{host}/api/v2/authentication"
            self._host = host
            self._user = user
            self._timeout = timeout
            self._verify_ssl = verify_ssl
            self._use_ssl = use_ssl
            self._passwd = passwd
            self._api_key_used = api_key_used
            self._csrf_token = None
            self._session_token = None
            self._api_key = passwd if api_key_used else None
            self._session_id = None
            self._req_id = 0
            self._login_message = "NA"
            self._req_resp_obj = req_resp_obj
            self._session_ptr = session_ptr
            self._print_ptr = print_ptr

            self._do_login()

        def _update_request_id(self):
            self._req_id += 1

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
        def csrf_token(self):
            return self._csrf_token

        @property
        def session_token(self):
            return self._session_token

        @property
        def api_key(self):
            return self._api_key
        
        def _send_login_info(self, json_request):
            login_response = self._post_login_request(json_request)
            try:
                self._req_resp_obj.response_json = login_response.json()
                self._print_ptr()
            except json.JSONDecodeError as err:
                # possible legacy login will get a 401 here with no JSON response
                self._req_resp_obj.response_json = {"status": login_response.status_code, "reason": login_response.reason}
                self._print_ptr()

        def _do_login(self):
            if self._api_key_used:
                # api key already set at instantiation - just return and write the messaging that API key is used
                self._login_message = "API Key used at login"
                self._session_id = str(uuid.uuid4())
                self._req_resp_obj.request_string = f"Login request to {self._url} not made purposefully. API Token will be utilized on each call."
                self._req_resp_obj.response_json = {"status": 0, "reason": "Using API Token"}
                self._print_ptr()
                return

            json_request = {
                "username": self._user,
                "password": self._passwd,
                "secretkey": self._passwd,
                "ack_post_disclaimer": True,
                "request_key": True
            }
            self._send_login_info(json_request)

        def _post_login_request(self, json_request):
            self._req_resp_obj.reset()
            self._update_request_id()
            self._session_ptr.headers.update({"Content-Type": "json", "accept": "application/json"})
            response = None
            try:
                self._req_resp_obj.request_string = f"POST REQUEST: {self._url} for user {self._user} with " \
                                                    f"password {self._passwd}"
                response = self._session_ptr.post(self._url, verify=self._verify_ssl, timeout=self._timeout,
                                                    json=json_request)

                if response.status_code == 200:
                    # if session_key response set the sesssion token and carry on (older FOS version)
                    self._session_token = response.json().get("session_key", None)
                    if self._session_token is None:
                        # Check for CSRF token in cookies (newer FortiOS versions)
                        for cookie in self._session_ptr.cookies:
                            if "ccsrf_token" in cookie.name.lower():
                                self._csrf_token = cookie.value
                    
                    if self._csrf_token is None and self._session_token is None:
                        self._login_message = "Login failed no CSRF Token or Session Key found."
                        raise FGTConnectionError(self.login_message)
                    else:
                        self._login_message = f"Login request response status code is 200. Token found as \
                            {self._csrf_token if self._csrf_token is not None else self._session_token}"
                        self._session_id = str(uuid.uuid4())
                else:
                    self._login_message = f"Login failed and received a status code of {response.status_code}"
                    raise FGTConnectionError(self.login_message)
                return response
            except FGTConnectionError as err:
                self._req_resp_obj.error_msg = str(err)
                self._print_ptr()
                raise FGTConnectionError(self._req_resp_obj.error_msg)
            except ReqConnError as err:
                msg = f"Connection error: {type(err)} {err}\n\n"
                self._req_resp_obj.error_msg = msg
                self._print_ptr()
                raise FGTConnectionError(msg)
            except json.JSONDecodeError as err:
                msg = f"JSON decode error in response: {type(err)} {err}\n\n"
                self._req_resp_obj.error_msg = msg
                self._print_ptr()
                raise FGTValueError(msg)
            except ValueError as err:
                msg = f"Value error: {type(err)} {err}\n\n"
                self._req_resp_obj.error_msg = msg
                self._print_ptr()
                raise FGTValueError(msg)
            except KeyError as err:
                msg = f"Key error in response: {type(err)} {err}\n\n"
                self._req_resp_obj.error_msg = msg
                self._print_ptr()
                raise FGTResponseNotFormedCorrect(msg)
            except Exception as err:
                msg = f"Response parser error: {type(err)} {err}"
                self._req_resp_obj.error_msg = msg
                self._print_ptr()
                raise FGTBaseException(msg)
