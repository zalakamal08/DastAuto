import requests
import time
from state import HttpRequest, HttpResponse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_proxy_config():
    proxy_url = "http://127.0.0.1:8080"
    return {
        "http": proxy_url,
        "https": proxy_url,
    }

def handle_request_exception(e, response_time, msg):
    print(f"   {msg}")
    return HttpResponse(
        status_code=0,
        headers={},
        content="",
        response_time=response_time,
        error_message=msg
    )

class RequestExecutor:
    PROXIES = get_proxy_config()

    @staticmethod
    def execute_request(request_details: HttpRequest) -> HttpResponse:
        start_time = time.time()
        print(f"   Executing request via proxy: {RequestExecutor.PROXIES['http']}")
        try:
            response = requests.request(
                method=request_details.method.upper(),
                url=request_details.url,
                headers=request_details.headers,
                params=request_details.params,
                data=request_details.data if not request_details.json_data else None,
                json=request_details.json_data,
                timeout=30,
                allow_redirects=True,
                proxies=RequestExecutor.PROXIES,
                verify=False
            )
            response_time = time.time() - start_time
            return HttpResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                content=response.text,
                response_time=response_time
            )
        except requests.exceptions.ProxyError as e:
            response_time = time.time() - start_time
            return handle_request_exception(e, response_time, f"Proxy Error: {str(e)}. Ensure proxy at {RequestExecutor.PROXIES['http']} is running.")
        except requests.exceptions.SSLError as e:
            response_time = time.time() - start_time
            return handle_request_exception(e, response_time, f"SSL Error: {str(e)}. If using a proxy, ensure its CA certificate is trusted or `verify=False` is set.")
        except requests.exceptions.RequestException as e:
            response_time = time.time() - start_time
            return handle_request_exception(e, response_time, f"Request failed: {str(e)}")