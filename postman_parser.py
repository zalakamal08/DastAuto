# pentester_project/postman_parser.py
import json
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from state import HttpRequest # Assuming HttpRequest is in state.py

class PostmanParser:
    def __init__(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8') as f: # Ensure utf-8
                self.collection = json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Postman collection file not found: {file_path}")
        except json.JSONDecodeError:
            raise ValueError(f"Invalid JSON in Postman collection: {file_path}")

    def extract_requests(self) -> List[HttpRequest]:
        """Extracts all requests from the Postman collection and converts them to HttpRequest objects."""
        raw_requests = []
        self._parse_item_group(self.collection.get("item", []), raw_requests)
        
        http_requests = []
        for i, postman_item_with_metadata in enumerate(raw_requests): # postman_item is now the item itself
            req_name = postman_item_with_metadata.get("name", f"Unnamed Request {i+1}")
            try:
                # Pass the whole item, not just item["request"] to preserve name
                http_req = self._convert_to_http_request(postman_item_with_metadata) 
                if http_req: 
                    http_requests.append(http_req)
            except Exception as e:
                print(f"Warning: Could not parse request '{req_name}': {e}")
        return http_requests

    def _parse_item_group(self, items: List[Dict[str, Any]], extracted_requests: List[Dict[str, Any]]):
        """Recursively parses items and item groups in the collection."""
        for item in items:
            if "request" in item and isinstance(item.get("request"), dict):
                # It's a request, add the whole item to preserve name at top level
                extracted_requests.append(item) 
            elif "item" in item and isinstance(item.get("item"), list):
                # It's a folder/group, recurse
                self._parse_item_group(item.get("item", []), extracted_requests)

    def _parse_url(self, url_data, request_name):
        from urllib.parse import urlparse, parse_qs, urlunparse
        if isinstance(url_data, str): 
            parsed_url = urlparse(url_data)
            base_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, '', '', ''))
            query_params = parse_qs(parsed_url.query)
            params = {k: v[0] if len(v) == 1 else v for k, v in query_params.items()}
            return base_url, params
        elif isinstance(url_data, dict): 
            raw_url_str = url_data.get("raw", "")
            query_params_from_raw = {}
            if raw_url_str:
                parsed_url = urlparse(raw_url_str)
                base_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, '', '', ''))
                query_params_from_raw = parse_qs(parsed_url.query)
            else: 
                protocol = url_data.get("protocol", "http")
                host_parts = url_data.get("host", ["localhost"])
                host = ".".join(host_parts) if isinstance(host_parts, list) else str(host_parts)
                path_parts = url_data.get("path", [])
                path_str = ""
                if isinstance(path_parts, list):
                    path_str = "/" + "/".join(str(p) for p in path_parts)
                elif isinstance(path_parts, str):
                    path_str = "/" + path_parts if not path_parts.startswith("/") else path_parts
                base_url = f"{protocol}://{host}{path_str}"
            params = {}
            for q_param in url_data.get("query", []):
                if not q_param.get("disabled"):
                    params[q_param.get("key")] = q_param.get("value", "")
            for k, v_list in query_params_from_raw.items():
                if k not in params: 
                    params[k] = v_list[0] if len(v_list) == 1 else v_list
            return base_url, params
        else:
            print(f"Warning: URL format not recognized for request '{request_name}'. Skipping.")
            return None, None

    def _parse_body(self, pm_request_data, headers, request_name):
        import json
        body_data = pm_request_data.get("body")
        data_payload: Any = None
        json_payload = None
        if body_data and body_data.get("mode"):
            mode = body_data.get("mode")
            if mode == "raw":
                raw_body = body_data.get("raw", "")
                content_type = headers.get("Content-Type", "").lower()
                if "application/json" in content_type:
                    try:
                        json_payload = json.loads(raw_body)
                    except json.JSONDecodeError:
                        data_payload = raw_body 
                        print(f"Warning: Content-Type is application/json but body is not valid JSON for '{request_name}'. Treating as raw text.")
                else:
                    data_payload = raw_body
            elif mode == "urlencoded":
                form_data = {}
                for param in body_data.get("urlencoded", []):
                    if not param.get("disabled"):
                        form_data[param.get("key")] = param.get("value")
                data_payload = form_data 
                if "Content-Type" not in headers: 
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
            elif mode == "formdata": 
                form_data_parts = {}
                for param in body_data.get("formdata", []):
                     if not param.get("disabled") and param.get("type", "text") == "text":
                        form_data_parts[param.get("key")] = param.get("value")
                data_payload = form_data_parts
        return data_payload, json_payload

    def _convert_to_http_request(self, postman_item: Dict[str, Any]) -> Optional[HttpRequest]:
        """Converts a single Postman request item to our HttpRequest format."""
        pm_request_data = postman_item.get("request")
        if not pm_request_data:
            return None
        
        request_name = postman_item.get("name") # Get the name from the item level

        method = pm_request_data.get("method", "GET").upper()
        
        # URL and Query Params
        url_data = pm_request_data.get("url")
        base_url, params = self._parse_url(url_data, request_name)
        if not base_url:
            return None

        # Headers
        headers = {}
        for header in pm_request_data.get("header", []):
            if not header.get("disabled"):
                headers[header.get("key")] = header.get("value")
        
        # Body
        data_payload, json_payload = self._parse_body(pm_request_data, headers, request_name)
        
        return HttpRequest(
            name=request_name, # STORE THE NAME
            url=base_url, 
            method=method,
            headers=headers,
            params=params, 
            data=data_payload, 
            json_data=json_payload 
        )