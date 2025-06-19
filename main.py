import asyncio
import argparse
from typing import Any, Optional, List
from pentester_graph import AutomatedPentesterGraph
from state import HttpRequest, VulnerabilityType, AnalysisVerdict
from config import GEMINI_API_KEY
from postman_parser import PostmanParser

def get_user_selection(prompt: str, options: list, allow_skip=False) -> Any:
    print(prompt)
    for i, option in enumerate(options):
        print(f"  {i+1}. {option}")
    if allow_skip:
        print(f"  {len(options)+1}. Skip this request")
    while True:
        try:
            choice = int(input(f"Enter your choice (1-{len(options) + (1 if allow_skip else 0)}): "))
            if 1 <= choice <= len(options):
                return options[choice-1]
            elif allow_skip and choice == len(options) + 1:
                return None
            else:
                print("Invalid choice. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def select_target_parameter(request: HttpRequest) -> Optional[str]:
    param_options = []
    param_sources = {}
    if request.params:
        for p_name in request.params.keys():
            param_options.append(f"{p_name} (URL Query Param)")
            param_sources[f"{p_name} (URL Query Param)"] = p_name
    if isinstance(request.data, dict):
        for p_name in request.data.keys():
            param_options.append(f"{p_name} (Form Data Param)")
            param_sources[f"{p_name} (Form Data Param)"] = p_name
    elif isinstance(request.data, str) and request.data:
        param_options.append(f"Entire Raw Body (Special Target: __RAW_BODY__)")
        param_sources[f"Entire Raw Body (Special Target: __RAW_BODY__)"] = "__RAW_BODY__"
    if request.json_data:
        for p_name in request.json_data.keys():
            param_options.append(f"{p_name} (JSON Body Key)")
            param_sources[f"{p_name} (JSON Body Key)"] = p_name
    if not param_options:
        print("  No easily identifiable parameters (query, form, top-level JSON, raw body) found in this request.")
        user_param = input("  Enter parameter name to target (or leave blank to skip parameter-specific test): ").strip()
        return user_param if user_param else None
    chosen_param_display = get_user_selection("Select the parameter to target:", param_options, allow_skip=True)
    if chosen_param_display:
        return param_sources[chosen_param_display]
    return None

def print_request_info(req_to_test: HttpRequest):
    print(f"  Method: {req_to_test.method}")
    print(f"  URL: {req_to_test.url}")
    if req_to_test.params: print(f"  Query Params: {req_to_test.params}")
    if req_to_test.data: print(f"  Data: {str(req_to_test.data)[:100]}...")
    if req_to_test.json_data: print(f"  JSON Data: {str(req_to_test.json_data)[:100]}...")

def print_vulnerability_summary(vulnerabilities_summary_output: List[str]):
    print("\n\n--- FINAL CONCISE VULNERABILITY SUMMARY ---")
    if vulnerabilities_summary_output:
        for line in vulnerabilities_summary_output:
            print(line)
    else:
        print("No high-confidence vulnerabilities were found in the selected tests.")
    print("\nAll selected tests from the Postman collection have been processed.")

async def process_requests(requests_from_collection, pentester_graph, vulnerability_types, max_attempts):
    vulnerabilities_summary_output = []
    for i, req_to_test in enumerate(requests_from_collection):
        print(f"\n--- Processing Request {i+1}/{len(requests_from_collection)}: '{req_to_test.name or req_to_test.url}' ---")
        print_request_info(req_to_test)
        print("\nSelect vulnerability type to test for this request:")
        chosen_vuln_type_enum_val = get_user_selection(
            "Available vulnerability types:",
            [vt.value for vt in vulnerability_types],
            allow_skip=True
        )
        if not chosen_vuln_type_enum_val:
            print("Skipping vulnerability scan for this request.")
            continue
        selected_vulnerability_type = VulnerabilityType(chosen_vuln_type_enum_val)
        print(f"\nSelect parameter to target for {selected_vulnerability_type.value}:")
        target_param_name = select_target_parameter(req_to_test)
        if not target_param_name:
            print(f"No specific parameter targeted for {selected_vulnerability_type.value} on this request. Skipping this specific test.")
            continue
        print(f"\n🚀 Starting test: {selected_vulnerability_type.value} on parameter '{target_param_name}' for '{req_to_test.name or req_to_test.url}'")
        final_state_for_test = await pentester_graph.run_test(
            target_request=req_to_test,
            vulnerability_type=selected_vulnerability_type,
            target_parameter=target_param_name,
            max_total_attempts=max_attempts
        )
        print(f"--- Finished test for Request '{req_to_test.name or req_to_test.url}', Param '{target_param_name}', Vuln '{selected_vulnerability_type.value}' ---")
        if final_state_for_test.vulnerabilities_found:
            for vuln_detail in final_state_for_test.vulnerabilities_found:
                if vuln_detail.get('analysis_verdict') == AnalysisVerdict.VULNERABLE.value and \
                   (vuln_detail.get('analysis_confidence', 0.0)) >= final_state_for_test.confidence_threshold_vulnerable:
                    api_name = vuln_detail.get('request_name', req_to_test.url)
                    param = vuln_detail.get('target_parameter', target_param_name)
                    vuln_name = vuln_detail.get('vulnerability_type', selected_vulnerability_type.value)
                    reason = final_state_for_test.executive_summary_reasoning or vuln_detail.get('concise_reason_for_vulnerability', "No specific reason provided.")
                    summary_line = f"{api_name} -> parameter '{param}' is vulnerable to -> {vuln_name} : {reason}"
                    vulnerabilities_summary_output.append(summary_line)
                    print(f"🔴 VULNERABILITY FOUND: {summary_line}")
    return vulnerabilities_summary_output

async def main():
    if not GEMINI_API_KEY:
        print("Error: Gemini API Key not configured. Exiting.")
        return
    parser = argparse.ArgumentParser(description="Automated Pentester using LangGraph and Postman.")
    parser.add_argument("postman_collection", help="Path to the Postman collection JSON file.")
    parser.add_argument(
        "--max_attempts",
        type=int,
        default=10,
        help="Maximum strategy/payload batch generation attempts per parameter per vulnerability type."
    )
    args = parser.parse_args()
    print(f"Loading Postman collection from: {args.postman_collection}")
    try:
        postman_parser = PostmanParser(args.postman_collection)
        requests_from_collection = postman_parser.extract_requests()
    except Exception as e:
        print(f"Error loading or parsing Postman collection: {e}")
        return
    if not requests_from_collection:
        print("No requests found in the Postman collection.")
        return
    print(f"\nFound {len(requests_from_collection)} requests in the collection.")
    pentester_graph = AutomatedPentesterGraph()
    vulnerability_types = list(VulnerabilityType)
    vulnerabilities_summary_output = await process_requests(
        requests_from_collection, pentester_graph, vulnerability_types, args.max_attempts
    )
    print_vulnerability_summary(vulnerabilities_summary_output)

if __name__ == "__main__":
    asyncio.run(main())