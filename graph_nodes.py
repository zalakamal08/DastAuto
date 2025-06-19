# pentester_project/graph_nodes.py
from typing import Optional, List, Any, Dict # Added Dict
from state import PentestState, HttpRequest, AnalysisVerdict, AttemptDetail
from http_utils import RequestExecutor
from llm_agents import DynamicPayloadGeneratorAgent, DynamicResponseAnalyzerAgent, TestSynthesizerAgent
import copy
##33
async def capture_baseline_node(state: PentestState) -> dict: # MODIFIED to return dict
    print("\n📋 Node: CAPTURE_BASELINE")
    print(f"   Sending baseline request to: {state.target_request.url}")
    baseline_response = RequestExecutor.execute_request(state.target_request)
    
    updates: Dict[str, Any] = {"baseline_response": baseline_response}

    target_parameter_baseline_value = state.target_parameter_baseline_value # Preserve if already set
    if state.target_parameter:
        param_val = None
        if state.target_request.params and state.target_parameter in state.target_request.params:
            param_val = state.target_request.params.get(state.target_parameter)
        elif isinstance(state.target_request.data, dict) and state.target_parameter in state.target_request.data:
            param_val = state.target_request.data.get(state.target_parameter)
        elif state.target_request.json_data and state.target_parameter in state.target_request.json_data:
            param_val = state.target_request.json_data.get(state.target_parameter)
        elif isinstance(state.target_request.data, str) and state.target_parameter == "__RAW_BODY__":
            param_val = state.target_request.data # Store the raw body string
        
        if param_val is not None:
            target_parameter_baseline_value = str(param_val)
            print(f"   Stored baseline value for '{state.target_parameter}': '{str(param_val)[:100]}...'") # Truncate for long raw bodies
    
    updates["target_parameter_baseline_value"] = target_parameter_baseline_value

    if baseline_response.error_message:
        print(f"   ❌ Error capturing baseline: {baseline_response.error_message}")
        updates["stop_reason"] = f"Baseline request failed: {baseline_response.error_message}"
    else:
        print(f"   ✅ Baseline captured: Status {baseline_response.status_code}, Time: {baseline_response.response_time:.3f}s")
    
    print(f"DEBUG (capture_baseline): baseline_response in updates: {updates.get('baseline_response') is not None}")
    return updates

async def generate_strategy_and_payload_node(state: PentestState) -> dict: # MODIFIED to return dict
    updates: Dict[str, Any] = {}
    
    new_overall_attempt_count = state.overall_attempt_count + 1
    updates["overall_attempt_count"] = new_overall_attempt_count
    print(f"\n🧠 Node: GENERATE_STRATEGY_PAYLOAD_BATCH (Overall Strategy Attempt {new_overall_attempt_count})")
    
    updates["current_payload_batch"] = []
    updates["current_payload_batch_index"] = 0
    updates["current_payload"] = None

    strategy_desc, payloads_or_signal = await DynamicPayloadGeneratorAgent.generate_strategy_and_payload_batch(state)
    
    updates["current_llm_payload_strategy"] = strategy_desc 

    current_attack_strategy_summary = state.current_attack_strategy_summary
    consecutive_no_progress_attempts = state.consecutive_no_progress_attempts

    if isinstance(payloads_or_signal, list):
        updates["current_payload_batch"] = payloads_or_signal
        if payloads_or_signal: # Check if the list is not empty
            updates["current_payload"] = payloads_or_signal[0]
            print(f"   🎯 LLM Strategy for Batch: '{strategy_desc}'")
            print(f"   Payload Batch (size {len(payloads_or_signal)}): {payloads_or_signal}")
            print(f"   Starting with payload: '{updates['current_payload']}'")
            
            if not current_attack_strategy_summary or \
               (strategy_desc.split(':')[0].strip().lower() != current_attack_strategy_summary.split(':')[0].strip().lower()):
                consecutive_no_progress_attempts = 0 
                print(f"   ✨ New broad strategy for batch. Resetting consecutive_no_progress_attempts.")
            current_attack_strategy_summary = strategy_desc
        else: 
            updates["current_payload"] = "NO_NEW_IDEAS"
            print(f"   🤖 LLM Strategy: {strategy_desc}. LLM returned empty payload list, signaling NO_NEW_IDEAS.")

    elif payloads_or_signal == "NO_NEW_IDEAS":
        updates["current_payload"] = "NO_NEW_IDEAS"
        print(f"   🤖 LLM Strategy: {strategy_desc}. LLM Signal: NO_NEW_IDEAS.")
    elif payloads_or_signal == "CHANGE_STRATEGY_SUGGESTED":
        updates["current_payload"] = "CHANGE_STRATEGY_SUGGESTED"
        print(f"   🔄 LLM suggests new high-level strategy: '{strategy_desc}'. Will attempt this next.")
        if not current_attack_strategy_summary or \
           (strategy_desc.split(':')[0].strip().lower() != current_attack_strategy_summary.split(':')[0].strip().lower()):
            consecutive_no_progress_attempts = 0 
            print(f"   ✨ New broad strategy proposed. Resetting consecutive_no_progress_attempts.")
        current_attack_strategy_summary = strategy_desc
    else: 
        updates["current_payload"] = "NO_NEW_IDEAS"
        print(f"   ⚠️ Unexpected payload signal from LLM: {payloads_or_signal}. Defaulting to NO_NEW_IDEAS.")

    updates["current_attack_strategy_summary"] = current_attack_strategy_summary
    updates["consecutive_no_progress_attempts"] = consecutive_no_progress_attempts
    
    print(f"DEBUG (generate_strategy): current_payload: {updates.get('current_payload')}, batch_index: {updates.get('current_payload_batch_index')}")
    return updates

async def inject_and_execute_node(state: PentestState) -> dict: # MODIFIED to return dict
    print("\n🚀 Node: INJECT_AND_EXECUTE")
    updates: Dict[str, Any] = {}
    
    print(f"DEBUG (inject_and_execute - START): current_payload: {state.current_payload}, batch_index: {state.current_payload_batch_index}, batch_size: {len(state.current_payload_batch) if state.current_payload_batch else 'N/A'}")

    if not state.current_payload or state.current_payload in ["NO_NEW_IDEAS", "CHANGE_STRATEGY_SUGGESTED"]:
        print(f"   ⚠️ Control signal ('{state.current_payload}') or no current payload. Skipping HTTP execution.")
        updates["current_response"] = None 
        return updates
    
    new_individual_execution_count = state.individual_execution_count + 1
    updates["individual_execution_count"] = new_individual_execution_count
    
    print(f"   Executing payload {state.current_payload_batch_index + 1}/{len(state.current_payload_batch)} from current batch. (Total Executions: {new_individual_execution_count})")
    print(f"   Payload: '{state.current_payload}'")

    modified_request = copy.deepcopy(state.target_request)
    injected = False
    if state.target_request.params and state.target_parameter in state.target_request.params:
        modified_request.params[state.target_parameter] = state.current_payload
        injected = True
    elif state.target_request.data and isinstance(state.target_request.data, dict) and \
         state.target_parameter in state.target_request.data:
        modified_request.data[state.target_parameter] = state.current_payload
        injected = True
    elif state.target_request.json_data and isinstance(state.target_request.json_data, dict) and \
         state.target_parameter in state.target_request.json_data:
        modified_request.json_data[state.target_parameter] = state.current_payload
        injected = True
    elif isinstance(state.target_request.data, str) and state.target_parameter == "__RAW_BODY__":
        modified_request.data = state.current_payload
        injected = True
        
    if not injected:
        print(f"   ⚠️ Could not find target parameter '{state.target_parameter}' for injection.")
        updates["current_response"] = None 
        updates["stop_reason"] = f"Target parameter '{state.target_parameter}' not found for injection."
        return updates
    else:
        print(f"   💉 Payload '{state.current_payload}' injected into '{state.target_parameter}'.")

    response = RequestExecutor.execute_request(modified_request)
    updates["current_response"] = response
    
    if response.error_message: print(f"   📨 Error during modified request: {response.error_message}")
    else: print(f"   📨 Response received: Status {response.status_code}, Time: {response.response_time:.3f}s")
    
    return updates

async def dynamic_analyze_response_node(state: PentestState) -> dict: # MODIFIED to return dict
    print("\n🔍 Node: DYNAMIC_ANALYZE_RESPONSE")
    updates: Dict[str, Any] = {}
    
    print(f"DEBUG (dynamic_analyze_response - START): current_payload: {state.current_payload}, batch_index: {state.current_payload_batch_index}")
    
    analysis_results_dict: dict
    response_status: int = 0
    response_content_preview: str = "N/A"
    response_time_val: float = 0.0
    response_err_msg: Optional[str] = None

    current_payload_for_analysis = state.current_payload or "PAYLOAD_NOT_SET_OR_SIGNAL"

    if current_payload_for_analysis in ["NO_NEW_IDEAS", "CHANGE_STRATEGY_SUGGESTED"]:
        analysis_results_dict = { 
            "verdict": AnalysisVerdict.UNCERTAIN, "confidence": 0.0,
            "reasoning": f"Analysis based on control signal: {current_payload_for_analysis}",
            "key_observations": [f"Control signal '{current_payload_for_analysis}' received. No HTTP analysis performed for this step."]
        }
    elif not state.current_response: 
        analysis_results_dict = {
            "verdict": AnalysisVerdict.ERROR_ENCOUNTERED, "confidence": 0.0,
            "reasoning": "No HTTP response object available for analysis (e.g., injection parameter not found, or request execution failed).",
            "key_observations": [state.stop_reason or "HTTP request for attack was not successfully made or response was lost."]
        }
        response_err_msg = state.stop_reason or "No valid HTTP response for analysis."
    else: 
        analysis_results_dict = await DynamicResponseAnalyzerAgent.analyze_response_dynamically(state) 
        response_status = state.current_response.status_code
        response_content_preview = state.current_response.content[:200] if state.current_response.content else "N/A"
        response_time_val = state.current_response.response_time
        response_err_msg = state.current_response.error_message

    attempt_detail = AttemptDetail(
        payload=current_payload_for_analysis,
        llm_strategy_for_payload=state.current_llm_payload_strategy, 
        response_status_code=response_status,
        response_content_preview=response_content_preview,
        response_time=response_time_val,
        response_error_message=response_err_msg,
        analysis_verdict=analysis_results_dict.get("verdict"),
        analysis_confidence=analysis_results_dict.get("confidence"),
        analysis_reasoning=analysis_results_dict.get("reasoning"),
        analysis_key_observations=analysis_results_dict.get("key_observations", [])
    )
    
    new_detailed_attempt_history = state.detailed_attempt_history + [attempt_detail]
    updates["detailed_attempt_history"] = new_detailed_attempt_history
    
    vulnerabilities_found_list = list(state.vulnerabilities_found) # Make a mutable copy
    executive_summary_verdict_val = state.executive_summary_verdict
    executive_summary_reasoning_val = state.executive_summary_reasoning

    if attempt_detail.analysis_verdict == AnalysisVerdict.VULNERABLE:
        conf_display = f"{attempt_detail.analysis_confidence:.2f}" if attempt_detail.analysis_confidence is not None else "N/A"
        print(f"   🚨 VULNERABLE! Confidence: {conf_display}. Reason: {attempt_detail.analysis_reasoning}")
        if (attempt_detail.analysis_confidence or 0.0) >= state.confidence_threshold_vulnerable:
            # Call a modified add_vulnerability_to_report that returns the updated list and summary fields
            # For simplicity here, we'll replicate the logic. In a refactor, this could be a helper.
            concise_reason = f"Payload '{attempt_detail.payload}' led to '{attempt_detail.analysis_verdict.value if attempt_detail.analysis_verdict else 'N/A'}' verdict. Analyzer observed: {attempt_detail.analysis_reasoning or 'No specific reasoning.'}"
            entry = {
                "vulnerability_type": state.vulnerability_type.value,
                "target_parameter": state.target_parameter,
                "payload": attempt_detail.payload,
                "llm_strategy": attempt_detail.llm_strategy_for_payload,
                "analysis_verdict": attempt_detail.analysis_verdict.value if attempt_detail.analysis_verdict else "N/A",
                "analysis_confidence": attempt_detail.analysis_confidence,
                "analysis_reasoning": attempt_detail.analysis_reasoning,
                "concise_reason_for_vulnerability": concise_reason,
                "response_status": attempt_detail.response_status_code,
                "request_name": state.target_request.name or state.target_request.url
            }
            vulnerabilities_found_list.append(entry)
            if not executive_summary_verdict_val or executive_summary_verdict_val != "VULNERABLE":
                executive_summary_verdict_val = "VULNERABLE"
                executive_summary_reasoning_val = concise_reason
            
            updates["vulnerabilities_found"] = vulnerabilities_found_list
            updates["executive_summary_verdict"] = executive_summary_verdict_val
            updates["executive_summary_reasoning"] = executive_summary_reasoning_val

    elif attempt_detail.analysis_verdict == AnalysisVerdict.POTENTIALLY_VULNERABLE:
        conf_display = f"{attempt_detail.analysis_confidence:.2f}" if attempt_detail.analysis_confidence is not None else "N/A"
        print(f"   🟡 POTENTIALLY VULNERABLE. Confidence: {conf_display}. Reason: {attempt_detail.analysis_reasoning}")
    else:
        ver_display = attempt_detail.analysis_verdict.value if attempt_detail.analysis_verdict else "N/A"
        conf_display = f"{attempt_detail.analysis_confidence:.2f}" if attempt_detail.analysis_confidence is not None else "N/A"
        print(f"   📊 Analysis: {ver_display}, Conf: {conf_display}. Reason: {attempt_detail.analysis_reasoning}")

    return updates

def should_continue_dynamic_testing(state: PentestState) -> dict:
    print("\n🚦 Node: DYNAMIC_DECISION_LOGIC (should_continue_dynamic_testing)")
    
    updates: Dict[str, Any] = {}
    routing_key = "" 

    if state.stop_reason and "Baseline request failed" in state.stop_reason: 
        print(f"   ➡️ Critical stop triggered: {state.stop_reason}")
        routing_key = "generate_report_edge"
        updates["next_edge"] = routing_key
        return updates

    last_attempt = state.detailed_attempt_history[-1] if state.detailed_attempt_history else None
    
    if last_attempt and last_attempt.analysis_verdict == AnalysisVerdict.VULNERABLE and \
       (last_attempt.analysis_confidence or 0.0) >= state.confidence_threshold_vulnerable:
        current_stop_reason = f"Vulnerability confirmed with high confidence ({last_attempt.analysis_confidence or 0.0:.2f}) with payload '{last_attempt.payload}'. Test concluded."
        print(f"   ➡️ {current_stop_reason}")
        routing_key = "generate_report_edge"
        updates["stop_reason"] = current_stop_reason
        updates["next_edge"] = routing_key
        return updates

    if state.current_payload_batch and \
       state.current_payload_batch_index < len(state.current_payload_batch) - 1:
        
        new_batch_index = state.current_payload_batch_index + 1
        new_current_payload = state.current_payload_batch[new_batch_index]
        
        print(f"   ➡️ Continuing with next payload in batch ({new_batch_index + 1}/{len(state.current_payload_batch)}): '{new_current_payload}'")
        routing_key = "next_payload_in_batch_edge"
        
        updates["current_payload_batch_index"] = new_batch_index
        updates["current_payload"] = new_current_payload
        updates["next_edge"] = routing_key
        return updates

    is_progress_made_in_batch = False
    if state.current_payload_batch: 
        start_index_of_batch_in_history = len(state.detailed_attempt_history) - len(state.current_payload_batch)
        if start_index_of_batch_in_history < 0: start_index_of_batch_in_history = 0 

        for i in range(start_index_of_batch_in_history, len(state.detailed_attempt_history)):
            attempt_in_batch = state.detailed_attempt_history[i]
            if attempt_in_batch.analysis_verdict in [AnalysisVerdict.VULNERABLE, AnalysisVerdict.POTENTIALLY_VULNERABLE]:
                is_progress_made_in_batch = True
                break
            meaningful_obs = [obs for obs in attempt_in_batch.analysis_key_observations 
                              if "fallback" not in obs.lower() and \
                                 "no significant change" not in obs.lower() and \
                                 "no http response" not in obs.lower() and \
                                 "control signal" not in obs.lower()]
            if meaningful_obs:
                is_progress_made_in_batch = True
                break
        
        current_consecutive_no_progress = state.consecutive_no_progress_attempts
        if is_progress_made_in_batch:
            current_consecutive_no_progress = 0 
            print(f"   ⓘ Progress detected within the last batch. Resetting consecutive_no_progress_attempts for strategy.")
        else:
            current_consecutive_no_progress += 1
            print(f"   ⓘ No significant progress detected in the last batch. consecutive_no_progress_attempts for strategy is now {current_consecutive_no_progress}.")
        updates["consecutive_no_progress_attempts"] = current_consecutive_no_progress

    if state.current_payload == "NO_NEW_IDEAS": 
        current_stop_reason = state.stop_reason or "LLM payload generator exhausted all ideas."
        print(f"   ➡️ Stop signal from LLM: {current_stop_reason}")
        routing_key = "generate_report_edge"
        updates["stop_reason"] = current_stop_reason
        updates["next_edge"] = routing_key
        return updates
    
    if state.current_payload == "CHANGE_STRATEGY_SUGGESTED":
        print(f"   🔄 LLM suggested changing strategy. Looping back to generate new strategy/payload batch.")
        routing_key = "continue_testing_edge"
        updates["next_edge"] = routing_key
        return updates

    if state.overall_attempt_count >= state.max_total_attempts:
        current_stop_reason = state.stop_reason or f"Max overall strategy attempts ({state.max_total_attempts}) reached."
        print(f"   ➡️ {current_stop_reason}")
        routing_key = "generate_report_edge"
        updates["stop_reason"] = current_stop_reason
        updates["next_edge"] = routing_key
        return updates
    
    if state.stop_reason : 
        print(f"   ➡️ Stop reason: {state.stop_reason}")
        routing_key = "generate_report_edge"
        updates["next_edge"] = routing_key 
        return updates

    print(f"   ➡️ Conditions not met to stop. Continuing to generate new strategy/payload batch (Overall Strategy Attempt: {state.overall_attempt_count}).") # overall_attempt_count is already incremented
    routing_key = "continue_testing_edge"
    updates["next_edge"] = routing_key
    return updates


async def generate_executive_summary_node(state: PentestState) -> dict: # MODIFIED to return dict
    print("\n✍️ Node: GENERATE_EXECUTIVE_SUMMARY")
    updates: Dict[str, Any] = {}

    if not state.detailed_attempt_history and not state.vulnerabilities_found:
        print("   No attempts or findings to summarize. Skipping LLM summary.")
        updates["executive_summary_verdict"] = "UNCERTAIN_CONCLUSION"
        updates["executive_summary_reasoning"] = "No testing attempts were made or recorded, so no conclusion can be drawn."
        return updates

    verdict, reasoning = await TestSynthesizerAgent.generate_final_verdict_and_reasoning(state)
    updates["executive_summary_verdict"] = verdict
    updates["executive_summary_reasoning"] = reasoning
    print(f"   Synthesizer Verdict: {verdict}")
    print(f"   Synthesizer Reasoning (concise for vulnerable): {reasoning}")
    return updates


async def generate_dynamic_report_node(state: PentestState) -> dict: # MODIFIED to return dict
    print("\n📝 Node: ASSEMBLE_FINAL_DETAILED_REPORT")
    updates: Dict[str, Any] = {}
    
    report_parts = [
        f" Dynamic Penetration Test Report",
        f"Target: '{state.target_request.name or state.target_request.url}' ({state.target_request.method})",
        f"Vulnerability Type Tested: {state.vulnerability_type.value}",
        f"Target Parameter: {state.target_parameter}",
    ]

    report_parts.append("\n--- EXECUTIVE SUMMARY (from Synthesizer) ---")
    report_parts.append(f"Final Verdict: {state.executive_summary_verdict or 'Not Generated'}")
    report_parts.append(f"Reasoning: {state.executive_summary_reasoning or 'Not Generated'}")
    report_parts.append("------------------------------------------")

    report_parts.append(f"\nTotal Strategy/Batch Generation Attempts: {state.overall_attempt_count}")
    report_parts.append(f"Total Individual Payloads Executed: {state.individual_execution_count}")
    if state.stop_reason:
        report_parts.append(f"Reason for Test Conclusion: {state.stop_reason}")

    if state.vulnerabilities_found: 
        report_parts.append("\n VULNERABILITY FINDINGS (Flagged as 'VULNERABLE' with high confidence): ")
        for i, entry in enumerate(state.vulnerabilities_found, 1):
            report_parts.append(f"\n  Finding #{i} for '{entry.get('request_name', 'N/A')}':")
            report_parts.append(f"    - Strategy Employed: {entry.get('llm_strategy', 'N/A')}")
            report_parts.append(f"    - Payload Used: '{entry.get('payload', 'N/A')}'")
            conf_str = f"{entry.get('analysis_confidence'):.2f}" if entry.get('analysis_confidence') is not None else "N/A"
            report_parts.append(f"    - Analyzer Verdict: {entry.get('analysis_verdict', 'N/A')} (Confidence: {conf_str})")
            report_parts.append(f"    - Analyzer Reasoning (Full): {entry.get('analysis_reasoning', 'N/A')}")
            report_parts.append(f"    - Concise Summary: {entry.get('concise_reason_for_vulnerability', 'N/A')}")
    elif state.executive_summary_verdict != "VULNERABLE": 
        report_parts.append("\nNo specific attempts were flagged as definitively 'VULNERABLE' with high confidence during the test.")
   
    report_parts.append("\n FULL ATTEMPT HISTORY LOG: ")
    if state.detailed_attempt_history:
        for i, attempt in enumerate(state.detailed_attempt_history):
            conf_str = f"{attempt.analysis_confidence:.2f}" if attempt.analysis_confidence is not None else "N/A"
            ver_str = attempt.analysis_verdict.value if attempt.analysis_verdict else "N/A"
            report_parts.append(
                f"  Log Entry #{i+1}: Strategy Context: '{attempt.llm_strategy_for_payload or 'N/A'}'\n"
                f"                 Payload: '{attempt.payload}'\n" 
                f"                 -> Resp Status: {attempt.response_status_code}, Analyzer Verdict: {ver_str} (Conf: {conf_str})\n"
                f"                    Analyzer Reasoning: {attempt.analysis_reasoning or 'N/A'}\n"
                f"                    Key Observations: {'; '.join(attempt.analysis_key_observations) or 'None'}"
            )
    else: report_parts.append("  No detailed attempts were recorded.")
    
    updates["final_report"] = "\n".join(report_parts)
    print("   📋 Final detailed report string assembled.")
    return updates