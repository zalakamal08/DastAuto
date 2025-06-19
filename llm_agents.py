# pentester_project/llm_agents.py
import json
from typing import List, Dict, Optional, Tuple ,Any
from state import PentestState, VulnerabilityType, AnalysisVerdict, AttemptDetail
from config import get_gemini_model

gemini_model = get_gemini_model()

class DynamicPayloadGeneratorAgent:

    @staticmethod
    def _format_attempt_history(history: List[AttemptDetail]) -> str:
        if not history:
            return "No prior attempts in this session."
        
        formatted_history = ["\nTest Attempt History (most recent first, from current strategy batch or previous):"]
        for i, attempt in enumerate(reversed(history[-5:])): # Last 5 individual executions
            formatted_history.append(
                f"  Attempt {len(history) - i}:"
                f"    - Strategy Context: {attempt.llm_strategy_for_payload or 'N/A'}"
                f"    - Payload: \"{attempt.payload}\""
                f"    - Response Status: {attempt.response_status_code}"
                f"    - Verdict: {attempt.analysis_verdict.value if attempt.analysis_verdict else 'N/A'} (Conf: {attempt.analysis_confidence if attempt.analysis_confidence is not None else 'N/A'})"
                f"    - Analyzer Reasoning: {attempt.analysis_reasoning or 'None'}"
                f"    - Key Observations: {'; '.join(attempt.analysis_key_observations) or 'None'}"
            )
        return "\n".join(formatted_history)

    @staticmethod
    async def generate_strategy_and_payload_batch(state: PentestState) -> Tuple[Optional[str], Any]:
        history_summary = DynamicPayloadGeneratorAgent._format_attempt_history(state.detailed_attempt_history)
        
        param_location = "URL Query"
        original_param_value_info = ""
        if state.target_request.params and state.target_parameter in state.target_request.params:
            param_location = "URL Query"
            if state.target_parameter_baseline_value is not None:
                 original_param_value_info = f"The original value for '{state.target_parameter}' was: '{state.target_parameter_baseline_value}'. Consider this for initial probes or format-aware fuzzing."
        elif state.target_request.data and isinstance(state.target_request.data, dict) and \
             state.target_parameter in state.target_request.data:
            param_location = "Form Data"
            if state.target_parameter_baseline_value is not None:
                 original_param_value_info = f"The original value for '{state.target_parameter}' (form data) was: '{state.target_parameter_baseline_value}'. Consider this."
        elif state.target_request.json_data and isinstance(state.target_request.json_data, dict) and \
             state.target_parameter in state.target_request.json_data:
            param_location = "JSON Body"
            if state.target_parameter_baseline_value is not None:
                 original_param_value_info = f"The original value for '{state.target_parameter}' (JSON key) was: '{state.target_parameter_baseline_value}'. Consider this."
        elif isinstance(state.target_request.data, str) and state.target_parameter == "__RAW_BODY__":
            param_location = "Raw Request Body"
            if state.target_parameter_baseline_value is not None:
                 original_param_value_info = f"The original raw request body (target: __RAW_BODY__) started with: '{state.target_parameter_baseline_value[:100]}...'. Consider its structure."

        strategy_guidance = ""
        if state.consecutive_no_progress_attempts >= state.max_consecutive_no_progress_per_strategy:
            strategy_guidance = (
                f"The current high-level attack strategy ('{state.current_attack_strategy_summary or 'None defined'}') "
                f"has not yielded new leads for {state.consecutive_no_progress_attempts} full payload batches. "
                "You MUST propose a significantly different high-level attack strategy (e.g., switch from error-based to blind, try encoding if WAF suspected, try different character sets). " # Added more examples
                "Describe this new strategy in the 'strategy' field. Set 'payloads' to 'CHANGE_STRATEGY_SUGGESTED'. "
                "Or, if truly no logical strategies remain, set 'payloads' to 'NO_NEW_IDEAS'."
            )
        
        prompt = f"""
You are an expert, methodical penetration tester simulating manual testing for {state.vulnerability_type.value}
on the parameter '{state.target_parameter}' (in {param_location}) of API '{state.target_request.name or state.target_request.url}' ({state.target_request.method}).
Your overall goal is to confirm or deny the presence of this vulnerability.
{original_param_value_info}

Current High-Level Attack Strategy (if any): {state.current_attack_strategy_summary or 'Not yet defined. Define one if starting.'}
{strategy_guidance}

{history_summary}

Your Task (Overall Attempt #{state.overall_attempt_count + 1} for a new strategy/batch):
1.  Define/Refine Attack Strategy: Describe your specific attack strategy for THIS BATCH of payloads. This should be a logical next step based on the history and your overall goal.
    If {strategy_guidance}, this MUST be a NEW high-level strategy.
    Examples:
    - "Basic syntax probes for SQLi using common special characters."
    - "Attempt error-based SQLi detection using union-based techniques with varying column numbers."
    - "Test for XSS by attempting to inject simple script tags with different event handlers or attributes."
    - "If WAF suspected from history: Try filter evasion for common {state.vulnerability_type.value} characters using URL encoding, character encoding (e.g., hex, unicode), case variations, or alternative syntax."

2.  Generate Payloads Batch: Based on your chosen strategy, generate a JSON list of 1 to 5 precise, NOVEL payloads to try sequentially for this strategy.
    CRITICAL: Do NOT repeat any payloads explicitly listed in the 'Test Attempt History' above unless your new strategy specifically justifies re-testing a slightly modified version due to new insights (e.g., adding an encoding layer to a previously blocked payload). Aim for genuine variations.

    Alternatively:
    - If you are proposing a new high-level strategy as per guidance, set "payloads" to "CHANGE_STRATEGY_SUGGESTED".
    - If ALL logical strategies for {state.vulnerability_type.value} seem exhausted and no new ideas or variations are plausible given the history, set "payloads" to "NO_NEW_IDEAS".

Considerations:
- Be methodical. Start with simple probes, then escalate complexity based on observations from the history.
- If the history shows an error, a WAF block, or specific sanitization, your strategy and payload batch should aim to understand or bypass it.
- If previous attempts were UNCERTAIN but showed interesting response changes, focus your strategy on clarifying those observations.
- Each new batch of payloads should explore a new variation or technique. Avoid stagnation.

Output Format: Respond with a VALID JSON object with two keys: "strategy" (string) and "payloads" (JSON list of strings, OR the string "CHANGE_STRATEGY_SUGGESTED", OR "NO_NEW_IDEAS").
Example for SQLi initial probe batch:
{{
    "strategy": "Initial probe with common SQL special characters to check for basic syntax errors.",
    "payloads": ["'", "\"", "-- ", ";", "/*"]
}}
Example for changing strategy:
{{
    "strategy": "Switching to boolean-based blind SQL injection techniques as error-based attempts were inconclusive and showed potential WAF activity.",
    "payloads": "CHANGE_STRATEGY_SUGGESTED"
}}
Example for no new ideas:
{{
    "strategy": "Conclusion: All relevant strategies for {state.vulnerability_type.value}, including various evasion techniques, have been attempted without success.",
    "payloads": "NO_NEW_IDEAS"
}}
Ensure your JSON is well-formed.
"""
        try:
            response = await gemini_model.generate_content_async(prompt)
            llm_output_text = response.text.strip() if response.text else "{}"
            
            parsed_json = {}
            try:
                json_start = llm_output_text.find('{')
                json_end = llm_output_text.rfind('}')
                if json_start != -1 and json_end != -1 and json_end > json_start:
                    json_str = llm_output_text[json_start : json_end+1]
                    parsed_json = json.loads(json_str)
                else:
                    raise json.JSONDecodeError("No JSON object found in LLM output", llm_output_text, 0)
            except json.JSONDecodeError as e:
                print(f"⚠️ PayloadGen: JSONDecodeError parsing LLM strategy/payloads: {e}. Output: {llm_output_text[:200]}")
                return "Failed to parse LLM output, attempting recovery.", "CHANGE_STRATEGY_SUGGESTED"

            strategy = parsed_json.get("strategy", "Strategy not specified by LLM.")
            payloads_data = parsed_json.get("payloads")

            if not payloads_data: 
                print("⚠️ PayloadGen: LLM returned empty payloads. Suggesting strategy change.")
                return strategy or "LLM returned empty payloads.", "CHANGE_STRATEGY_SUGGESTED"
            
            if isinstance(payloads_data, list):
                if not all(isinstance(p, str) for p in payloads_data):
                    print("⚠️ PayloadGen: LLM returned a list for 'payloads', but not all items are strings. Suggesting strategy change.")
                    return strategy, "CHANGE_STRATEGY_SUGGESTED"
                if not payloads_data:
                     print("⚠️ PayloadGen: LLM returned an empty list of payloads. Suggesting strategy change.")
                     return strategy, "CHANGE_STRATEGY_SUGGESTED"
            elif isinstance(payloads_data, str):
                if payloads_data not in ["CHANGE_STRATEGY_SUGGESTED", "NO_NEW_IDEAS"]:
                    print(f"ℹ️ PayloadGen: LLM returned a single string payload '{payloads_data}'. Treating as a batch of one.")
                    payloads_data = [payloads_data] 
            else:
                print(f"⚠️ PayloadGen: LLM returned 'payloads' of unexpected type {type(payloads_data)}. Suggesting strategy change.")
                return strategy, "CHANGE_STRATEGY_SUGGESTED"

            return strategy, payloads_data

        except Exception as e:
            print(f"Error generating strategy/payload batch with Gemini: {e}")
            return "LLM API call failed during strategy/payload generation.", "CHANGE_STRATEGY_SUGGESTED"


class DynamicResponseAnalyzerAgent:

    @staticmethod
    def _parse_analysis(llm_output: str) -> Dict[str, Any]:
        try:
            json_start = llm_output.find('{')
            json_end = llm_output.rfind('}')
            if json_start != -1 and json_end != -1 and json_end > json_start:
                json_str = llm_output[json_start : json_end+1]
                data = json.loads(json_str)
                
                parsed: Dict[str, Any] = {} 
                verdict_str = data.get("verdict", "uncertain").lower()
                try:
                    parsed["verdict"] = AnalysisVerdict(verdict_str)
                except ValueError:
                    if "vulnerable" in verdict_str: parsed["verdict"] = AnalysisVerdict.VULNERABLE
                    elif "potential" in verdict_str: parsed["verdict"] = AnalysisVerdict.POTENTIALLY_VULNERABLE
                    else: parsed["verdict"] = AnalysisVerdict.UNCERTAIN
                
                parsed["confidence"] = float(data.get("confidence", 0.3))
                parsed["reasoning"] = data.get("reasoning", "No reasoning provided by LLM.")
                
                observations = data.get("key_observations", [])
                parsed["key_observations"] = observations if isinstance(observations, list) and all(isinstance(s, str) for s in observations) else []
                return parsed
            else:
                print(f"⚠️ Analyzer: LLM analysis output not in expected JSON. Raw: {llm_output[:100]}")
        except json.JSONDecodeError as e:
            print(f"⚠️ Analyzer: JSONDecodeError parsing analysis. Raw: {llm_output[:100]}. Error: {e}")
        except Exception as e:
            print(f"⚠️ Analyzer: Error processing analysis output. Raw: {llm_output[:100]}. Error: {e}")
        
        fallback_verdict = AnalysisVerdict.UNCERTAIN
        if "VULNERABLE" in llm_output.upper(): fallback_verdict = AnalysisVerdict.VULNERABLE
        elif "POTENTIALLY_VULNERABLE" in llm_output.upper(): fallback_verdict = AnalysisVerdict.POTENTIALLY_VULNERABLE
        return {
            "verdict": fallback_verdict, "confidence": 0.2, 
            "reasoning": "Fallback due to parsing error or unexpected LLM output.",
            "key_observations": [f"Raw LLM output preview: {llm_output[:100]}"]
        }

    @staticmethod
    async def analyze_response_dynamically(state: PentestState) -> Dict[str, Any]:
        if not hasattr(state, 'baseline_response') or not state.baseline_response: # Added hasattr check
             print("Error: baseline_response is missing or None in analyze_response_dynamically.")
             return {
                "verdict": AnalysisVerdict.ERROR_ENCOUNTERED, "confidence": 0.0,
                "reasoning": "Critical error: Baseline response is missing or None for analysis.", # Updated message
                "key_observations": ["Cannot perform analysis without a baseline."]
            }
        if not state.current_response: 
            return {
                "verdict": AnalysisVerdict.ERROR_ENCOUNTERED, "confidence": 0.0,
                "reasoning": "No HTTP response from current attack attempt for analysis.",
                "key_observations": ["Payload might have been a control signal or attack request failed."]
            }

        baseline = state.baseline_response
        current = state.current_response
        
        prompt = f"""
You are an expert security response analyst.
An automated test for {state.vulnerability_type.value} was performed on parameter '{state.target_parameter}'.
The overall attack strategy for the current batch of payloads was: "{state.current_llm_payload_strategy or 'Not specified'}"
The specific payload used for THIS attempt was: '{state.current_payload}'

BASELINE RESPONSE (before any attack):
Status: {baseline.status_code}, Content Length: {len(baseline.content) if baseline.content else 'N/A'}, 
Preview: {baseline.content[:200] if baseline.content else 'N/A'}, Error: {baseline.error_message or 'None'}

ATTACK RESPONSE (to the payload above):
Status: {current.status_code}, Content Length: {len(current.content) if current.content else 'N/A'}, 
Preview: {current.content[:200] if current.content else 'N/A'}, Error: {current.error_message or 'None'}

Task: Analyze the differences. Based on the payload's INTENDED STRATEGY (context: "{state.current_llm_payload_strategy or 'Not specified'}") and the observed response changes, provide your analysis.
Consider:
- Error messages (SQL errors, application errors, WAF blocks). If a WAF block is suspected, explicitly state this and any patterns observed (e.g., specific keywords blocked).
- Payload reflection (raw, sanitized, partial). If sanitization is observed, describe what was changed or removed.
- Changes in status code, content length, response time.
- Unexpected data or behavior.
- For {state.vulnerability_type.value}, what are the typical indicators you'd look for given this strategy?
- Your key_observations should highlight information that would help a pentester decide the *next specific step* or *type of payload variation* to try. For example, "Application returned a generic error, but the response time increased slightly, suggesting server-side processing of the payload." or "The single quote was reflected as HTML entity ', indicating potential sanitization against XSS."

Output your analysis as a VALID JSON object:
{{
    "verdict": "vulnerable_or_potentially_vulnerable_or_not_vulnerable_or_uncertain_or_error_encountered",
    "confidence": 0.0_to_1.0,
    "reasoning": "Your detailed step-by-step reasoning for the verdict, explaining how the observations relate to the payload strategy and vulnerability type. Be specific.",
    "key_observations": ["list_of_the_most_significant_factual_observations_from_the_attack_response_compared_to_baseline, focusing on actionable details for next steps."]
}}
- Use "potentially_vulnerable" if there are strong indicators but not absolute proof yet.
- Use "error_encountered" if the ATTACK request itself failed in a way that prevents analysis (e.g. timeout, connection error).
- Be objective. If the evidence is weak for the current strategy, state that.
"""
        try:
            response = await gemini_model.generate_content_async(prompt)
            return DynamicResponseAnalyzerAgent._parse_analysis(response.text if response.text else "")
        except Exception as e:
            print(f"Error analyzing response with Gemini: {e}")
            return {
                "verdict": AnalysisVerdict.UNCERTAIN, "confidence": 0.1,
                "reasoning": f"LLM API call for analysis failed: {e}",
                "key_observations": []
            }


class TestSynthesizerAgent:

    @staticmethod
    def _format_key_evidence_for_summary(state: PentestState) -> str:
        summary_points = []
        if state.vulnerabilities_found:
            summary_points.append("Key evidence of confirmed/indicated vulnerability:")
            high_conf_vulns = [
                v_entry for v_entry in state.vulnerabilities_found 
                if v_entry.get('analysis_verdict') == AnalysisVerdict.VULNERABLE.value and \
                   (v_entry.get('analysis_confidence', 0.0)) >= state.confidence_threshold_vulnerable
            ]
            for vuln_entry in high_conf_vulns[:3]: 
                summary_points.append(
                    f"  - Payload: \"{vuln_entry.get('payload', 'N/A')}\" (Strategy: {vuln_entry.get('llm_strategy','N/A')}) "
                    f"led to verdict '{vuln_entry.get('analysis_verdict', 'N/A')}' "
                    f"with confidence {vuln_entry.get('analysis_confidence', 0.0):.2f}. "
                    f"Analyzer Reasoning: {str(vuln_entry.get('analysis_reasoning', 'None'))[:150]}..."
                )
        elif state.detailed_attempt_history:
            summary_points.append("Summary of key testing attempts (most relevant from history):")
            relevant_attempts = [
                a for a in state.detailed_attempt_history 
                if a.analysis_verdict in [AnalysisVerdict.POTENTIALLY_VULNERABLE, AnalysisVerdict.UNCERTAIN] and a.analysis_key_observations
            ][:2] 
            if not relevant_attempts and state.detailed_attempt_history:
                relevant_attempts.extend(state.detailed_attempt_history[-3:]) 
            
            unique_relevant_attempts = [] 
            seen_payloads = set()
            for attempt in relevant_attempts:
                if attempt.payload not in seen_payloads:
                    unique_relevant_attempts.append(attempt)
                    seen_payloads.add(attempt.payload)
            
            for attempt in unique_relevant_attempts[:3]:
                summary_points.append(
                    f"  - Payload: \"{attempt.payload}\" (Strategy: {attempt.llm_strategy_for_payload or 'N/A'}) "
                    f"resulted in '{attempt.analysis_verdict.value if attempt.analysis_verdict else 'N/A'}' (Confidence: {attempt.analysis_confidence or 0.0:.2f}). "
                    f"Observations: {'; '.join(attempt.analysis_key_observations[:2])[:150]}..."
                )
        else:
            summary_points.append("No detailed attempts or significant findings were recorded.")
        return "\n".join(summary_points)

    @staticmethod
    async def generate_final_verdict_and_reasoning(state: PentestState) -> Tuple[str, str]:
        evidence_summary = TestSynthesizerAgent._format_key_evidence_for_summary(state) 

        primary_vuln_reasoning = "No definitive vulnerability confirmed with high confidence."
        first_high_conf_vuln_entry = next((
            v_entry for v_entry in state.vulnerabilities_found
            if v_entry.get('analysis_verdict') == AnalysisVerdict.VULNERABLE.value and
               (v_entry.get('analysis_confidence', 0.0)) >= state.confidence_threshold_vulnerable
        ), None)

        if first_high_conf_vuln_entry:
            primary_vuln_reasoning = first_high_conf_vuln_entry.get(
                'concise_reason_for_vulnerability', 
                "Vulnerability confirmed with high confidence."
            )
        elif state.vulnerabilities_found:
             primary_vuln_reasoning = state.vulnerabilities_found[0].get(
                 'concise_reason_for_vulnerability', 
                 "Potential vulnerability indicated with lower confidence."
            )
        
        escaped_primary_vuln_reasoning = primary_vuln_reasoning.replace("'", "\\'").replace("\n", " ")
        escaped_target_parameter = state.target_parameter.replace("'", "\\'")
        escaped_vulnerability_type_value = state.vulnerability_type.value.replace("'", "\\'")
        escaped_stop_reason = (state.stop_reason or 'criteria met').replace("'", "\\'")

        prompt = f"""
You are a lead penetration tester writing a concise executive summary.
The test was for {state.vulnerability_type.value} on parameter '{state.target_parameter}' of API: '{state.target_request.name or state.target_request.url}' ({state.target_request.method}).
Total individual payloads tested: {state.individual_execution_count}. Test conclusion reason: {state.stop_reason or 'Reached configured criteria.'}

Key Evidence & Attempt Summary (for your context, not direct inclusion in concise reasoning):
{evidence_summary}

Primary Vulnerability Finding (if any, for concise summary): {primary_vuln_reasoning}

Task:
Based on the overall test outcome and the primary finding:
1.  Determine a final verdict: "VULNERABLE", "NOT_VULNERABLE", or "UNCERTAIN_CONCLUSION".
    - "VULNERABLE" if there's a `Primary Vulnerability Finding` indicating high confidence.
    - "NOT_VULNERABLE" if diverse strategies were attempted consistently yielding "NOT_VULNERABLE" and no significant "POTENTIALLY_VULNERABLE" findings.
    - "UNCERTAIN_CONCLUSION" otherwise (e.g., test stopped early, findings mixed/low-confidence).
2.  Provide a brief (1-2 sentences) reasoning for YOUR verdict. If "VULNERABLE", this reasoning should be the "small summary why this is the case" based on the `Primary Vulnerability Finding`.

Output ONLY a JSON object with two keys: "final_verdict" and "final_reasoning".
Example VULNERABLE:
{{
    "final_verdict": "VULNERABLE",
    "final_reasoning": "{escaped_primary_vuln_reasoning}"
}}
Example NOT_VULNERABLE:
{{
    "final_verdict": "NOT_VULNERABLE",
    "final_reasoning": "The parameter '{escaped_target_parameter}' does not appear to be vulnerable to {escaped_vulnerability_type_value}. Multiple attack strategies and {state.individual_execution_count} payloads did not elicit vulnerable responses."
}}
Example UNCERTAIN_CONCLUSION:
{{
    "final_verdict": "UNCERTAIN_CONCLUSION",
    "final_reasoning": "Assessment for {escaped_vulnerability_type_value} on '{escaped_target_parameter}' is inconclusive. Testing concluded due to '{escaped_stop_reason}' before a definitive vulnerability could be confirmed or ruled out."
}}
"""
        try:
            response = await gemini_model.generate_content_async(prompt)
            llm_output_text = response.text.strip() if response.text else "{}"
            
            parsed_json = {}
            try:
                json_start = llm_output_text.find('{')
                json_end = llm_output_text.rfind('}')
                if json_start != -1 and json_end != -1 and json_end > json_start:
                    json_str = llm_output_text[json_start : json_end+1]
                    parsed_json = json.loads(json_str)
                else:
                    raise json.JSONDecodeError("No JSON object found in summary LLM output", llm_output_text, 0)
            except json.JSONDecodeError as e:
                print(f"⚠️ SummaryGen: JSONDecodeError: {e}. Output: {llm_output_text[:200]}")
                if first_high_conf_vuln_entry:
                    return "VULNERABLE", first_high_conf_vuln_entry.get('concise_reason_for_vulnerability', "Vulnerability indicated. LLM summary failed.")
                return "UNCERTAIN_CONCLUSION", "Testing concluded. LLM summary generation failed to parse."

            verdict = parsed_json.get("final_verdict", "UNCERTAIN_CONCLUSION")
            reasoning = parsed_json.get("final_reasoning", "No detailed reasoning provided by LLM summary.")
            return verdict, reasoning

        except Exception as e:
            print(f"Error generating final summary with Gemini: {e}")
            if first_high_conf_vuln_entry:
                 return "VULNERABLE", first_high_conf_vuln_entry.get('concise_reason_for_vulnerability', f"Vulnerability indicated. Summary LLM call failed: {e}")
            return "UNCERTAIN_CONCLUSION", f"Testing concluded. Summary LLM call failed: {e}"