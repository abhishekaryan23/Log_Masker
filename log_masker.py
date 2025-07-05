import ollama
import json
import re
import argparse
import logging # New import
import sys # For sys.exit

# --- Logging Setup ---
# Could be more sophisticated (e.g., file handler, formatter) if needed
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global PII map and counter
pii_map = {}
placeholder_id_counter = 0

def get_or_create_placeholder(original_value: str, pii_type_suggestion: str = "DATA") -> str:
    global placeholder_id_counter
    if original_value in pii_map:
        return pii_map[original_value]
    else:
        placeholder_id_counter += 1
        sanitized_type = re.sub(r'\W+', '', pii_type_suggestion.upper())
        if not sanitized_type or len(sanitized_type) > 30:
            sanitized_type = "DATA"
        placeholder = f"[{sanitized_type}_{placeholder_id_counter}]"
        pii_map[original_value] = placeholder
        return placeholder

def parse_llm_response_for_masking(llm_content: str, original_log_line: str) -> tuple[str, dict]:
    current_line_mappings = {}

    try:
        if not llm_content.startswith("Masked Log:"):
            logging.warning(f"LLM response does not start with 'Masked Log:'. Attempting to proceed. Content: {llm_content[:200]}...")
            if "Masked Log:" in llm_content:
                 llm_content = llm_content[llm_content.find("Masked Log:"):]
            else: # Cannot find "Masked Log:", likely cannot parse
                logging.warning(f"Cannot find 'Masked Log:' in LLM response for: {original_log_line}. Returning original.")
                return original_log_line, {}


        if "Masked Log:" in llm_content and "Mappings:" in llm_content:
            parts = llm_content.split("Mappings:", 1)
            mappings_section = parts[1].strip()
            temp_extracted_pairs = []

            if mappings_section:
                for line in mappings_section.splitlines():
                    line = line.strip()
                    if not line:
                        continue

                    parts_map = line.rsplit(':', 1)
                    if len(parts_map) == 2:
                        original_value = parts_map[0].strip()
                        pii_type_hint = parts_map[1].strip().upper().replace(" ", "_")
                        if not pii_type_hint:
                            pii_type_hint = "DATA"
                        temp_extracted_pairs.append((original_value, pii_type_hint))
                    else:
                        logging.warning(f"Could not parse mapping line (expected 'value:TYPE'): '{line}' in LLM response for: {original_log_line}")
                        continue

            final_masked_log_line = original_log_line
            temp_extracted_pairs.sort(key=lambda x: len(x[0]), reverse=True)

            for original_value, pii_type_hint in temp_extracted_pairs:
                if original_value in final_masked_log_line:
                    consistent_placeholder = get_or_create_placeholder(original_value, pii_type_hint)
                    final_masked_log_line = final_masked_log_line.replace(original_value, consistent_placeholder)
                    current_line_mappings[consistent_placeholder] = original_value

            return final_masked_log_line, current_line_mappings

        elif f"Masked Log: {original_log_line}" in llm_content:
            if "Mappings:" in llm_content:
                mappings_section_check = llm_content.split("Mappings:", 1)[1].strip()
                if not mappings_section_check:
                    return original_log_line, {}
            else:
                return original_log_line, {}

        logging.warning(f"LLM response format issue or no PII identified by structure for: {original_log_line}. Content: {llm_content[:300]}...")
        return original_log_line, {}

    except Exception as e:
        logging.error(f"Error parsing LLM response for '{original_log_line}': {e}. Content: {llm_content[:200]}...", exc_info=True)
        return original_log_line, {}

def mask_log_line(log_line: str, model_name: str = "llama2") -> tuple[str, dict]:
    try:
        prompt = f"""Your task is to analyze the log line below, identify all pieces of proprietary or sensitive information, and then provide the original log line with this information replaced by generic placeholders. You will also list the mappings of the original sensitive data to its type.

Strictly adhere to the following instructions:
1.  Identify sensitive data such as: user names, real names, email addresses, IP addresses (IPv4 and IPv6), hostnames (internal or specific), API keys, access tokens, passwords, financial account numbers, credit card numbers, medical record numbers, Social Security Numbers, phone numbers, specific geo-locations (street addresses), or any other data an organization (like a bank or healthcare provider) would not want exposed.
2.  In the "Masked Log" section, provide the *complete original log line* with *all* identified sensitive items replaced by generic placeholders (e.g., [EMAIL_ADDRESS], [IP_ADDRESS], [USER_ID], [LOCATION]). The placeholder should give a hint about the type of data.
3.  In the "Mappings" section, list each piece of original sensitive information you found and its type. The format for each mapping MUST be:
    <original_sensitive_value_exactly_as_in_log>: <TYPE_OF_DATA>
    (Example: johndoe@example.com: EMAIL_ADDRESS)
    (Example: 192.168.1.100: IP_ADDRESS)
    (Example: ACCT12345XYZ: ACCOUNT_NUMBER)
4.  Your entire response MUST start with "Masked Log:" and contain NO other text before it.
5.  After "Masked Log:", you MUST include "Mappings:".
6.  If no sensitive information is found in the log line, the "Masked Log" should be the original log line, and the "Mappings" section should be present but empty.

Log line: "{log_line}"

Example of a PERFECT response for a log containing PII:
Masked Log: Login attempt for user [USERNAME] from IP [IP_ADDRESS] failed for account [ACCOUNT_NUMBER].
Mappings:
testuser1: USERNAME
192.168.1.10: IP_ADDRESS
ACCT_XYZ789: ACCOUNT_NUMBER

Example of a PERFECT response if NO PII is found:
Masked Log: System backup completed successfully.
Mappings:
(this section is empty)

Begin your response now:
"""

        response = ollama.chat(
            model=model_name,
            messages=[{'role': 'user', 'content': prompt}],
            options={"temperature": 0.05}
        )
        content = response['message']['content'].strip()

        if content == f"Masked Log: {log_line}\nMappings:" or \
           content == f"Masked Log: {log_line}\nMappings:\n" or \
           content == f"Masked Log: {log_line}\nMappings:\n\n":
            logging.debug(f"LLM indicated no PII found for log line: {log_line}")
            return log_line, {}

        masked_log, extracted_mappings = parse_llm_response_for_masking(content, log_line)
        return masked_log, extracted_mappings

    except ollama.ResponseError as e: # Catch specific ollama errors
        logging.error(f"Ollama API error processing log '{log_line}' with model '{model_name}': {e.status_code} - {e.error}", exc_info=False) # exc_info can be noisy for ResponseError
        if e.status_code == 404: # Model not found
            logging.error(f"Model '{model_name}' not found on Ollama server. Please ensure it's pulled.")
            # Optionally, could re-raise a custom exception or exit
        return log_line, {}
    except Exception as e: # Catch other potential errors during LLM call or processing
        logging.error(f"Unexpected error during LLM processing for log '{log_line}': {e}", exc_info=True)
        return log_line, {}

def process_log_file(filepath: str, model_name: str) -> tuple[list, dict]:
    processed_log_entries = []
    logging.info(f"Starting processing of log file: {filepath}")
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                log_line = line.strip()
                if not log_line:
                    continue

                logging.debug(f"Processing log line {i+1}: {log_line[:100]}...") # Log snippet

                masked_version, pii_details = mask_log_line(log_line, model_name=model_name)

                if masked_version != log_line:
                    logging.info(f"Masked PII in line {i+1}. Original snippet: {log_line[:70]}... Masked snippet: {masked_version[:70]}...")

                processed_log_entries.append({
                    "original_log": log_line,
                    "masked_log": masked_version,
                    "pii_extracted_this_log": pii_details
                })
    except FileNotFoundError:
        logging.error(f"Log file not found: {filepath}")
        return [], pii_map
    except IOError as e:
        logging.error(f"IOError processing file {filepath}: {e}", exc_info=True)
        return processed_log_entries, pii_map # Return what was processed so far
    except Exception as e:
        logging.error(f"Unexpected error processing file {filepath}: {e}", exc_info=True)
        return processed_log_entries, pii_map

    logging.info(f"Finished processing {len(processed_log_entries)} lines from {filepath}.")
    return processed_log_entries, pii_map


def main():
    # Configure logging level via argument or keep it simple for now
    # logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    # Moved basicConfig to global scope to ensure it's set before any log calls.

    parser = argparse.ArgumentParser(description="Masks proprietary information in log files using an LLM.")
    parser.add_argument("logfile", help="Path to the input log file.")
    parser.add_argument("--model", default="llama2", help="Name of the Ollama model to use (default: llama2).")
    parser.add_argument("--output_masked", default="masked_logs_output.json", help="Path for the output JSON file with masked logs.")
    parser.add_argument("--output_pii_map", default="global_pii_reference_map.json", help="Path for the output JSON file with the global PII map.")
    parser.add_argument("--loglevel", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set the logging level (default: INFO).")

    args = parser.parse_args()

    # Set logging level from command line
    numeric_level = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {args.loglevel}')
    logging.getLogger().setLevel(numeric_level) # Set level for root logger


    global pii_map, placeholder_id_counter
    pii_map.clear()
    placeholder_id_counter = 0

    ollama_model_to_use = args.model
    logging.info(f"Using Ollama model: {ollama_model_to_use}")

    try:
        models_info = ollama.list()
        logging.info("Successfully connected to Ollama.")
        available_models = [m['name'] for m in models_info['models']]
        logging.debug(f"Available Ollama models: {available_models}")
        model_is_available = any(ollama_model_to_use in m_name for m_name in available_models)
        if not model_is_available:
            logging.warning(f"Model '{ollama_model_to_use}' not found in Ollama's list of available models. Processing will attempt to use it anyway.")
            # Consider exiting if model is critical and not found:
            # logging.critical(f"Model '{ollama_model_to_use}' not found. Exiting.")
            # sys.exit(1)
    except Exception as e:
        logging.error(f"Failed to connect to Ollama or list models: {e}. Please ensure Ollama is running.", exc_info=True)
        # Depending on severity, might exit here
        logging.critical("Exiting due to Ollama connection failure.")
        sys.exit(1) # Exit if can't connect to Ollama

    logging.info(f"Processing log file: {args.logfile}")
    processed_entries, final_pii_map = process_log_file(args.logfile, ollama_model_to_use)

    if processed_entries:
        try:
            with open(args.output_masked, "w", encoding='utf-8') as f:
                json.dump(processed_entries, f, indent=2)
            logging.info(f"Masked log entries written to {args.output_masked}")
        except IOError as e:
            logging.error(f"Error writing masked logs to {args.output_masked}: {e}", exc_info=True)
    else:
        logging.info("No log entries were processed or no output generated for masked logs.")


    if final_pii_map:
        try:
            with open(args.output_pii_map, "w", encoding='utf-8') as f:
                json.dump(final_pii_map, f, indent=2)
            logging.info(f"Global PII reference map written to {args.output_pii_map}")
        except IOError as e:
            logging.error(f"Error writing PII map to {args.output_pii_map}: {e}", exc_info=True)
    else:
        logging.info("No PII was identified or mapped globally.")

    logging.info("Log masking process completed.")

if __name__ == '__main__':
    main()
