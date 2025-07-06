import pytest
from log_masker import get_or_create_placeholder, parse_llm_response_for_masking
# Import the module itself to allow modifying its global variables in tests
import log_masker

# Fixture to reset global state before each test
@pytest.fixture(autouse=True)
def reset_globals_for_test():
    log_masker.pii_map.clear()
    log_masker.placeholder_id_counter = 0

def test_get_or_create_placeholder_new():
    placeholder1 = get_or_create_placeholder("johndoe@example.com", "EMAIL")
    assert placeholder1 == "[EMAIL_1]"
    assert "johndoe@example.com" in log_masker.pii_map
    assert log_masker.pii_map["johndoe@example.com"] == "[EMAIL_1]"

    placeholder2 = get_or_create_placeholder("192.168.1.1", "IP_ADDRESS")
    assert placeholder2 == "[IP_ADDRESS_2]"
    assert "192.168.1.1" in log_masker.pii_map
    assert log_masker.pii_map["192.168.1.1"] == "[IP_ADDRESS_2]"
    assert log_masker.placeholder_id_counter == 2

def test_get_or_create_placeholder_existing():
    # Call once to create
    get_or_create_placeholder("johndoe@example.com", "EMAIL")
    assert log_masker.placeholder_id_counter == 1

    # Call again with the same value
    placeholder_again = get_or_create_placeholder("johndoe@example.com", "EMAIL")
    assert placeholder_again == "[EMAIL_1]"
    assert log_masker.placeholder_id_counter == 1 # Counter should not increment

def test_get_or_create_placeholder_type_sanitization():
    placeholder = get_or_create_placeholder("sensitive_value", "Invalid Type!@#")
    # \W+ removes !,@,#. Result: INVALIDTYPE
    assert placeholder == "[INVALIDTYPE_1]"

    placeholder2 = get_or_create_placeholder("another_value", "!@#$%^") # All special
    # \W+ removes all. Result: empty string, so defaults to DATA
    assert placeholder2 == "[DATA_2]"

    # Test type hint that becomes DATA due to length constraint (now 30)
    long_type_ok = "THISISAREALLYLONGTYPEBUTOKAYNO"  # 30 chars
    placeholder3 = get_or_create_placeholder("long_type_value_ok", long_type_ok)
    assert placeholder3 == f"[{long_type_ok}_3]" # Should use this type as len is 30 (not > 30)

    long_type_too_long = "THISISAREALLYLONGTYPEBUTOKAYNOW" # 31 chars
    placeholder4 = get_or_create_placeholder("long_type_value_too_long", long_type_too_long)
    assert placeholder4 == "[DATA_4]" # Defaults to DATA as len is 31 (> 30)

def test_parse_llm_response_perfect_format():
    llm_response = """Masked Log: User [EMAIL_ADDRESS] accessed [DATA].
Mappings:
johndoe@example.com: EMAIL_ADDRESS
secret_code: DATA
"""
    original_log = "User johndoe@example.com accessed secret_code."

    masked_log, mappings = parse_llm_response_for_masking(llm_response, original_log)

    assert masked_log == "User [EMAIL_ADDRESS_1] accessed [DATA_2]."
    assert mappings == {
        "[EMAIL_ADDRESS_1]": "johndoe@example.com",
        "[DATA_2]": "secret_code"
    }
    assert log_masker.pii_map["johndoe@example.com"] == "[EMAIL_ADDRESS_1]"
    assert log_masker.pii_map["secret_code"] == "[DATA_2]"

def test_parse_llm_response_no_pii_empty_mappings():
    llm_response = """Masked Log: This is a safe log line.
Mappings:
"""
    original_log = "This is a safe log line."
    masked_log, mappings = parse_llm_response_for_masking(llm_response, original_log)
    assert masked_log == original_log
    assert mappings == {}
    assert not log_masker.pii_map

def test_parse_llm_response_no_pii_missing_mappings_section_alt_format():
    llm_response = f"Masked Log: This is a safe log line."
    original_log = "This is a safe log line."
    masked_log, mappings = parse_llm_response_for_masking(llm_response, original_log)
    assert masked_log == original_log
    assert mappings == {}


def test_parse_llm_response_malformed_extra_text_leading():
    llm_response = """Okay, I think I found something.
Masked Log: User [EMAIL_ADDRESS] accessed stuff.
Mappings:
johndoe@example.com: EMAIL_ADDRESS
"""
    original_log = "User johndoe@example.com accessed stuff."
    masked_log, mappings = parse_llm_response_for_masking(llm_response, original_log)

    assert masked_log == "User [EMAIL_ADDRESS_1] accessed stuff."
    assert mappings == {"[EMAIL_ADDRESS_1]": "johndoe@example.com"}

def test_parse_llm_response_malformed_bad_mapping_line():
    llm_response = """Masked Log: User [EMAIL_ADDRESS] accessed stuff.
Mappings:
johndoe@example.com: EMAIL_ADDRESS
This is not a valid mapping line.
another@example.com: EMAIL_ADDRESS_TYPE_WITH_SPACES
"""
    original_log = "User johndoe@example.com and another@example.com accessed stuff."
    masked_log, mappings = parse_llm_response_for_masking(llm_response, original_log)

    assert "[EMAIL_ADDRESS_1]" in masked_log
    # pii_type_hint from parser: "EMAIL_ADDRESS_TYPE_WITH_SPACES"
    # sanitized_type in get_or_create_placeholder: "EMAIL_ADDRESS_TYPE_WITH_SPACES" (underscores kept by \W+)
    # Length 28 <= 30. So this type is used.
    assert "[EMAIL_ADDRESS_TYPE_WITH_SPACES_2]" in masked_log
    assert mappings["[EMAIL_ADDRESS_1]"] == "johndoe@example.com"
    assert mappings["[EMAIL_ADDRESS_TYPE_WITH_SPACES_2]"] == "another@example.com"
    assert len(mappings) == 2

def test_parse_llm_response_pii_value_with_colon():
    llm_response = """Masked Log: Error: Detail: [USER_IDENTIFIER]
Mappings:
User_info:name=bad_user: USER_IDENTIFIER
"""
    original_log = "Error: Detail: User_info:name=bad_user"
    masked_log, mappings = parse_llm_response_for_masking(llm_response, original_log)
    assert masked_log == "Error: Detail: [USER_IDENTIFIER_1]"
    assert mappings["[USER_IDENTIFIER_1]"] == "User_info:name=bad_user"

def test_parse_llm_response_no_mappings_section_present():
    llm_response = "Masked Log: Some text here but no mappings section."
    original_log = "Some text here but no mappings section."
    masked_log, mappings = parse_llm_response_for_masking(llm_response, original_log)
    assert masked_log == original_log
    assert mappings == {}

def test_parse_llm_response_empty_llm_content():
    llm_response = ""
    original_log = "Some original log."
    masked_log, mappings = parse_llm_response_for_masking(llm_response, original_log)
    assert masked_log == original_log
    assert mappings == {}

def test_parse_llm_response_real_world_complex_replacement():
    llm_response = """Masked Log: User [EMAIL_ADDRESS] (IP: [IP_ADDRESS]) attempted to access resource [RESOURCE_ID] owned by [USERNAME].
Mappings:
user.name@example.com: EMAIL_ADDRESS
10.20.30.40: IP_ADDRESS
RESOURCE_XYZ_12345: RESOURCE_ID
owner_user: USERNAME
"""
    original_log = "User user.name@example.com (IP: 10.20.30.40) attempted to access resource RESOURCE_XYZ_12345 owned by owner_user."
    masked_log, mappings = parse_llm_response_for_masking(llm_response, original_log)

    # Expected order due to sort by length of original value:
    # 1. user.name@example.com (EMAIL_ADDRESS, len 21) -> [EMAIL_ADDRESS_1]
    # 2. RESOURCE_XYZ_12345 (RESOURCE_ID, len 18)  -> [RESOURCE_ID_2] (Type RESOURCE_ID, len 11 <=30)
    # 3. 10.20.30.40 (IP_ADDRESS, len 11)         -> [IP_ADDRESS_3] (Type IP_ADDRESS, len 10 <=30)
    # 4. owner_user (USERNAME, len 10)          -> [USERNAME_4] (Type USERNAME, len 8 <=30)
    expected_masked_log = "User [EMAIL_ADDRESS_1] (IP: [IP_ADDRESS_3]) attempted to access resource [RESOURCE_ID_2] owned by [USERNAME_4]."
    assert masked_log == expected_masked_log
    assert mappings == {
        "[EMAIL_ADDRESS_1]": "user.name@example.com",
        "[IP_ADDRESS_3]": "10.20.30.40",
        "[RESOURCE_ID_2]": "RESOURCE_XYZ_12345",
        "[USERNAME_4]": "owner_user"
    }
    assert log_masker.pii_map["user.name@example.com"] == "[EMAIL_ADDRESS_1]"
    assert log_masker.pii_map["10.20.30.40"] == "[IP_ADDRESS_3]"
    assert log_masker.pii_map["RESOURCE_XYZ_12345"] == "[RESOURCE_ID_2]"
    assert log_masker.pii_map["owner_user"] == "[USERNAME_4]"

def test_substring_replacement_order():
    llm_response = """Masked Log: Access by [USER_EMAIL_LONG] and [USER_EMAIL_SHORT].
Mappings:
shortname@domain.com: USER_EMAIL_SHORT
very.long.shortname@domain.com: USER_EMAIL_LONG
"""
    original_log = "Access by very.long.shortname@domain.com and shortname@domain.com."
    masked_log, mappings = parse_llm_response_for_masking(llm_response, original_log)

    # pii_type_hint from parser: "USER_EMAIL_LONG" and "USER_EMAIL_SHORT"
    # sanitized_type in get_or_create_placeholder keeps underscores: "USER_EMAIL_LONG", "USER_EMAIL_SHORT"
    # Lengths are 15 and 14, both <=30. So these types are used.
    assert masked_log == "Access by [USER_EMAIL_LONG_1] and [USER_EMAIL_SHORT_2]."
    assert mappings["[USER_EMAIL_LONG_1]"] == "very.long.shortname@domain.com"
    assert mappings["[USER_EMAIL_SHORT_2]"] == "shortname@domain.com"

def test_parse_llm_response_with_special_chars_in_pii_type():
    llm_response = """Masked Log: Processed [WEIRD_TYPE_NAME].
Mappings:
some_data_abc: WEIRD TYPE NAME / V2
"""
    original_log = "Processed some_data_abc."
    masked_log, mappings = parse_llm_response_for_masking(llm_response, original_log)
    # pii_type_hint from parser: "WEIRD_TYPE_NAME_/_V2"
    # sanitized_type in get_or_create_placeholder: re.sub(r'\W+', '', "WEIRD_TYPE_NAME_/_V2") -> "WEIRD_TYPE_NAME__V2" (double underscore where / was)
    # Length 19 <=30. So this type is used.
    assert masked_log == "Processed [WEIRD_TYPE_NAME__V2_1]."
    assert mappings["[WEIRD_TYPE_NAME__V2_1]"] == "some_data_abc"
