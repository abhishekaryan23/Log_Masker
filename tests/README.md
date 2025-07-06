# Testing the LLM Log Masker

This directory contains unit tests for the `log_masker.py` application. The tests are written using the `pytest` framework.

## Purpose of Tests

The unit tests focus on verifying the correctness of the core Python logic within `log_masker.py`, specifically:

-   **Placeholder Generation (`get_or_create_placeholder`):**
    -   Ensuring consistent placeholder creation for the same PII.
    -   Correct incrementing of unique IDs for new PII.
    -   Proper handling of PII type suggestions, including sanitization and length constraints.
-   **LLM Response Parsing (`parse_llm_response_for_masking`):**
    -   Correctly parsing well-formatted responses from the LLM.
    -   Gracefully handling various malformed or unexpected LLM response structures.
    -   Accurately extracting PII mappings from the LLM response.
    -   Properly reconstructing the masked log line using consistent placeholders.
    -   Handling cases where no PII is identified.

These tests are designed to run without requiring a live Ollama server or a specific LLM model, as they mock the LLM's responses to test the script's processing logic.

## Running the Tests

1.  **Navigate to the Project Root Directory:**
    Open your terminal or command prompt and ensure you are in the main project directory (the one containing `log_masker.py` and this `tests` folder).

2.  **Install Dependencies (if not already done):**
    The primary dependency for running tests is `pytest`, which is included in the main `requirements.txt` file.
    From the **project root directory** (where `requirements.txt` is located):
    ```bash
    # Activate your virtual environment if you're using one
    # source venv/bin/activate  (Linux/macOS)
    # venv\Scripts\activate    (Windows)

    pip install -r requirements.txt
    ```

3.  **Execute Pytest:**
    From the **project root directory**, run the following command:
    ```bash
    pytest
    ```
    This command will automatically discover and run the tests in the `tests` directory.

    Alternatively, you can specify the tests directory or file:
    ```bash
    pytest tests/
    ```
    or
    ```bash
    pytest tests/test_log_masker.py
    ```

    **Python Path:**
    In most cases, running `pytest` from the project root should handle Python's import paths correctly. If you encounter `ModuleNotFoundError` for `log_masker`, you can explicitly add the project root to your `PYTHONPATH` before running the tests:
    -   Linux/macOS:
        ```bash
        export PYTHONPATH=$PYTHONPATH:.
        pytest tests/
        ```
    -   Windows (Command Prompt):
        ```bash
        set PYTHONPATH=%PYTHONPATH%;.
        pytest tests/
        ```
    -   Windows (PowerShell):
        ```bash
        $env:PYTHONPATH += ";."
        pytest tests/
        ```

## Expected Output

If all tests pass, you will see a summary indicating the number of passed tests, for example:

```
============================= test session starts ==============================
...
collected 14 items

tests/test_log_masker.py ..............                                  [100%]

============================== 14 passed in 0.XXs ==============================
```

If any tests fail, `pytest` will provide detailed error messages, highlighting the specific assertions that failed and the differences between expected and actual results. This information is crucial for debugging.
```
