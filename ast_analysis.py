import json
import requests
import time
from mistralai import Mistral, UserMessage
from openai import OpenAI, AzureOpenAI
import streamlit as st

import google.generativeai as genai

def ast_json_to_markdown(ast_analysis):
    markdown_output = "| Vulnerability | Severity | Mitigation |\n"
    markdown_output += "|-------------|----------|------------------|\n"
    try:
        # Access the list of threats under the "Risk Assessment" key
        defects = ast_analysis.get("AST Analysis", [])
        for defect in defects:
            # Check if threat is a dictionary
            if isinstance(defect, dict):
                vulnerability = defect.get('Vulnerability', 0)
                severity = defect.get('Severity', 0)
                mitigation = defect.get('Mitigation', 0)

                markdown_output += f"| {vulnerability} | {severity} | {mitigation} |\n"
            else:
                raise TypeError(f"Expected a dictionary, got {type(defect)}: {defect}")
    except Exception as e:
        # Print the error message and type for debugging
        st.write(f"Error: {e}")
        raise
    return markdown_output


# Function to create a prompt to generate mitigating controls
def create_ast_analysis_prompt(report):
    prompt = f"""
Act as a application security expert with more than 20 years of experience in assessing static application security testing results.
Your task is to produce a summary of the risk and potential mitigations for the vulnerabilities identified in the following AST report:
{report}
When providing the report, use a JSON formatted response with a top-level key "AST Analysis" and a list of vulnerabilities, each with the following sub-keys:
- "Vulnerability": A string summarizing the identified defect in easy-to-understand terms.
- "Severity": A string describing the qualitative risk of the defect, either 'low', 'medium', 'high' or 'critical'.
- "Mitigation": A string describing a potential fix to remediate the defect identified.
Ensure the JSON response is correctly formatted and does not contain any additional text. Here is an example of the expected JSON response format:
{{
  "AST Analysis": [
    {{
      "Vulnerability": "The variable 'username' is directly used to create a database query, which could allow for an attacker to perform unauthorized database queries.",
      "Severity": "High",
      "Mitigation": "Use an SQL sanitization library to prevent attackers from injecting SQL language into the variable"
    }},
    {{
      "Vulnerability": "The variable 'url' is stored in a C array and is not terminated with a null character. When reading the variable, memory could be accessed storing sensitive information.",
      "Severity": "Medium",
      "Mitigation": "Insert a \n character at the end of the url characters."
    }}
  ]
}}
"""
    return prompt

# Function to get AST analysis from the GPT response.
def get_ast_analysis(api_key, model_name, prompt):
    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=model_name,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": "You are a helpful assistant designed to output JSON."},
            {"role": "user", "content": prompt}
        ]
    )

    # Convert the JSON string in the 'content' field to a Python dictionary
    try:
        ast_analysis = json.loads(response.choices[0].message.content)
    except json.JSONDecodeError as e:
        st.write(f"JSON decoding error: {e}")
        ast_analysis = {}

    return ast_analysis

# Function to get AST analysis from the Azure OpenAI response.
def get_ast_analysis_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, prompt):
    client = AzureOpenAI(
        azure_endpoint = azure_api_endpoint,
        api_key = azure_api_key,
        api_version = azure_api_version,
    )

    response = client.chat.completions.create(
        model = azure_deployment_name,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": "You are a helpful assistant designed to output JSON."},
            {"role": "user", "content": prompt}
        ]
    )

    # Convert the JSON string in the 'content' field to a Python dictionary
    try:
        ast_analysis = json.loads(response.choices[0].message.content)
    except json.JSONDecodeError as e:
        st.write(f"JSON decoding error: {e}")
        ast_analysis = {}

    return ast_analysis

# Function to get AST analysis from the Google model's response.
def get_ast_analysis_google(google_api_key, google_model, prompt):
    genai.configure(api_key=google_api_key)

    model = genai.GenerativeModel(google_model)

    # Create the system message
    system_message = "You are a helpful assistant designed to output JSON. Only provide the AST analysis in JSON format with no additional text. Do not wrap the output in a code block."

    # Start a chat session with the system message in the history
    chat = model.start_chat(history=[
        {"role": "user", "parts": [system_message]},
        {"role": "model", "parts": ["Understood. I will provide AST analysis in JSON format only and will not wrap the output in a code block."]}
    ])

    # Send the actual prompt
    response = chat.send_message(
        prompt,
        safety_settings={
            'DANGEROUS': 'block_only_high' # Set safety filter to allow generation
        })
    print(response)

    try:
        # Access the JSON content from the response
        ast_analysis = json.loads(response.text)
        return ast_analysis
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {str(e)}")
        print("Raw JSON string:")
        print(response.text)
        return {}

# Function to get AST analysis from the Mistral model's response.
def get_ast_analysis_mistral(mistral_api_key, mistral_model, prompt):
    client = Mistral(api_key=mistral_api_key)

    response = client.chat.complete(
        model=mistral_model,
        response_format={"type": "json_object"},
        messages=[
            UserMessage(content=prompt)
        ]
    )

    try:
        # Convert the JSON string in the 'content' field to a Python dictionary
        ast_analysis = json.loads(response.choices[0].message.content)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {str(e)}")
        print("Raw JSON string:")
        print(response.choices[0].message.content)
        ast_analysis = {}

    return ast_analysis

# Function to get AST analysis from Ollama hosted LLM.
def get_ast_analysis_ollama(ollama_model, prompt):
    url = "http://localhost:11434/api/chat"
    max_retries = 3
    retry_delay = 2  # seconds
    if not isinstance(prompt, str):
        st.error("Prompt should be a string.")
        return {}

    for attempt in range(1, max_retries + 1):
        data = {
            "model": ollama_model,
            "stream": False,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a helpful assistant designed to output JSON. Only provide the AST analysis in JSON format with no additional text."
                },
                {
                    "role": "user",
                    "content": prompt,
                    "format": "json"
                }
            ]
        }

        try:
            response = requests.post(url, json=data)
            response.raise_for_status()  # Check for HTTP errors
            outer_json = response.json()
            response_content = outer_json.get("message", {}).get("content", "")  # Safely access content

            # Attempt to parse JSON
            ast_analysis = json.loads(response_content)
            return ast_analysis
        except requests.exceptions.HTTPError as http_err:
             st.error(f"Attempt {attempt}: HTTP error occurred: {http_err}")
             print(f"HTTP error occurred: {http_err}")
             print(f"Response: {response.text}")  # Log the full response

        except json.JSONDecodeError as e:
            st.error(f"Attempt {attempt}: Error decoding JSON. Retrying...")
            print(f"Error decoding JSON: {str(e)}")
            print("Raw JSON string:")
            print(response_content)

            if attempt < max_retries:
                time.sleep(retry_delay)
            else:
                st.error("Max retries reached. Unable to generate valid JSON response.")
                return {}

    # This line should never be reached due to the return statements above,
    # but it's here as a fallback
    return {}
