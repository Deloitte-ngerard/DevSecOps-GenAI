The GenAI4DSO application allows for application security practitioners to more easily leverage Large Language Models (LLMs) to accelerate a variety of activities such as threat modeling, analysis of results from static code testing (SAST) or dynamic testing (DAST), etc.

The application is based on the Stride GPT project: 
STRIDE GPT is an AI-powered threat modelling tool that leverages Large Language Models (LLMs) to generate threat models and attack trees for a given application based on the STRIDE methodology. Users provide application details, such as the application type, authentication methods, and whether the application is internet-facing or processes sensitive data. The model then generates its output based on the provided information.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [License](#license)


## Features
- Generates threat models based on the STRIDE methodology
- Multi-modal: Use architecture diagrams, flowcharts, etc. as inputs for threat modeling 
- Generates attack trees to enumerate possible attack paths
- Suggests possible mitigations for identified threats
- Supports DREAD risk scoring for identified threats
- Generates Gherkin test cases based on identified threats
- GitHub repository analysis for comprehensive threat modelling
- AST report Analysis
- Note: there is no data storage; application details are not saved
- Supports models accessed via OpenAI API, Azure OpenAI Service, Google AI API, Mistral API, or locally hosted models via Ollama


## Installation

### Option 1: Cloning the Repository

1. Clone this repository:

2. Change to the cloned repository directory:

3. Install the required Python packages:

    ```bash
    pip install -r requirements.txt
    ```

4. Set up environment variables:
   
   a. Copy the `.env.example` file to a new file named `.env`:
   ```
   cp .env.example .env
   ```
   
   b. Edit the `.env` file and add your API keys:
   ```
   GITHUB_API_KEY=your_actual_github_api_key
   OPENAI_API_KEY=your_actual_openai_api_key
   # ... add other API keys as needed
   ```

## Usage

### Option 1: Running the Streamlit App Locally

1. Run the Streamlit app:

    ```bash
    streamlit run main.py
    ```

2. Open the app in your web browser using the provided URL.

3. Follow the steps in the Streamlit interface.

### Option 2: Using Docker Container

1. Run the Docker container, mounting the `.env` file:

    ```bash
    docker run -p 8501:8501 --env-file .env <Name of Docker Image>
    ```
    This command will start the container, map port 8501 (default for Streamlit apps) from the container to your host machine, and load the environment variables from the `.env` file.

2. Open a web browser and navigate to `http://localhost:8501` to access the app running inside the container.

3. Follow the steps in the Streamlit interface.

Note: When you run the application (either locally or via Docker), it will automatically load the environment variables you've set in the `.env` file. This will pre-fill the API keys in the application interface.

## License

[MIT](https://choosealicense.com/licenses/mit/)
