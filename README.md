# IoSL AI Agent Identity

## Overview
This project implements a framework for decentralized identity management and authentication for and using AI agents. It includes various components that facilitate the creation, management, and interaction of agents within a decentralized environment. For a detailed view see "IoSL__AI_Agents_with_Digital_Identities.pdf"

## Project Structure
```
iosl-ai-agent-identity/
├── domain_a/ 
├── domain_b/ # Domain B logic
├── google_a2a/ # A2A communication example
├── requirements.txt    # Python dependencies
├── .env                # Environment variables for OPENAI_API_KEY
├── .gitignore
├── README.md
├── venv/               # Python virtual environment until docker setup 

```

## Installation and Virtual Environment Setup (until docker)
To set up the project, follow these steps:

Clone the repository:
   ```
   git clone <repository-url>
   cd iosl-ai-agent-identity
   ```



- **Python 3.12.10** must be installed and available as `python3.12` or `python`
- Recommended: virtual environment usage (`venv`)
- An OpenAI API key required in .env

### macOS / Linux

```bash
# Navigate to project root
cd iosl-ai-agent-identity
```

#### Create virtual environment
```bash
python3 -m venv venv
```

#### Activate it
```bash
source venv/bin/activate
```

#### Install dependencies
```bash
pip install -r requirements.txt
```

### Windows (PowerShell)

```bash
cd iosl-ai-agent-identity

python -m venv venv
venv\Scripts\Activate


pip install -r requirements.txt
```
## Running the Project
```bash
# From the project root: (iosl-ai-agent-identity)
# Set Python path (for agent imports to work)

# macOS/Linux
export PYTHONPATH=.

# Windows (PowerShell)
$env:PYTHONPATH = "."

```

# Run the Domain A
```
python domain_a/main.py
```
# Run the Domain B
```
python domain_b/main.py
```
# Run Google A2A Communication
First, in the root run
```
pip install -e .
```

Then, create two terminals. In the first terminal,first run
```
python google_a2a/main.py
```

In the second terminaol, run
```
python google_a2a/client.py
```

# Manually Registering a DID on the BCovrin Test Ledger

1. Open the following page in your browser:
http://test.bcovrin.vonx.io/

2. In the "Authenticate a New DID" section:

- Select “Register from seed”
- Enter a random 32-character wallet seed
Example: 000000000000000000000000Steward1
- Leave DID blank – it will be created automatically
- (Optional) Enter an Alias for your DID
- Select ENDORSER as Role

3. Click “Register DID”
4. If the seed is linked to a DID with write permissions, your new DID will be successfully written to the ledger.

Note:
If you receive an error like Error: identity not registered, it means the seed you provided does not belong to a DID with ledger write access.

Once registered, you can resolve your new DID using the Universal Resolver.



