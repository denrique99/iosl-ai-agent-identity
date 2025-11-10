import json
from mcp.server.fastmcp import FastMCP
from typing import Dict
from holder_tools import (
    create_presentation_definition_agent_a, get_did_document, load_vc, load_seed, _sign_with_seed, create_vp, save_credential, 
    send_message_to_host, vc_matches_pd,check_drone_matches_pd, create_presentation_definition_agent_y,
    check_signature_vp, check_signature_vc, create_credential_application
)
import sys
import logging
import os
# Set up logging
log_file_path = os.path.join(os.getcwd(), "mcp_debug.log")

logging.basicConfig(
    filename=log_file_path,
    filemode='a',  # append mode
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    force=True 
)

logger = logging.getLogger(__name__)
logger.info("Logging initialized.")
# Create a MCP server instance
mcp = FastMCP(
    name = "MCP Server",
    host = "0.0.0.0",
    port = 8050,
)

@mcp.tool()
def load_vc_tool() -> dict:
    """
    Load the Verifiable Credential (VC) from a local JSON file.
    Returns:
        dict: The Verifiable Credential as a dictionary.
    """
    return load_vc()

@mcp.tool()
def load_seed_tool() -> str:
    """
    Load the seed of Agent A from the environment variable or a file.
    Returns:
        str: The seed as a base64 encoded string.
    """
    return load_seed()

@mcp.tool()
def _sign_with_seed_tool(seed: bytes, payload: bytes) -> str:
    """
    Signing payload with secret seed from the Agent Wallet
    Returns:
        str: The JWS (JSON Web Signature) of the signed payload.
    """
    return _sign_with_seed(seed, payload)

@mcp.tool(name="create_vp_tool")
def create_vp_tool(pd: Dict) -> dict:
    """
    Create a Verifiable Presentation (VP) based on the holder's Verifiable Credential (VC)
    and a given Presentation Definition (PD).
    Returns:
        dict: The Verifiable Presentation as a minified JSON object.
    """
    created_vp= create_vp(pd)
    logger.info(f"Created VP: \n {json.dumps(created_vp, indent=2)}")
    return created_vp
    
# @mcp.tool()
# def create_vp_tool(args: CreateVPArgs) -> str:
#     """
#     Create a Verifiable Presentation (VP) based on the holder's Verifiable Credential (VC)
#     and a given Presentation Definition (PD).
#     Returns:
#         dict: The Verifiable Presentation as a minified JSON object.
#     """
#     return create_vp(args.pd)

@mcp.tool()
def vc_matches_pd_tool(pd: Dict) -> bool:
    """
    Check if the Verifiable Credential (VC) matches the constraints defined in the Presentation Definition (PD).
    Args:
        pd (Dict): The Presentation Definition containing input descriptors and constraints.
    Returns:
        bool: True if the VC matches all constraints in the PD, False otherwise.
    """
    return vc_matches_pd(pd) 

@mcp.tool()
def create_presentation_definition_agent_a_tool(purpose: str) -> Dict:
    """
    Create a Presentation Definition (PD) for Agent A.
    Args:
        purpose (str): The purpose of the PD, e.g., "Verify my identity".
    Returns:
        Dict: The Presentation Definition as a dictionary.
    """
    # This function would create a PD tailored for Agent A's requirements
    # For now, we can return a simple example PD
    logger.info(f"Creating Presentation Definition for Agent A with purpose:\n {purpose}")
    return create_presentation_definition_agent_a(purpose=purpose)

@mcp.tool()
def create_presentation_definition_agent_y_tool(purpose: str) -> Dict:
    """
    Create a Presentation Definition (PD) for Agent Y.
    Args:
        purpose (str): The purpose of the PD, e.g., "Verify my identity".
    Returns:
        Dict: The Presentation Definition as a dictionary.
    """
    # This function would create a PD tailored for Agent Y's requirements
    # For now, we can return a simple example PD
    logger.info(f"Creating Presentation Definition for Agent Y with purpose:\n {purpose}")
    return create_presentation_definition_agent_y(purpose=purpose)

@mcp.tool(name="check_signature_vp_tool")
def check_signature_vp_tool(vp: Dict) -> bool:
    """
    Check the signature of a Verifiable Presentation (VP).
    Args:
        vp (Dict): The Verifiable Presentation to check.
    Returns:
        bool: True if the VP's signature is valid, False otherwise.
    """
    logger.info(f"Checking signature of VP: \n {json.dumps(vp, indent=2)}")
    return check_signature_vp(vp)

@mcp.tool(name="check_signature_vc_tool")
def check_signature_vc_tool(vp: Dict) -> bool:
    """
    Check the signature of a Verifiable Credential (VC) within a Verifiable Presentation (VP).
    Args:
        vp (Dict): The Verifiable Presentation
    Returns:
        bool: True if the VC's signature is valid, False otherwise.
    """
    logger.info(f"Checking signature of VC in VP: \n {vp}")
    return check_signature_vc(vp)


@mcp.tool()
def get_did_document_tool(did:str) -> dict:
    """
    Extract the DID document from the Verifiable Presentation (VP).
    Args:
        vp (str): The Verifiable Presentation as a JSON string.
    Returns:
        dict: The DID document extracted from the VP.
    """
    return get_did_document(did)


@mcp.tool()
def create_credential_application_tool(credential_manifest: Dict) -> str:
    """
    Create a credential application based on the received credential manifest.
    Args:
        credential_manifest (Dict): The credential manifest from Agent X.
    Returns:
        str: The credential application as a JSON string.
    """
    return create_credential_application(credential_manifest)

@mcp.tool()
def save_credential_tool(vc: Dict) -> bool:
    """
    Save a received Verifiable Credential to a local file.
    Args:
        vc (Dict): The Verifiable Credential to save.
    Returns:
        bool: True if the VC was saved successfully, False otherwise.
    """
    return save_credential(vc)

@mcp.tool(name="check_drone_matches_pd_tool")
def check_drone_matches_pd_tool(pd: Dict) -> bool:
    """
    Check if the drone's Verifiable Credential (VC) matches the constraints defined in the Presentation Definition (PD).
    Args:
        pd (Dict): The Presentation Definition containing input descriptors and constraints.
    Returns:
        bool: True if the VC matches all constraints in the PD, False otherwise.
    """
    logger.info(f"Checking if drone matches PD: \n {pd}")
    return check_drone_matches_pd(pd)

@mcp.tool()
async def send_message_to_host_tool(agent_name: str,message:str = None, data: dict = None) -> Dict:
    """
    Send a message to the agent.
    Args:
        agent_name (str): The name of the agent to send the message to.
        message (str): Brief description of the message to send.
        data (dict): Additional data to send with the message.
    Returns:
        Dict: The response from the host agent.
    """
    logger.info(f"Sending message to host agent: {agent_name}")
    if not agent_name:
        raise ValueError("Agent name must be provided.")
    
    if not message and not data:
        raise ValueError("Either message or data must be provided.")
    response = await send_message_to_host(agent_name, message, data)
    
    return response

# run the server (do it from client code for prototype, not here)
if __name__ == "__main__":
    mcp.run(transport="stdio")
    
# To run the server manually:
# uv run mcp_server_holder_tools.py or python mcp_server_holder_tools.py
# mcp dev mcp_server_holder_tools.py to start with inspector / debugging web interface