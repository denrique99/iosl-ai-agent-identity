from mcp.server.fastmcp import FastMCP
from typing import Dict
from issuer_tools import (
    load_vc, load_seed, _sign_with_seed,
    create_presentation_definition, 
    check_signature_vp, check_signature_vc, vc_matches_pd, 
    create_vp, create_credential_manifest, issue_credential,
    CreateVPArgs  # Import the Pydantic model
)
import logging
import json
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

@mcp.tool()
def create_presentation_definition_tool(purpose: str) -> dict:
    """
    Create a presentation definition for verifying agent credentials.
    Args:
        purpose (str): The purpose of the presentation definition.
    Returns:
        dict: The presentation definition containing input descriptors and constraints.
    """
    return create_presentation_definition(purpose)

@mcp.tool()
def check_signature_vp_tool(vp: dict) -> bool:
# def check_signature_vp_tool(vp: Union[str, dict]) -> bool:
    """
    Check the signature of the Verifiable Presentation (VP).
    Args:
        vp (Union[str, dict]): The Verifiable Presentation as a JSON object or string.
    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    return check_signature_vp(vp)

@mcp.tool()
def check_signature_vc_tool(vp:dict) -> bool:
    """
    Check the signature of the Verifiable Credential (VC).
    Args:
        vp (dict): The Verifiable Presentation containing the Verifiable Credential as a JSON object.
    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    return check_signature_vc(vp)

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
def create_vp_tool(pd: Dict) -> str:
    """
    Create a Verifiable Presentation (VP) based on the holder's Verifiable Credential (VC)
    and a given Presentation Definition (PD).
    Args:
        pd (Dict): The Presentation Definition to which this VP is responding.
    Returns:
        str: The Verifiable Presentation as a minified JSON string.
    """
    # Validate input using the Pydantic model
    try:
        # Use the imported CreateVPArgs to validate pd parameter
        args_model = CreateVPArgs(pd=pd)
        validated_pd = args_model.pd
    except Exception as e:
        logger.error(f"Validation error: {e}")
        raise ValueError(f"Invalid presentation definition format: {e}")
    
    if not validated_pd:
        raise ValueError("A presentation definition is required")
        
    # Create the VP with the validated pd
    created_vp = create_vp(validated_pd)
    
    # Log the created VP
    logger.info(f"Created VP: \n {created_vp}")
    
    # Return the VP as a JSON string (create_vp now always returns a JSON string)
    return created_vp

@mcp.tool()
def create_credential_manifest_tool(purpose: str) -> dict:
    """
    Create a credential manifest that defines the requirements for issuing a VC.
    Args:
        purpose (str): The purpose of the credential manifest.
    Returns:
        dict: The credential manifest containing output descriptors and constraints.
    """
    return create_credential_manifest(purpose)

@mcp.tool()
def issue_credential_tool(credential_application: Dict) -> str:
    """
    Issue a Verifiable Credential to Agent A based on their credential application.
    Args:
        credential_application (Dict): The credential application from Agent A.
    Returns:
        str: The signed Verifiable Credential as a JSON string.
    """
    return issue_credential(credential_application)

# run the server (do it from client code for prototype, not here)
if __name__ == "__main__":
    mcp.run(transport="stdio")
    
# To run the server:
# mcp dev mcp_server_issuer_tools.py to start with inspector / debugging web interface