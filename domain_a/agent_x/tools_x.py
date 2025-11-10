import base64
import re
import uuid
import json
import base58
import os
import datetime
from langchain_core.tools import tool
from pyld import jsonld
from typing import Dict
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
from pydantic import BaseModel, Field
import requests
from jsonpath_ng import parse

ROOT_PATH = os.path.dirname(os.path.abspath(__file__))
VC_PATH = os.path.join(ROOT_PATH, "agent_x_god_vc.json")
KEY_PATH = os.path.join(ROOT_PATH, "agent_x_key.json")

class CreateVPArgs(BaseModel):
    pd: Dict = Field(
        ...,
        description="The Presentation Definition to which this VP is responding."
    )


class PDArgs(BaseModel):
    """
    Pydantic model for Presentation Definition arguments.
    This model is used to validate the input for the vc_matches_pd tool.
    """
    pd: Dict = Field(
        ...,
        description="The Presentation Definition containing input descriptors and constraints."
    )

class CredentialManifestArgs(BaseModel):
    """
    Pydantic model for Credential Manifest arguments.
    """
    purpose: str = Field(
        ...,
        description="The purpose of the credential manifest."
    )

def load_vc() -> dict:
    """
    Load the Verifiable Credential (VC) from a local JSON file.
    Returns:
        dict: The Verifiable Credential as a dictionary.
    """
    with open(VC_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def load_seed() -> str:
    """
    Load the seed of Agent A from the environment variable or a file.
    Returns:
        str: The seed as a base64 encoded string.
    """
    with open(KEY_PATH, "r", encoding="utf-8") as f:
        key_data = json.load(f)
    seed = key_data.get("seed")
    did = key_data.get("did")
    print(f"[VC-LOAD] Loaded seed: {seed}")
    if not seed:
        raise ValueError("Seed not found in the key file.")
    return seed, did

def _sign_with_seed(seed: bytes, payload: bytes) -> str:
    print('[VC-SIGN] Signing payload with secret seed from the Agent Wallet:', seed.decode())
    print("\n\n")
    sig = SigningKey(seed).sign(payload).signature
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

@tool("create_presentation_definition")
def create_presentation_definition(purpose: str) -> dict:
    """
    Create a presentation definition for verifying agent credentials.
    Args:
        purpose (str): The purpose of the presentation definition.
    Returns:
        dict: The presentation definition containing input descriptors and constraints.
    """

    pd ={
        "presentation_definition": {
            "id": str(uuid.uuid4()),
            "input_descriptors": [
                {
                    "id": "vc_agent_info",
                    "name": "Agent Credential",
                    "purpose": purpose,
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.credentialSubject.id"],
                                "filter": {
                                    "type": "string",
                                    "pattern": "^did:indy:bcovrin:test:[a-zA-Z0-9]+$"
                                },
                                "purpose": "Agent's DID must be provided and follow the indy:bcovrin:test format."
                            },
                            {
                                "path": ["$.credentialSubject.role"],
                                "filter": {
                                    "type": "string",
                                    "const": "agent_a"
                                },
                                "purpose": "Agent must have role agent_a."
                            },
                            {
                                "path": ["$.credentialSubject.securityDomain"],
                                "filter": {
                                    "type": "string",
                                    "const": "domain_a"
                                },
                                "purpose": "Agent must belong to security domain domain_a."
                            }
                        ]
                    }
                }
            ]
        }
    }
    return pd

def get_did_document(did:str) -> dict:
    """
    Extract the DID document from the Verifiable Presentation (VP).
    Args:
        vp (str): The Verifiable Presentation as a JSON string.
    Returns:
        dict: The DID document extracted from the VP.
    """
    url = f"https://dev.uniresolver.io/1.0/identifiers/{did}"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        return json.dumps(data, indent=2)
    except requests.RequestException as e:
        return f"Error retrieving the DID document: {str(e)}"

@tool("check_signature_vp",infer_schema=True)
def check_signature_vp(vp: dict) -> bool:
    """
    Check the signature of the Verifiable Presentation (VP).
    Args:
        vp (dict): The Verifiable Presentation as a JSON object.
    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    vp_data = vp if isinstance(vp, dict) else json.loads(vp)
    proof = vp_data.get("proof", {})
    verification_method_url = proof.get("verificationMethod")

    # holder_did = vp_data.get("holder", "")
    holder_did = verification_method_url.split('#')[0]
    key_fragment = verification_method_url.split('#')[1] if '#' in verification_method_url else None
    
    jws = proof.get("jws", "")
    normalized = jsonld.normalize(vp_data,{"algorithm": "URDNA2015", "format": "application/n-quads"})
    try:
        print(f"[DID-RESOLVE] Resolving DID: {holder_did}")

        did_doc_json = get_did_document(did=holder_did)
        did_doc = json.loads(did_doc_json)
        if not did_doc:
            print(f"Could not resolve DID document for holder: {holder_did}")
            return False
        
        # print(f"Did Doc content: {did_doc}")

        if "didDocument" in did_doc and "verificationMethod" in did_doc["didDocument"]:
            for method in did_doc["didDocument"]["verificationMethod"]:
                # Match the full verificationMethod URL or just the fragment depending on DID method specifics
                if method.get("id") == verification_method_url:
                    public_key_base58 = method.get("publicKeyBase58")
                    break
                # Alternatively, if the method['id'] is just the fragment appended to the DID, you can do:
                elif method.get("id") == f"{holder_did}#{key_fragment}" and key_fragment:
                    public_key_base58 = method.get("publicKeyBase58")
                    break

        # verification_method = did_doc["didDocument"]["verificationMethod"][0]
        # public_key_base58 = verification_method.get("publicKeyBase58")
        print("Public Key Base58:", public_key_base58)
        pub_bytes = base58.b58decode(public_key_base58)
        verify_key = VerifyKey(pub_bytes)
        
        signature = base64.urlsafe_b64decode(jws + "==")

        verify_key.verify(normalized.encode(), signature)
        print("[VP-VERIFY] VP is valid.")
        return True
    except (BadSignatureError, json.JSONDecodeError, KeyError, TypeError) as e:
        print(f"[VP-VERIFY] Verification failed: {e}")
        return False

@tool("check_signature_vc",infer_schema=True)
def check_signature_vc(vp:dict) -> bool:
    """
    Check the signature of the Verifiable Credential (VC).
    Args:
        vp (dict): The Verifiable Presentation containing the Verifiable Credential as a JSON object.
    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    vp_data = vp if isinstance(vp, dict) else json.loads(vp)
    vc_data = vp_data.get("verifiableCredential", [{}])[0]  # We are assuming the first VC in the VP since there is only one VC in the VP
    print("------------")
    print(f"[VC-VERIFY] Verifying VC: {vc_data}")
    print("------------")
    issuer_did = vc_data.get("issuer", "")
    proof = vc_data.get("proof", {})
    verification_method_url = proof.get("verificationMethod")

    holder_did = verification_method_url.split('#')[0]
    key_fragment = verification_method_url.split('#')[1] if '#' in verification_method_url else None

    jws = proof.get("jws", "")
    normalized = jsonld.normalize(vc_data,{"algorithm": "URDNA2015", "format": "application/n-quads"})
    try:
        print(f"[DID-RESOLVE] Resolving DID: {issuer_did}")
        did_doc_json = get_did_document(did=issuer_did)
        did_doc = json.loads(did_doc_json)
        if not did_doc:
            print(f"Could not resolve DID document for issuer: {issuer_did}")
            return False

        if "didDocument" in did_doc and "verificationMethod" in did_doc["didDocument"]:
            for method in did_doc["didDocument"]["verificationMethod"]:
                # Match the full verificationMethod URL or just the fragment depending on DID method specifics
                if method.get("id") == verification_method_url:
                    public_key_base58 = method.get("publicKeyBase58")
                    break
                # Alternatively, if the method['id'] is just the fragment appended to the DID, you can do:
                elif method.get("id") == f"{holder_did}#{key_fragment}" and key_fragment:
                    public_key_base58 = method.get("publicKeyBase58")
                    break

        print("Public Key Base58:", public_key_base58)
        pub_bytes = base58.b58decode(public_key_base58)
        verify_key = VerifyKey(pub_bytes)
        
        signature = base64.urlsafe_b64decode(jws + "==")

        verify_key.verify(normalized.encode(), signature)
        print("[VC-VERIFY] VC is valid.")
        return True
    except (BadSignatureError, json.JSONDecodeError, KeyError, TypeError) as e:
        print(f"[VC-VERIFY] Verification failed: {e}")
        return False


@tool("vc_matches_pd",args_schema=PDArgs,infer_schema=True)
def vc_matches_pd(pd: Dict) -> bool:
    """
    Check if the Verifiable Credential (VC) matches the constraints defined in the Presentation Definition (PD).
    Args:
        pd (Dict): The Presentation Definition containing input descriptors and constraints.
    Returns:
        bool: True if the VC matches all constraints in the PD, False otherwise.
    """
    print("Checking VC against Presentation Definition (PD)...")
    print(f"PD: {pd}")
    vc = load_vc()
    if "presentation_definition" in pd:
        pd = pd["presentation_definition"]
    descriptors = pd.get("input_descriptors", [])
    
    print(f"Checking VC against {len(descriptors)} input descriptors in PD")
    for descriptor in descriptors:
        required_format = descriptor.get("format")
        if required_format and required_format != "ldp_vc": # Assuming load_vc() always provides an ldp_vc
            print(f"Skipping descriptor {descriptor.get('id')} due to format mismatch. Required: {required_format}, Found: ldp_vc")
            continue # Skip this descriptor if format doesn't match

        fields = descriptor.get("constraints", {}).get("fields", [])
        
        for field in fields:
            print(f"Checking field: {field.get('purpose', 'No purpose specified')}")
            for path in field.get("path", []):
                jsonpath_expr = parse(path)
                match = jsonpath_expr.find(vc)
                
                if not match:
                    return False 

                value = match[0].value
                filter_ = field.get("filter", {})

                # const kontrolü
                if "const" in filter_:
                    print(f"Checking const: {filter_['const']} against value: {value}")
                    if value != filter_["const"]:
                        return False

                # pattern kontrolü
                if "pattern" in filter_:
                    if not re.fullmatch(filter_["pattern"], value):
                        return False

    return True


@tool("create_vp", args_schema=CreateVPArgs)
def create_vp(pd: Dict) -> str:
    """
    Create a Verifiable Presentation (VP) based on the holder's Verifiable Credential (VC)
    and a given Presentation Definition (PD).
    Returns:
        str: The Verifiable Presentation as a minified JSON string.
    """
    agent_seed, holder_did = load_seed()
    vc = load_vc()

    if "presentation_definition" in pd:
        pd = pd["presentation_definition"]
    else:
        pd = pd

    # --- Step 2: Dynamically create presentation_submission ---
    presentation_submission = {
        "id": str(uuid.uuid4()), # Generate a unique ID for the submission
        "definition_id": pd["id"], # Get ID from the received PD
        "descriptor_map": []
    }

    # Iterate through input_descriptors in the PD
    # For a simple case, we assume one VC satisfies all requirements for simplicity
    # In a real scenario, you'd match VCs against each input_descriptor and potentially include multiple VCs.
    for i, input_descriptor in enumerate(pd["input_descriptors"]):
        # For this example, we assume `vc` (loaded from file) satisfies the first descriptor.
        # In a more complex scenario, we'd have logic here to find the best matching VC(s) from a set of available VCs and ensure they meet the constraints.

        # We'll hardcode the path for the single VC we loaded
        descriptor_map_entry = {
            "id": input_descriptor["id"],
            "format": "ldp_vc", # Assuming your loaded VC is an LDP_VC. Could be jwt_vc if it's a JWT.
            "path": f"$.verifiableCredential[{i}]" # Path to the corresponding VC in the VP array
                                                    # If only one VC, path would be $.verifiableCredential[0]
        }
        presentation_submission["descriptor_map"].append(descriptor_map_entry)

    # Create the VP object with the given PD
    vp ={
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://identity.foundation/presentation-exchange/submission/v1"
        ],
        # According to DIF spec, "type": ["VerifiablePresentation","PresentationSubmission"], 
        "type": [
        "VerifiablePresentation",
        "PresentationSubmission"
        ],
        "presentation_submission": presentation_submission,
        "verifiableCredential": [vc],
        "holder": vc["credentialSubject"]["id"],
    }
    # THIS IS THE VP'S PROOF (from the Holder)
    proof = {
    "type": "Ed25519Signature2020",
    "created": datetime.datetime.now().isoformat(),
    "proofPurpose": "assertionMethod",
    "verificationMethod": holder_did + "#verkey",
    "jws": ""
    }
    doc = { **vp, "proof": proof }
    normalized = jsonld.normalize(
        doc,
        {"algorithm": "URDNA2015", "format": "application/n-quads"}
    )
    seed_bytes = (agent_seed).encode()
    # This signs the normalized VP document using agent_a's (the holder's) seed.
    proof["jws"] = _sign_with_seed(seed_bytes, normalized.encode())
    # Creating the final VP object with the proof.
    signed_vp = { **vp, "proof": proof}

    return json.dumps(signed_vp, separators=(",",":"))

@tool("create_credential_manifest", args_schema=CredentialManifestArgs)
def create_credential_manifest(purpose: str) -> dict:
    """
    Create a credential manifest that defines the requirements for issuing a VC.
    Args:
        purpose (str): The purpose of the credential manifest.
    Returns:
        dict: The credential manifest containing output descriptors and constraints.
    """
    manifest = {
        "credential_manifest": {
            "id": str(uuid.uuid4()),
            "issuer": {
                "id": load_seed()[1],  # Agent X's DID
                "name": "Agent X"
            },
            "output_descriptors": [
                {
                    "id": "agent_credential",
                    "schema": "https://example.org/agent_credential_schema",
                    "name": "Agent Credential",
                    "description": "Credential proving agent status",
                    "display": {
                        "title": {
                            "path": ["$.credentialSubject.role"],
                            "fallback": "Agent Credential"
                        },
                        "subtitle": {
                            "path": ["$.credentialSubject.securityDomain"],
                            "fallback": "Security Domain"
                        }
                    },
                    "styles": {
                        "thumbnail": {
                            "uri": "https://example.org/agent_icon.png",
                            "alt": "Agent Icon"
                        }
                    }
                }
            ]
        }
    }
    return manifest

class IssueVCArgs(BaseModel):
    """
    Pydantic model for issuing a VC.
    """
    credential_application: Dict = Field(
        ...,
        description="The credential application from Agent A."
    )

@tool("issue_credential", args_schema=IssueVCArgs)
def issue_credential(credential_application: Dict) -> str:
    """
    Issue a Verifiable Credential to Agent A based on their credential application.
    Args:
        credential_application (Dict): The credential application from Agent A.
    Returns:
        str: The signed Verifiable Credential as a JSON string.
    """
    agent_seed, issuer_did = load_seed()
    
    # Extract Agent A's DID from the credential application
    holder_did = credential_application.get("holder", {}).get("id")
    
    # Create the VC
    vc = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": f"urn:uuid:{str(uuid.uuid4())}",
        "type": ["VerifiableCredential", "AgentCredential"],
        "issuer": issuer_did,
        "issuanceDate": datetime.datetime.now().isoformat(),
        "credentialSubject": {
            "id": holder_did,
            "role": "agent_a",
            "securityDomain": "domain_a",
            "issuedBy": issuer_did
        }
    }
    
    # Create and add the proof
    proof = {
        "type": "Ed25519Signature2020",
        "created": datetime.datetime.now().isoformat(),
        "proofPurpose": "assertionMethod",
        "verificationMethod": f"{issuer_did}#verkey",
        "jws": ""
    }
    
    # Sign the VC
    doc = {**vc, "proof": proof}
    normalized = jsonld.normalize(
        doc,
        {"algorithm": "URDNA2015", "format": "application/n-quads"}
    )
    seed_bytes = agent_seed.encode()
    proof["jws"] = _sign_with_seed(seed_bytes, normalized.encode())
    
    # Create the final signed VC
    signed_vc = {**vc, "proof": proof}
    
    return json.dumps(signed_vc, separators=(",", ":"))