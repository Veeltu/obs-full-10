"""
Config-Driven JSON Proxy with Production-Ready Logging

Environment Variables:
- LOG_LEVEL: Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Default: INFO
- LOG_FORMAT: Set log format (simple, detailed). Default: detailed
- DEBUG: Enable Flask debug mode (true/false). Default: false

Usage Examples:
- Production: LOG_LEVEL=WARNING LOG_FORMAT=simple
- Development: LOG_LEVEL=DEBUG LOG_FORMAT=detailed DEBUG=true
"""

from flask import Flask, jsonify, abort
import yaml
import os
import requests
import logging
from urllib3.exceptions import InsecureRequestWarning

# TODO: research documentation on how to set up
# Setup logging
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.environ.get("LOG_FORMAT", "detailed")

# Validate log level
if LOG_LEVEL not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
    # logger.warning(f"Invalid LOG_LEVEL '{LOG_LEVEL}', defaulting to INFO")
    LOG_LEVEL = "INFO"

# Choose format based on environment
if LOG_FORMAT == "simple":
    log_format = '%(levelname)s - %(message)s'
elif LOG_FORMAT == "detailed":
    log_format = '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
else:
    log_format = '%(asctime)s - %(levelname)s - %(message)s'

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format=log_format,
    handlers=[
        logging.StreamHandler(),
        # logging.FileHandler('proxy.log') 
    ]
)
logger = logging.getLogger(__name__)

# ============================================================
# FLASK APP SETUP
# ============================================================
app = Flask(__name__)

# Turn off SSL warnings (not recommended for production)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# ============================================================
# LOAD CONFIGURATION
# ============================================================
def load_config():
    """Load the YAML configuration file."""
    config_paths = [
        "config.yaml",  # Local development
        "/config/config.yaml"  # Docker container
    ]
    
    logger.debug(f"Attempting to load config from paths: {config_paths}")
    
    for config_path in config_paths:
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f)
                if config:
                    logger.info(f"Successfully loaded config from: {config_path}")
                    return config
                else:
                    logger.warning(f"Config file {config_path} is empty")
                    continue
        except FileNotFoundError:
            logger.debug(f"Config file not found at: {config_path}")
            continue
        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error in {config_path}: {e}")
            continue
        except Exception as e:
            logger.error(f"Unexpected error loading config from {config_path}: {e}")
            continue
    
    logger.error("No valid config file found in any of the expected locations!")
    return {}

# Load config at startup
config = load_config()

# Get list of hosts from config
HOSTS = config.get("hosts", [])
if not HOSTS:
    logger.warning("No hosts configured in config file, using default localhost")
    HOSTS = ["http://localhost"]
else:
    logger.info(f"Configured {len(HOSTS)} hosts: {HOSTS}")

# Get login URL from config
LOGIN_URL = config.get("login_url", "/api/login")
logger.debug(f"Using login URL: {LOGIN_URL}")

# ============================================================
# HELPER FUNCTIONS
# ============================================================

auth_config = config.get("auth", {})
username = os.environ.get(auth_config.get("username_env", ""))
password = os.environ.get(auth_config.get("password_env", ""))

def get_host_header(host_url):
    """
    Extract a clean hostname for "Host" HTTP header (strip https:// etc.).
    """
    h = host_url.replace("https://", "").replace("http://", "")
    h = h.split("/")[0]
    if ":" in h:
        h = h.split(":")[0]
    
    logger.debug(f"Extracted host header: {host_url} -> {h}")
    return h

def get_auth_headers():
    """Get authentication headers by logging in and obtaining token."""

    # If both are set, login and get token
    if username and password:
        logger.debug("Username and password configured, attempting login")
        try:
            # Build full login URL
            host = HOSTS[0]  # Use first host for login
            if LOGIN_URL.startswith("/"):
                login_url = host + LOGIN_URL
            else:
                login_url = host + "/" + LOGIN_URL
            
            # Get host header for login
            host_header = get_host_header(host)
            
            # Login to get token
            login_headers = {
                "Content-Type": "application/json",
                "Accept": "*/*",
                "Host": host_header
            }
            
            login_resp = requests.post(
                login_url,
                json={"username": username, "password": password},
                headers=login_headers,
                timeout=10,
                verify=False
            )
            login_resp.raise_for_status()
            
            access_token = login_resp.json().get("token")
            if access_token:
                logger.debug("Successfully obtained authentication token")
                # Return headers with token and proper Host header
                headers = {
                    "AuthToken": access_token, 
                    "Accept": "*/*",
                    "Host": host_header
                }
                logger.debug("Returning authentication headers with token")
                return headers
            else:
                logger.error("No token received from login response")
                return {}
                
        except requests.exceptions.Timeout:
            logger.error("Login request timed out")
            return {}
        except requests.exceptions.RequestException as e:
            logger.error(f"Login request failed: {e}")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error during login: {e}")
            return {}
    
    # No auth configured or login failed
    if not username or not password:
        logger.debug("Authentication not configured (missing username or password)")
    else:
        logger.debug("Authentication failed, returning empty headers")
    
    logger.debug("Returning empty authentication headers")
    return {}

def build_full_url(path, host_index=0):
    """Convert relative path to full URL using one of the configured hosts."""
    # If it's already a full URL, return as-is
    if path.startswith("http"):
        logger.debug(f"Path is already a full URL: {path}")
        return path
    
    # Get host from our list (round-robin style)
    host = HOSTS[host_index % len(HOSTS)]
    
    # Combine host and path
    if path.startswith("/"):
        full_url = host + path
    else:
        full_url = f"{host}/{path}"
    
    logger.debug(f"Built full URL: {path} -> {full_url}")
    return full_url

def fetch_data(url, headers):
    """Fetch JSON data from a URL."""
    try:
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        response.raise_for_status()  # Raise error for bad status codes
        return response.json()
    except requests.exceptions.Timeout:
        logger.error(f"Timeout fetching {url}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error fetching {url}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching {url}: {e}")
        return None

# ============================================================
# DISCOVERY PATTERN FUNCTIONS
# ============================================================
def extract_ids_from_response(response_data, path_to_ids):
    """
    Extract IDs from API response by finding all 'id' keys recursively.
    
    This function searches through the entire data structure and returns
    all values found under 'id' keys, regardless of the structure.
    """
    if not path_to_ids:
        return []
    
    logger.debug(f"Extracting IDs from response, path_to_ids: {path_to_ids}")
    logger.debug(f"Response data type: {type(response_data)}")
    
    # Simple function to find all 'id' values recursively
    def find_all_ids(data, ids=None):
        if ids is None:
            ids = []
        
        if isinstance(data, dict):
            # If this dict has an 'id' key, add its value
            if 'id' in data:
                ids.append(data['id'])
                logger.debug(f"Found ID: {data['id']}")
            
            # Recursively search all values in this dict
            for value in data.values():
                find_all_ids(value, ids)
                
        elif isinstance(data, list):
            # Recursively search all items in this list
            for item in data:
                find_all_ids(item, ids)
        
        return ids
    
    # Find all IDs
    all_ids = find_all_ids(response_data)
    logger.info(f"Extracted {len(all_ids)} IDs from response")
    logger.debug(f"Extracted IDs: {all_ids}")
    
    return all_ids

def handle_discovery_route(route_config):
    """
    Handle a route that uses the discovery pattern.
    
    This means:
    1. First, fetch a list of items from one endpoint
    2. Then, for each item, fetch detailed data
    """
    discovery_config = route_config.get("discovery")
    per_item_config = route_config.get("per_item")
    
    if not discovery_config:
        logger.error("Discovery pattern configured but no discovery config found")
        return []
    
    if not per_item_config:
        logger.error("Discovery pattern configured but no per_item config found")
        return []
    
    # Step 1: Get the list of items
    discovery_url = discovery_config.get("url")
    if not discovery_url:
        logger.error("Discovery config missing 'url' field")
        return []
    
    discovery_url = build_full_url(discovery_url)
    headers = get_auth_headers()
    
    logger.info(f"Starting discovery from: {discovery_url}")
    discovery_response = fetch_data(discovery_url, headers)
    
    if not discovery_response:
        logger.error(f"Failed to get discovery data from {discovery_url}")
        return []
    
    # Step 2: Extract the IDs from the response
    path_to_ids = discovery_config.get("items_path", "")
    item_ids = extract_ids_from_response(discovery_response, path_to_ids)
    
    if not item_ids:
        logger.warning(f"No items found during discovery from {discovery_url}")
        return []
    
    logger.info(f"Processing {len(item_ids)} discovered items")
    
    # Step 3: For each ID, fetch detailed data
    results = []
    url_template = per_item_config.get("url_template")
    
    if not url_template:
        logger.error("Per-item config missing 'url_template' field")
        return []
    
    for i, item_id in enumerate(item_ids):
        # Replace {item} in the template with the actual ID
        item_url = url_template.replace("{item}", str(item_id))
        full_url = build_full_url(item_url, i)
        
        logger.debug(f"Fetching details for item {item_id} from: {full_url}")
        item_data = fetch_data(full_url, headers)
        
        if item_data:
            # Check if transform is configured for this route
            transform = per_item_config.get("transform", "none")
            
            if transform == "attach_id":
                # Add the ID directly to item_data
                if isinstance(item_data, dict):
                    item_data["id"] = item_id
                    result = item_data
                else:
                    result = {"id": item_id, "data": item_data}
            else:
                # No transform, just return the data
                result = item_data
            
            results.append(result)
            
        else:
            logger.warning(f"Failed to fetch data for item {item_id} from {full_url}")
    
    logger.info(f"Successfully processed {len(results)} out of {len(item_ids)} items")
    return results

def handle_standard_route(route_config):
    """
    Handle a standard route that just fetches from a list of endpoints.
    """
    upstreams = route_config.get("upstreams", [])
    
    if not upstreams:
        logger.warning("No upstream endpoints configured for this route")
        return []
    
    results = []
    
    logger.info(f"Fetching from {len(upstreams)} upstream endpoints")
    
    # Fetch data from each upstream endpoint
    for i, upstream in enumerate(upstreams):
        full_url = build_full_url(upstream, i)
        logger.debug(f"Fetching from: {full_url}")
        
        headers = get_auth_headers()
        data = fetch_data(full_url, headers)
        
        if data:
            # Build safe stub based on last part of path with data_api_ prefix
            # Fix: Handle cases where split doesn't work as expected
            # Extract just the path part, not the full URL
            path_part = upstream.lstrip('/')  # Remove leading slash
            path_parts = path_part.split("/")
            
            if len(path_parts) > 1:
                # Get the last meaningful part of the path
                path = path_parts[-1] if path_parts[-1] else path_parts[-2]
            else:
                path = path_part
            
            path = path.replace("/", "_")
            
            # Add path-based key to the response with data_api_ prefix
            results.append({
                f"data_api_{path}": data
            })
        else:
            logger.warning(f"Failed to fetch from: {full_url}")
    
    if results:
        logger.info(f"Successfully fetched data from {len(results)} out of {len(upstreams)} endpoints")
    else:
        logger.warning(f"No data fetched from any of {len(upstreams)} endpoints")
    return results

# ============================================================
# ROUTE HANDLER
# ============================================================
def create_route_handler(route_config):
    """
    Create a handler function for a specific route.
    This function will be called when someone visits the route.
    """
    def handler():
        route_path = route_config.get("path", "unknown")
        logger.info(f"Handling request for route: {route_path}")
        
        # Check if this route uses discovery pattern
        if "discovery" in route_config:
            logger.debug("Using discovery pattern")
            results = handle_discovery_route(route_config)
        else:
            logger.debug("Using standard pattern")
            results = handle_standard_route(route_config)
        
        # Check if we got any results
        if not results:
            logger.error(f"No results found for route {route_path}, returning error")
            abort(502, description="No data available")
        
        logger.info(f"Successfully processed route {route_path}, returning {len(results)} results")
        return jsonify(results)
    
    return handler

# ============================================================
# REGISTER ALL ROUTES
# ============================================================
def register_routes():
    """Register all routes from the configuration file."""
    routes = config.get("routes", [])
    
    if not routes:
        logger.warning("No routes configured in config file")
        return
    
    logger.info(f"Registering {len(routes)} routes...")
    
    for route in routes:
        path = route.get("path")
        if not path:
            logger.error("Route missing 'path' field, skipping")
            continue
            
        name = route.get("name", path)
        
        logger.debug(f"Registering route: {path}")
        
        # Create the handler function for this route
        handler = create_route_handler(route)
        
        # Register the route with Flask
        app.add_url_rule(path, endpoint=name, view_func=handler, methods=["GET"])
    
    logger.info(f"Successfully registered {len(routes)} routes")

# Register all routes
register_routes()

# ============================================================
# UTILITY ENDPOINTS
# ============================================================
@app.route("/health")
def health_check_endpoint():
    """Simple health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "config-driven-proxy",
        "hosts": HOSTS
    })

@app.route("/config")
def show_config():
    """Show the current configuration (without sensitive data)."""
    safe_config = {
        "hosts": HOSTS,
        "loginurl": LOGIN_URL,
        "routes": [{"path": r["path"], "name": r.get("name", "")} for r in config.get("routes", [])],
        "auth_configured": bool(config.get("auth", {})),
        "logging": {
            "level": LOG_LEVEL,
            "format": LOG_FORMAT
        }
    }
    return jsonify(safe_config)

# @app.route("/loglevel/<level>")
# def set_log_level(level):
#     """Dynamically change log level (for debugging purposes)."""
#     global LOG_LEVEL
    
#     level = level.upper()
#     if level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
#         old_level = LOG_LEVEL
#         LOG_LEVEL = level
        
#         # Update the logger level
#         logger.setLevel(getattr(logging, level))
        
#         logger.info(f"Log level changed from {old_level} to {level}")
#         return jsonify({
#             "status": "success",
#             "message": f"Log level changed from {old_level} to {level}",
#             "old_level": old_level,
#             "new_level": level
#         })
#     else:
#         return jsonify({
#             "status": "error",
#             "message": f"Invalid log level: {level}",
#             "valid_levels": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
#         }), 400

# ============================================================
# START THE APP
# ============================================================
if __name__ == "__main__":
    logger.info("Starting Config-Driven Proxy...")
    logger.info(f"Configured hosts: {HOSTS}")
    logger.info(f"Configured routes: {len(config.get('routes', []))}")
    logger.info(f"Log level: {LOG_LEVEL}")
    logger.info(f"Log format: {LOG_FORMAT}")
    
    # Use environment variable for debug mode
    debug_mode = os.environ.get("DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)

