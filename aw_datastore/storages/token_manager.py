"""
Token Manager - JSON-based storage for authentication tokens and API URLs

This module provides a simple, file-based storage system for authentication tokens
and API URLs, replacing the previous SQLite-based storage approach.

Features:
- JSON file-based storage for human readability
- Cross-platform compatibility
- Atomic file operations
- Automatic directory creation
- Error handling and logging
"""

import json
import os
import logging
import base64
from datetime import datetime
from typing import Optional, Tuple, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class TokenManager:
    """
    JSON-based token storage manager for authentication tokens and API URLs.
    
    This class handles the storage, retrieval, and deletion of authentication
    tokens and API URLs using a simple JSON file format.
    """
    
    def __init__(self, testing: bool = False):
        """
        Initialize the TokenManager.
        
        Args:
            testing: If True, uses test-specific storage location
        """
        self.testing = testing
        self.storage_path = self._get_storage_path()
        self._ensure_directory_exists()
    
    def _get_storage_path(self) -> str:
        """
        Get the JSON storage file path.
        
        Returns:
            str: Full path to the JSON storage file
        """
        if self.testing:
            # Use test-specific directory
            base_dir = os.path.expanduser("~/Library/Application Support/activitywatch/aw-qt-test")
        else:
            # Use production directory
            base_dir = os.path.expanduser("~/Library/Application Support/activitywatch/aw-qt")
        
        return os.path.join(base_dir, "auth.json")
    
    def _ensure_directory_exists(self) -> None:
        """Ensure the storage directory exists."""
        try:
            directory = os.path.dirname(self.storage_path)
            os.makedirs(directory, exist_ok=True)
            logger.debug(f"Storage directory ensured: {directory}")
        except Exception as e:
            logger.error(f"Failed to create storage directory: {e}")
            raise
    
    @staticmethod
    def _decode_jwt_exp(token: str) -> Optional[float]:
        """Decode JWT token and extract expiration timestamp."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            payload = parts[1]
            payload += '=' * (4 - len(payload) % 4)  # Add padding
            decoded = base64.urlsafe_b64decode(payload)
            data = json.loads(decoded)
            return data.get('exp')
        except Exception:
            return None
    
    def store_token_data(self, token: str, url: str) -> bool:
        """
        Store authentication token and API URL to JSON file.
        
        Args:
            token: JWT authentication token
            url: API URL for backend communication
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Validate inputs
            if not token or not url:
                logger.error("Token and URL are required")
                return False
            
            # Prepare data structure
            auth_data = {
                "token": token,
                "url": url,
                "created": datetime.now().isoformat(),
                "updated": datetime.now().isoformat(),
                "version": "1.0"
            }
            
            # Write to JSON file atomically
            temp_path = f"{self.storage_path}.tmp"
            with open(temp_path, 'w', encoding='utf-8') as f:
                json.dump(auth_data, f, indent=2, ensure_ascii=False)
            
            # Atomic move (rename) to final location
            os.replace(temp_path, self.storage_path)
            
            logger.info("===>> Authentication token and URL stored successfully")
            logger.debug(f"===>> Storage path: {self.storage_path}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to store token data: {e}")
            # Clean up temp file if it exists
            temp_path = f"{self.storage_path}.tmp"
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass
            return False
    
    def get_token_data(self) -> Optional[Tuple[str, str]]:
        """
        Get stored authentication token and API URL from JSON file.
        
        Returns:
            Optional[Tuple[str, str]]: (token, url) tuple if found, None otherwise
        """
        try:
            if not os.path.exists(self.storage_path):
                logger.info("===>> No token storage file found")
                return None
            
            with open(self.storage_path, 'r', encoding='utf-8') as f:
                auth_data = json.load(f)
            
            # Validate data structure
            if not isinstance(auth_data, dict):
                logger.error("===>> Invalid token data format")
                return None
            
            token = auth_data.get('token')
            url = auth_data.get('url')
            
            if not token or not url:
                logger.error("===>> Token or URL missing from storage")
                return None
            
            # Check token expiration
            exp_timestamp = self._decode_jwt_exp(token)
            if exp_timestamp:
                current_time = datetime.now().timestamp()
                if current_time >= exp_timestamp:
                    expires_at = datetime.fromtimestamp(exp_timestamp)
                    logger.error(f"===>> Token expired on {expires_at.strftime('%Y-%m-%d %H:%M:%S')}")
                    logger.error("===>> User needs to re-authenticate")
                    return None
                else:
                    expires_at = datetime.fromtimestamp(exp_timestamp)
                    logger.debug(f"===>> Token valid until {expires_at.strftime('%Y-%m-%d %H:%M:%S')}")
            
            logger.info(f"===>> Authentication token and URL retrieved successfully (URL: {url})")
            return token, url
            
        except FileNotFoundError:
            logger.debug("Token storage file not found")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in token storage file: {e}")
            return None
        except Exception as e:
            logger.error(f"❌ Failed to get token data: {e}")
            return None
    
    def delete_token_data(self) -> bool:
        """
        Delete stored authentication token and API URL from JSON file.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not os.path.exists(self.storage_path):
                logger.debug("No token storage file to delete")
                return True
            
            os.remove(self.storage_path)
            logger.info("===>> Authentication token and URL deleted successfully")
            return True
            
        except FileNotFoundError:
            logger.debug("Token storage file already deleted")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to delete token data: {e}")
            return False
    
    def is_authenticated(self) -> bool:
        """
        Check if authentication data exists and is valid.
        
        Returns:
            bool: True if valid authentication data exists, False otherwise
        """
        token_data = self.get_token_data()
        return token_data is not None
    
    def get_storage_info(self) -> dict:
        """
        Get information about the token storage.
        
        Returns:
            dict: Storage information including path, existence, and metadata
        """
        info = {
            "storage_path": self.storage_path,
            "exists": os.path.exists(self.storage_path),
            "testing": self.testing
        }
        
        if info["exists"]:
            try:
                stat = os.stat(self.storage_path)
                info.update({
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
                
                # Try to get token data info
                token_data = self.get_token_data()
                if token_data:
                    info["has_valid_data"] = True
                    info["token_length"] = len(token_data[0])
                    info["url"] = token_data[1]
                else:
                    info["has_valid_data"] = False
                    
            except Exception as e:
                info["error"] = str(e)
        
        return info
    


