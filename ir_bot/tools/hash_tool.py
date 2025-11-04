# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Hashing tool for forensic evidence integrity verification."""

import hashlib
import os

def calculate_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """
    Calculate the hash of a file for forensic integrity verification.
    
    Args:
        file_path: Path to the file to hash
        algorithm: Hashing algorithm to use (sha256, sha1, md5)
        
    Returns:
        The hexadecimal hash digest of the file, or an error message
    """
    if not os.path.exists(file_path):
        return f"Error: File not found at '{file_path}'"
        
    if not os.path.isfile(file_path):
        return f"Error: '{file_path}' is not a file"
        
    try:
        # Select the hash algorithm
        if algorithm.lower() == "sha256":
            hash_obj = hashlib.sha256()
        elif algorithm.lower() == "sha1":
            hash_obj = hashlib.sha1()
        elif algorithm.lower() == "md5":
            hash_obj = hashlib.md5()
        else:
            return f"Error: Unsupported algorithm '{algorithm}'. Use sha256, sha1, or md5."
            
        # Read and hash the file in chunks to handle large files
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_obj.update(chunk)
                
        return f"{algorithm.upper()} hash of {file_path}: {hash_obj.hexdigest()}"
        
    except Exception as e:
        return f"Error calculating hash: {str(e)}"