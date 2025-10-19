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

"""Common tools for reading local files."""

import os

def read_local_file(path: str) -> str:
    """
    Reads the content of a local file or all files in a directory recursively.

    Args:
        path: The absolute or relative path to the file or directory.

    Returns:
        The content of the file as a string, or the concatenated content of all
        files in the directory. Returns an error message if the path is invalid.
    """
    if not os.path.exists(path):
        return f"Error: Path not found at '{path}'"

    if os.path.isfile(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            return f"An unexpected error occurred while reading the file: {e}"

    elif os.path.isdir(path):
        combined_content = ""
        try:
            for dirpath, _, filenames in os.walk(path):
                for filename in filenames:
                    file_path = os.path.join(dirpath, filename)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            combined_content += f"--- Content of {file_path} ---\n"
                            combined_content += f.read()
                            combined_content += "\n\n"
                    except Exception:
                        # Ignore files that can't be read
                        pass
            return combined_content
        except Exception as e:
            return f"An unexpected error occurred while traversing the directory: {e}"
    else:
        return f"Error: Path '{path}' is not a valid file or directory."
