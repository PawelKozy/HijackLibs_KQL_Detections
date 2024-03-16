import json
import requests
import re
import os
def sanitize_filename(filename):
    """
    Sanitize the filename to remove any characters that might not be valid in file names.
    """
    return re.sub(r'[\\/*?:"<>|]', "", filename)  # Remove characters not allowed in filenames
def ensure_directory_exists(directory):
    """
    Ensure that a directory exists; if not, create it.
    """
    if not os.path.exists(directory):
        os.makedirs(directory)
def generate_kql_query(data, detection_output_directory, generic_output_directory):
    initial_transforms = "DeviceImageLoadEvents\n| extend FileName = tolower(FileName), FolderPath = tolower(FolderPath), InitiatingProcessFileName = tolower(InitiatingProcessFileName)\n"
    FileProfile = "\n| invoke FileProfile(\"SHA1\", 1000)\n"
    all_conditions = []
    for entry in data:
        individual_conditions = []
        dll_name = entry['Name'].lower()
        expected_locations = entry.get('ExpectedLocations', []) or []
        vulnerable_executables = entry.get('VulnerableExecutables', []) or []
        folder_conditions = []
        for location in expected_locations:
            location_lower = location.lower()
            if location_lower.endswith("%version%"):
                location_processed = location_lower[:-9]
            else:
                location_processed = location_lower
            location_processed = location_processed.replace("%version%", "\" and FolderPath contains \"")
            location_processed = location_processed.replace("%syswow64%", "c:\\windows\\syswow64")\
                                               .replace("%localappdata%", "appdata\\local")\
                                               .replace("%system32%", "c:\\windows\\system32")\
                                               .replace("%userprofile%", "")\
                                                .replace("%windir%", "c:\\windows")\
                                               .replace("%programdata%", "c:\\programdata")\
                                               .replace("%programfiles%", "c:\\program files")
            if location_processed.strip("\\"):
                condition = "FolderPath contains \"" + location_processed.replace("\\", "\\\\") + "\""
                folder_conditions.append(condition)
        exe_conditions = []
        for ve in vulnerable_executables:
            exe_name = ve['Path'].lower().split('\\')[-1]
            condition = f"InitiatingProcessFileName endswith \"{exe_name}\""
            exe_conditions.append(condition)
        if folder_conditions:
            individual_conditions.append(f"not({' or '.join(folder_conditions)})")
        if exe_conditions:
            individual_conditions.append(f"({' or '.join(exe_conditions)})")
        if individual_conditions:
            dll_condition = f'FileName == "{dll_name}"'
            all_conditions.append(f"({dll_condition} and {' and '.join(individual_conditions)})")
        # Writing individual file
        safe_dll_name = sanitize_filename(dll_name)
        with open(f"{detection_output_directory}/{safe_dll_name}_detection_query.kql", "w") as file:
            individual_query = initial_transforms + "| where " + " and ".join(individual_conditions) + FileProfile
            file.write(individual_query)
    # Constructing the combined query
    combined_conditions = " or ".join(all_conditions)
    combined_conditions = combined_conditions.replace(" or (FileName", "\nor (FileName")
    combined_query = initial_transforms + "| where " + combined_conditions + FileProfile
    # Writing the combined query to a file
    ensure_directory_exists(generic_output_directory)
    with open(f"{generic_output_directory}/all_detection_queries.kql", "w") as combined_file:
        combined_file.write(combined_query)
if __name__ == "__main__":
    url = "https://hijacklibs.net/api/hijacklibs.json"
    detection_output_directory = "IndividualDetections"
    generic_output_directory = "GeneralDetections"
    # Ensure output directories exist
    ensure_directory_exists(detection_output_directory)
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        generate_kql_query(data, detection_output_directory, generic_output_directory)
        print(f"Individual detection queries generated in '{detection_output_directory}' directory.")
        print(f"Combined detection queries generated in '{generic_output_directory}' directory.")
    else:
        print(f"Failed to fetch data: {response.status_code}")
