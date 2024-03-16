import json
import requests
def generate_kql_query(data):
    # Initial part of the KQL query to transform file paths and names to lowercase for case-insensitive comparison
    initial_transforms = "| extend FileName = tolower(FileName), FolderPath = tolower(FolderPath), InitiatingProcessFileName = tolower(InitiatingProcessFileName)\n"
    FileProfile = "\n| invoke FileProfile(\"SHA1\", 1000)\n"
    all_conditions = []
    for entry in data:
        dll_name = entry['Name'].lower()
        expected_locations = entry.get('ExpectedLocations', []) or []
        vulnerable_executables = entry.get('VulnerableExecutables', []) or []
        folder_conditions = []
        for location in expected_locations:
            location_lower = location.lower()
            if location_lower.endswith("%version%"):
                location_processed = location_lower[:-9]
            else:
                location_processed = location_lower.replace("%programfiles%", "c:\\program files")\
                                                   .replace("%syswow64%", "c:\\windows\\syswow64")\
                                                   .replace("%localappdata%", "appdata\\local")\
                                                   .replace("%system32%", "c:\\windows\\system32")\
                                                   .replace("%userprofile%", "")\
                                                   .replace("%version%", "\" and FolderPath contains \"")
            if location_processed.strip("\\"): 
                condition = "FolderPath contains \"" + location_processed.replace("\\", "\\\\") + "\""
                folder_conditions.append(condition)
        exe_conditions = []
        for ve in vulnerable_executables:
            exe_name = ve['Path'].lower().split('\\')[-1]
            condition = f"InitiatingProcessFileName endswith \"{exe_name}\""
            exe_conditions.append(condition)
        conditions = []
        if folder_conditions:
            conditions.append(f"not({' or '.join(folder_conditions)})")
        if exe_conditions:
            conditions.append(f"({' or '.join(exe_conditions)})")
        if conditions:
            dll_condition = f'FileName == "{dll_name}"'
            all_conditions.append(f"({dll_condition} and {' and '.join(conditions)})")
    query_conditions = " or ".join(all_conditions)
    query_conditions = query_conditions.replace(" or (FileName", "\nor (FileName")
    query = initial_transforms + "| where " + query_conditions + FileProfile
    return query
if __name__ == "__main__":
    url = "https://hijacklibs.net/api/hijacklibs.json"
    
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        kql_query = generate_kql_query(data)
        print(kql_query)
    else:
        print(f"Failed to fetch data: {response.status_code}")
