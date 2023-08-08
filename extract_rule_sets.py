import requests
import csv

token = "azion21fcf248a9900337cba195733b6e0716c6d"
url = "https://api.azionapi.net/waf/rulesets/1836"

headers = {
    "Accept": "application/json; version=3",
    "Authorization": "Token " + token
}

response = requests.get(url, headers=headers)

if response.status_code == 200:
    data = response.json()

    rule_set = data["results"]

    csv_file = "allowed_rules.csv"

    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Rule ID", "Name", "Mode", "Active", "SQL Injection", "SQL Injection Sensitivity",
                         "Remote File Inclusion", "Remote File Inclusion Sensitivity", "Directory Traversal",
                         "Directory Traversal Sensitivity", "Cross-Site Scripting", "Cross-Site Scripting Sensitivity",
                         "Evading Tricks", "Evading Tricks Sensitivity", "File Upload", "File Upload Sensitivity",
                         "Unwanted Access", "Unwanted Access Sensitivity", "Identified Attack",
                         "Identified Attack Sensitivity", "Bypass Addresses"])

        writer.writerow([
            rule_set["id"], rule_set["name"], rule_set["mode"], rule_set["active"],
            rule_set["sql_injection"], rule_set["sql_injection_sensitivity"],
            rule_set["remote_file_inclusion"], rule_set["remote_file_inclusion_sensitivity"],
            rule_set["directory_traversal"], rule_set["directory_traversal_sensitivity"],
            rule_set["cross_site_scripting"], rule_set["cross_site_scripting_sensitivity"],
            rule_set["evading_tricks"], rule_set["evading_tricks_sensitivity"],
            rule_set["file_upload"], rule_set["file_upload_sensitivity"],
            rule_set["unwanted_access"], rule_set["unwanted_access_sensitivity"],
            rule_set["identified_attack"], rule_set["identified_attack_sensitivity"],
            rule_set["bypass_addresses"]
        ])

    print("Rules extraidas para", csv_file)

else:
    print("Um erro ocorreu na request", response.text)
