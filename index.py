import requests
import json

SNYK_BASE_URL = "https://snyk.io/api/"
SNYK_API_VERSION = "v1"
SNYK_TOKEN = "mySuperSecretSuperRealSnykToken123123"


def get_json_object(org_id, project_id):
    headers = {"Content-Type": "application/json", "Authorization": "token " + SNYK_TOKEN}
    values = {'includeDescription': 'true'}

    url = SNYK_BASE_URL + SNYK_API_VERSION + "/org/" + org_id + "/project/" + project_id + "/aggregated-issues"
    r = requests.post(url, headers=headers, json=values)    
    return r.json()


def transform_json(data):
    api_vulns_json = {"vulnerabilities": []}
    for issue in data["issues"]:
        if issue["issueType"] == "license":
            continue
        defect_vuln = {}

        defect_vuln["packageName"] = issue["pkgName"]
        defect_vuln["version"] = issue["pkgVersions"][0]
        defect_vuln["title"] = issue["issueData"]["title"]
        x = issue["issueData"]["cvssScore"]
        defect_vuln["cvssScore"] = x
        defect_vuln["CVSSv3"] = issue["issueData"]["CVSSv3"]
        defect_vuln["semver"] = issue["issueData"]["semver"]
        defect_vuln["severity"] = issue["issueData"]["severity"]
        defect_vuln["id"] = issue["issueData"]["id"]
        defect_vuln["description"] = issue["issueData"]["description"]

        # missing: vulnerabilities[from] and vulnerability[description]
        defect_vuln["from"] = ["juice-shop@12.3.0","fuzzball@1.4.0"]
        
        api_vulns_json["vulnerabilities"].append(defect_vuln)
        
    return api_vulns_json


if __name__ == "__main__":
    SNYK_ORG_ID = ""
    SNYK_PROJECT_ID = ""

    res = get_json_object(SNYK_ORG_ID, SNYK_PROJECT_ID)
    new_json = transform_json(res)
    
    json_object = json.dumps(new_json, indent=4)
    with open("results.json", "w") as outfile:
        outfile.write(json_object)