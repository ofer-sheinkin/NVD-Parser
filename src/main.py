from fastapi import FastAPI, Query
from typing import List, Union
import requests
import datetime
from fastapi.templating import Jinja2Templates
from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse
import os
import json
import shutil
from src.db import get_db_connection

app = FastAPI()

NVD_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/"
CVE_DATA = []

# Set up templates directory
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), '..', 'templates')
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Helper to get available years (2002 to current year)
def get_available_years():
    current_year = datetime.datetime.now().year
    return list(range(2002, current_year + 1))

# Helper to download and parse NVD feeds
def download_nvd_feeds(years: List[int]):
    global CVE_DATA
    CVE_DATA = []
    for year in years:
        url = f"{NVD_BASE_URL}nvdcve-1.1-{year}.json.gz"
        print(f"Downloading {url}")
        resp = requests.get(url)
        if resp.status_code == 200:
            import gzip, json, io
            with gzip.GzipFile(fileobj=io.BytesIO(resp.content)) as gz:
                data = json.load(gz)
                CVE_DATA.extend(data.get("CVE_Items", []))
        else:
            print(f"Failed to download {url}")

def create_cve_table():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT UNIQUE NOT NULL,
            description TEXT,
            published_date TEXT,
            severity TEXT,
            cvss3 REAL,
            cwe TEXT,
            refs TEXT,
            cpes TEXT,
            exploitability TEXT
        )
    ''')
    conn.commit()
    cur.close()
    conn.close()

def save_cve_to_db(cve):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO cves (cve_id, description, published_date, severity, cvss3, cwe, refs, cpes, exploitability)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            description=excluded.description,
            published_date=excluded.published_date,
            severity=excluded.severity,
            cvss3=excluded.cvss3,
            cwe=excluded.cwe,
            refs=excluded.refs,
            cpes=excluded.cpes,
            exploitability=excluded.exploitability
    ''', (
        cve['id'],
        cve['description'],
        cve.get('publishedDate'),
        cve.get('severity'),
        cve.get('cvss3'),
        cve.get('cwe'),
        json.dumps(cve.get('references', [])),
        json.dumps(cve.get('cpes', [])),
        cve.get('exploitability'),
    ))
    conn.commit()
    cur.close()
    conn.close()

# Call create_cve_table() at app startup
create_cve_table()

# Restore from backup if needed
def restore_db_from_backup():
    db_file = os.path.join(os.path.dirname(__file__), '..', 'cves.db')
    backup_file = os.path.join(os.path.dirname(__file__), '..', 'cves_backup.db')
    if os.path.exists(backup_file) and not os.path.exists(db_file):
        shutil.copyfile(backup_file, db_file)
        print('Restored cves.db from cves_backup.db')

restore_db_from_backup()

@app.on_event("startup")
def reload_cve_db_on_startup():
    """
    Automatically reload the latest year's CVE data into the SQLite database on app startup.
    """
    available_years = get_available_years()
    latest_year = available_years[-1]
    download_nvd_feeds([latest_year])
    for item in CVE_DATA:
        # Prepare the CVE dict for DB insertion (reuse logic from search_cves)
        cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
        descs = item.get("cve", {}).get("description", {}).get("description_data", [])
        desc = " ".join([d.get("value", "") for d in descs])
        cwe_list = []
        for pt in item.get("cve", {}).get("problemtype", {}).get("problemtype_data", []):
            for d in pt.get("description", []):
                val = d.get("value", "")
                if val and val != "NVD-CWE-Other" and val != "NVD-CWE-noinfo":
                    cwe_list.append(val)
        cwe = ", ".join(cwe_list)
        refs = [r.get("url", "") for r in item.get("cve", {}).get("references", {}).get("reference_data", [])]
        cpes = []
        for node in item.get("configurations", {}).get("nodes", []):
            for cpe in node.get("cpe_match", []):
                if cpe.get("vulnerable", False):
                    cpes.append(cpe.get("cpe23Uri", ""))
        impact = item.get("impact", {})
        exploitability = ""
        if "baseMetricV3" in impact:
            exploitability = str(impact["baseMetricV3"].get("exploitabilityScore", ""))
        elif "baseMetricV2" in impact:
            exploitability = str(impact["baseMetricV2"].get("exploitabilityScore", ""))
        published = item.get("publishedDate", "")
        severity = ""
        cvss3 = ""
        if "baseMetricV3" in impact:
            cvss3 = impact["baseMetricV3"].get("cvssV3", {}).get("baseScore", "")
            severity = impact["baseMetricV3"].get("cvssV3", {}).get("baseSeverity", "")
        elif "baseMetricV2" in impact:
            severity = impact["baseMetricV2"].get("severity", "")
        cve = {
            "id": cve_id,
            "description": desc,
            "publishedDate": published,
            "severity": severity,
            "cvss3": cvss3,
            "cwe": cwe,
            "references": refs,
            "cpes": cpes,
            "exploitability": exploitability
        }
        save_cve_to_db(cve)
    # Backup DB after update
    db_file = os.path.join(os.path.dirname(__file__), '..', 'cves.db')
    backup_file = os.path.join(os.path.dirname(__file__), '..', 'cves_backup.db')
    if os.path.exists(db_file):
        shutil.copyfile(db_file, backup_file)
        print('Backed up cves.db to cves_backup.db')

@app.get("/")
def read_root():
    return {"message": "Welcome to the NVD CVE Query API!"}

@app.post("/load")
def load_nvd_data(
    mode: str = Query("latest", description="'latest', 'all', or 'years'"),
    years: Union[List[str], None] = Query(None, description="List of years or ranges if mode is 'years'")
):
    """
    Load NVD CVE data for the specified years.
    mode: 'latest', 'all', or 'years'
    years: list of years or ranges (if mode is 'years')
    """
    available_years = get_available_years()
    if mode == "latest":
        years_to_load = [available_years[-1]]
    elif mode == "all":
        years_to_load = available_years
    elif mode == "years" and years:
        expanded_years = set()
        for y in years:
            y = y.strip()
            if '-' in y:
                try:
                    start, end = map(int, y.split('-'))
                    expanded_years.update(range(start, end + 1))
                except Exception:
                    continue
            else:
                try:
                    expanded_years.add(int(y))
                except Exception:
                    continue
        years_to_load = [y for y in sorted(expanded_years) if y in available_years]
    else:
        return {"error": "Invalid mode or years"}
    download_nvd_feeds(years_to_load)
    return {"loaded_years": years_to_load, "cve_count": len(CVE_DATA)}
    # Backup DB after update
    db_file = os.path.join(os.path.dirname(__file__), '..', 'cves.db')
    backup_file = os.path.join(os.path.dirname(__file__), '..', 'cves_backup.db')
    if os.path.exists(db_file):
        shutil.copyfile(db_file, backup_file)
        print('Backed up cves.db to cves_backup.db')

@app.get("/ui", response_class=HTMLResponse)
def serve_ui(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/search")
def search_cves(query: str, year: int = None):
    results = []
    for item in CVE_DATA:
        cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
        descs = item.get("cve", {}).get("description", {}).get("description_data", [])
        desc = " ".join([d.get("value", "") for d in descs])
        # CWE
        cwe_list = []
        for pt in item.get("cve", {}).get("problemtype", {}).get("problemtype_data", []):
            for d in pt.get("description", []):
                val = d.get("value", "")
                if val and val != "NVD-CWE-Other" and val != "NVD-CWE-noinfo":
                    cwe_list.append(val)
        cwe = ", ".join(cwe_list)
        # References
        refs = [r.get("url", "") for r in item.get("cve", {}).get("references", {}).get("reference_data", [])]
        # CPEs
        cpes = []
        for node in item.get("configurations", {}).get("nodes", []):
            for cpe in node.get("cpe_match", []):
                if cpe.get("vulnerable", False):
                    cpes.append(cpe.get("cpe23Uri", ""))
        # Exploitability
        impact = item.get("impact", {})
        exploitability = ""
        if "baseMetricV3" in impact:
            exploitability = str(impact["baseMetricV3"].get("exploitabilityScore", ""))
        elif "baseMetricV2" in impact:
            exploitability = str(impact["baseMetricV2"].get("exploitabilityScore", ""))
        # Filter by year if provided
        if year:
            if not cve_id.startswith(f"CVE-{year}-"):
                continue
        # Match by ID or keyword
        if query.lower() in cve_id.lower() or query.lower() in desc.lower():
            # Published date
            published = item.get("publishedDate", "")
            # Severity and CVSS 3.x
            severity = ""
            cvss3 = ""
            if "baseMetricV3" in impact:
                cvss3 = impact["baseMetricV3"].get("cvssV3", {}).get("baseScore", "")
                severity = impact["baseMetricV3"].get("cvssV3", {}).get("baseSeverity", "")
            elif "baseMetricV2" in impact:
                severity = impact["baseMetricV2"].get("severity", "")
            results.append({
                "id": cve_id,
                "description": desc,
                "publishedDate": published,
                "severity": severity,
                "cvss3": cvss3,
                "cwe": cwe,
                "references": refs,
                "cpes": cpes,
                "exploitability": exploitability
            })
        if len(results) >= 50:
            break
    return {"results": results}

@app.get("/cve/{cve_id}")
def get_cve_details(cve_id: str):
    """
    Get detailed information for a specific CVE ID
    """
    for item in CVE_DATA:
        if item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "") == cve_id:
            cve_data = item.get("cve", {})
            impact = item.get("impact", {})
            
            # Extract all available data
            descs = cve_data.get("description", {}).get("description_data", [])
            descriptions = [d.get("value", "") for d in descs]
            
            # CWE details
            cwe_list = []
            for pt in cve_data.get("problemtype", {}).get("problemtype_data", []):
                for d in pt.get("description", []):
                    val = d.get("value", "")
                    if val and val != "NVD-CWE-Other" and val != "NVD-CWE-noinfo":
                        cwe_list.append(val)
            
            # References with tags
            refs = []
            for r in cve_data.get("references", {}).get("reference_data", []):
                refs.append({
                    "url": r.get("url", ""),
                    "name": r.get("name", ""),
                    "tags": r.get("tags", [])
                })
            
            # CPEs with details
            cpes = []
            for node in item.get("configurations", {}).get("nodes", []):
                for cpe in node.get("cpe_match", []):
                    if cpe.get("vulnerable", False):
                        cpes.append({
                            "uri": cpe.get("cpe23Uri", ""),
                            "version_start": cpe.get("versionStartIncluding", ""),
                            "version_end": cpe.get("versionEndIncluding", ""),
                            "vulnerable": cpe.get("vulnerable", False)
                        })
            
            # CVSS details
            cvss_v3 = {}
            cvss_v2 = {}
            if "baseMetricV3" in impact:
                cvss_v3 = impact["baseMetricV3"].get("cvssV3", {})
                cvss_v3["exploitabilityScore"] = impact["baseMetricV3"].get("exploitabilityScore")
                cvss_v3["impactScore"] = impact["baseMetricV3"].get("impactScore")
            if "baseMetricV2" in impact:
                cvss_v2 = impact["baseMetricV2"].get("cvssV2", {})
                cvss_v2["exploitabilityScore"] = impact["baseMetricV2"].get("exploitabilityScore")
                cvss_v2["impactScore"] = impact["baseMetricV2"].get("impactScore")
            
            return {
                "id": cve_id,
                "publishedDate": item.get("publishedDate", ""),
                "lastModifiedDate": item.get("lastModifiedDate", ""),
                "descriptions": descriptions,
                "cwe": cwe_list,
                "references": refs,
                "cpes": cpes,
                "cvss_v3": cvss_v3,
                "cvss_v2": cvss_v2,
                "impact": impact
            }
    
    return {"error": "CVE not found"} 