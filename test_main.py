import pytest
import json
import gzip
import io
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from src.main import app, get_available_years, download_nvd_feeds, CVE_DATA

client = TestClient(app)

# Sample CVE data for testing
SAMPLE_CVE_DATA = {
    "CVE_Items": [
        {
            "cve": {
                "CVE_data_meta": {
                    "ID": "CVE-2025-0001"
                },
                "description": {
                    "description_data": [
                        {
                            "value": "Test vulnerability description"
                        }
                    ]
                },
                "problemtype": {
                    "problemtype_data": [
                        {
                            "description": [
                                {
                                    "value": "CWE-79"
                                }
                            ]
                        }
                    ]
                },
                "references": {
                    "reference_data": [
                        {
                            "url": "https://example.com/vuln",
                            "name": "Example Reference",
                            "tags": ["Vendor Advisory"]
                        }
                    ]
                }
            },
            "configurations": {
                "nodes": [
                    {
                        "cpe_match": [
                            {
                                "vulnerable": True,
                                "cpe23Uri": "cpe:2.3:a:test:software:1.0:*:*:*:*:*:*:*:*"
                            }
                        ]
                    }
                ]
            },
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH"
                    },
                    "exploitabilityScore": 3.9,
                    "impactScore": 3.6
                }
            },
            "publishedDate": "2025-01-01T00:00:00Z",
            "lastModifiedDate": "2025-01-01T00:00:00Z"
        },
        {
            "cve": {
                "CVE_data_meta": {
                    "ID": "CVE-2024-0001"
                },
                "description": {
                    "description_data": [
                        {
                            "value": "Another test vulnerability"
                        }
                    ]
                },
                "problemtype": {
                    "problemtype_data": [
                        {
                            "description": [
                                {
                                    "value": "CWE-287"
                                }
                            ]
                        }
                    ]
                },
                "references": {
                    "reference_data": [
                        {
                            "url": "https://example2.com/vuln",
                            "name": "Another Reference",
                            "tags": ["Patch"]
                        }
                    ]
                }
            },
            "configurations": {
                "nodes": [
                    {
                        "cpe_match": [
                            {
                                "vulnerable": True,
                                "cpe23Uri": "cpe:2.3:a:test:software2:2.0:*:*:*:*:*:*:*:*"
                            }
                        ]
                    }
                ]
            },
            "impact": {
                "baseMetricV2": {
                    "severity": "MEDIUM",
                    "exploitabilityScore": 5.0,
                    "impactScore": 2.9
                }
            },
            "publishedDate": "2024-01-01T00:00:00Z",
            "lastModifiedDate": "2024-01-01T00:00:00Z"
        }
    ]
}

class TestHelperFunctions:
    """Test helper functions"""
    
    def test_get_available_years(self):
        """Test that get_available_years returns correct range"""
        years = get_available_years()
        current_year = 2025  # Mock current year for consistent testing
        expected_years = list(range(2002, current_year + 1))
        
        assert len(years) == len(expected_years)
        assert years[0] == 2002
        assert years[-1] >= 2024  # Should include recent years
    
    @patch('main.requests.get')
    def test_download_nvd_feeds_success(self, mock_get):
        """Test successful download of NVD feeds"""
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        
        # Create gzipped JSON data
        json_data = json.dumps(SAMPLE_CVE_DATA).encode('utf-8')
        gz_data = io.BytesIO()
        with gzip.GzipFile(fileobj=gz_data, mode='wb') as gz:
            gz.write(json_data)
        
        mock_response.content = gz_data.getvalue()
        mock_get.return_value = mock_response
        
        # Test download
        download_nvd_feeds([2025])
        
        assert len(CVE_DATA) == 2
        assert CVE_DATA[0]["cve"]["CVE_data_meta"]["ID"] == "CVE-2025-0001"
        assert CVE_DATA[1]["cve"]["CVE_data_meta"]["ID"] == "CVE-2024-0001"
    
    @patch('main.requests.get')
    def test_download_nvd_feeds_failure(self, mock_get):
        """Test handling of failed downloads"""
        # Mock failed response
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        # Clear existing data
        global CVE_DATA
        CVE_DATA = []
        
        # Test download
        download_nvd_feeds([2025])
        
        assert len(CVE_DATA) == 0

class TestAPIEndpoints:
    """Test API endpoints"""
    
    def setup_method(self):
        """Setup test data before each test"""
        global CVE_DATA
        CVE_DATA = SAMPLE_CVE_DATA["CVE_Items"].copy()
    
    def test_read_root(self):
        """Test root endpoint"""
        response = client.get("/")
        assert response.status_code == 200
        assert response.json() == {"message": "Welcome to the NVD CVE Query API!"}
    
    def test_load_nvd_data_latest(self):
        """Test loading latest year data"""
        with patch('main.download_nvd_feeds') as mock_download:
            response = client.post("/load?mode=latest")
            assert response.status_code == 200
            data = response.json()
            assert "loaded_years" in data
            assert "cve_count" in data
            mock_download.assert_called_once()
    
    def test_load_nvd_data_all(self):
        """Test loading all years data"""
        with patch('main.download_nvd_feeds') as mock_download:
            response = client.post("/load?mode=all")
            assert response.status_code == 200
            data = response.json()
            assert "loaded_years" in data
            assert "cve_count" in data
            mock_download.assert_called_once()
    
    def test_load_nvd_data_years_single(self):
        """Test loading specific years"""
        with patch('main.download_nvd_feeds') as mock_download:
            response = client.post("/load?mode=years&years=2024&years=2025")
            assert response.status_code == 200
            data = response.json()
            assert "loaded_years" in data
            assert "cve_count" in data
            mock_download.assert_called_once()
    
    def test_load_nvd_data_years_range(self):
        """Test loading year ranges"""
        with patch('main.download_nvd_feeds') as mock_download:
            response = client.post("/load?mode=years&years=2024-2025")
            assert response.status_code == 200
            data = response.json()
            assert "loaded_years" in data
            assert "cve_count" in data
            mock_download.assert_called_once()
    
    def test_load_nvd_data_invalid_mode(self):
        """Test invalid mode handling"""
        response = client.post("/load?mode=invalid")
        assert response.status_code == 200
        data = response.json()
        assert "error" in data
    
    def test_search_cves_by_id(self):
        """Test searching CVEs by ID"""
        response = client.get("/search?query=CVE-2025-0001")
        assert response.status_code == 200
        data = response.json()
        assert "results" in data
        assert len(data["results"]) == 1
        assert data["results"][0]["id"] == "CVE-2025-0001"
    
    def test_search_cves_by_keyword(self):
        """Test searching CVEs by keyword"""
        response = client.get("/search?query=vulnerability")
        assert response.status_code == 200
        data = response.json()
        assert "results" in data
        assert len(data["results"]) >= 1
    
    def test_search_cves_by_year(self):
        """Test searching CVEs by year"""
        response = client.get("/search?query=test&year=2025")
        assert response.status_code == 200
        data = response.json()
        assert "results" in data
        # Should only return 2025 CVEs
        for result in data["results"]:
            assert result["id"].startswith("CVE-2025-")
    
    def test_search_cves_no_results(self):
        """Test search with no results"""
        response = client.get("/search?query=nonexistent")
        assert response.status_code == 200
        data = response.json()
        assert "results" in data
        assert len(data["results"]) == 0
    
    def test_get_cve_details_success(self):
        """Test getting CVE details"""
        response = client.get("/cve/CVE-2025-0001")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "CVE-2025-0001"
        assert "descriptions" in data
        assert "cwe" in data
        assert "references" in data
        assert "cpes" in data
        assert "cvss_v3" in data
        assert "cvss_v2" in data
    
    def test_get_cve_details_not_found(self):
        """Test getting non-existent CVE details"""
        response = client.get("/cve/CVE-2025-9999")
        assert response.status_code == 200
        data = response.json()
        assert "error" in data
        assert data["error"] == "CVE not found"
    
    def test_ui_endpoint(self):
        """Test UI endpoint returns HTML"""
        response = client.get("/ui")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

class TestDataProcessing:
    """Test data processing logic"""
    
    def setup_method(self):
        """Setup test data before each test"""
        global CVE_DATA
        CVE_DATA = SAMPLE_CVE_DATA["CVE_Items"].copy()
    
    def test_cve_data_structure(self):
        """Test CVE data structure parsing"""
        cve_item = CVE_DATA[0]
        
        # Test CVE ID extraction
        cve_id = cve_item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
        assert cve_id == "CVE-2025-0001"
        
        # Test description extraction
        descs = cve_item.get("cve", {}).get("description", {}).get("description_data", [])
        desc = " ".join([d.get("value", "") for d in descs])
        assert "Test vulnerability description" in desc
        
        # Test CWE extraction
        cwe_list = []
        for pt in cve_item.get("cve", {}).get("problemtype", {}).get("problemtype_data", []):
            for d in pt.get("description", []):
                val = d.get("value", "")
                if val and val != "NVD-CWE-Other" and val != "NVD-CWE-noinfo":
                    cwe_list.append(val)
        assert "CWE-79" in cwe_list
    
    def test_cvss_score_extraction(self):
        """Test CVSS score extraction"""
        cve_item = CVE_DATA[0]  # Has CVSS v3
        impact = cve_item.get("impact", {})
        
        # Test CVSS v3
        if "baseMetricV3" in impact:
            cvss3 = impact["baseMetricV3"].get("cvssV3", {}).get("baseScore", "")
            severity = impact["baseMetricV3"].get("cvssV3", {}).get("baseSeverity", "")
            assert cvss3 == 7.5
            assert severity == "HIGH"
        
        # Test CVSS v2 (from second item)
        cve_item_v2 = CVE_DATA[1]
        impact_v2 = cve_item_v2.get("impact", {})
        if "baseMetricV2" in impact_v2:
            severity_v2 = impact_v2["baseMetricV2"].get("severity", "")
            assert severity_v2 == "MEDIUM"
    
    def test_cpe_extraction(self):
        """Test CPE extraction"""
        cve_item = CVE_DATA[0]
        cpes = []
        for node in cve_item.get("configurations", {}).get("nodes", []):
            for cpe in node.get("cpe_match", []):
                if cpe.get("vulnerable", False):
                    cpes.append(cpe.get("cpe23Uri", ""))
        
        assert len(cpes) == 1
        assert "cpe:2.3:a:test:software:1.0" in cpes[0]
    
    def test_reference_extraction(self):
        """Test reference extraction"""
        cve_item = CVE_DATA[0]
        refs = [r.get("url", "") for r in cve_item.get("cve", {}).get("references", {}).get("reference_data", [])]
        
        assert len(refs) == 1
        assert "https://example.com/vuln" in refs[0]

class TestErrorHandling:
    """Test error handling scenarios"""
    
    def test_invalid_year_format(self):
        """Test handling of invalid year format"""
        response = client.post("/load?mode=years&years=invalid")
        assert response.status_code == 200
        data = response.json()
        assert "error" in data
    
    def test_empty_search_query(self):
        """Test handling of empty search query"""
        response = client.get("/search?query=")
        assert response.status_code == 200
        data = response.json()
        assert "results" in data
    
    def test_malformed_cve_data(self):
        """Test handling of malformed CVE data"""
        # Test with missing required fields
        malformed_data = {
            "CVE_Items": [
                {
                    "cve": {
                        "CVE_data_meta": {
                            "ID": "CVE-2025-0002"
                        }
                        # Missing description and other fields
                    }
                }
            ]
        }
        
        global CVE_DATA
        CVE_DATA = malformed_data["CVE_Items"]
        
        response = client.get("/search?query=CVE-2025-0002")
        assert response.status_code == 200
        data = response.json()
        assert "results" in data

# Integration tests
class TestIntegration:
    """Integration tests"""
    
    def test_full_workflow(self):
        """Test complete workflow: load data, search, get details"""
        # Mock the download function to avoid actual network calls
        with patch('main.download_nvd_feeds') as mock_download:
            # Load data
            load_response = client.post("/load?mode=latest")
            assert load_response.status_code == 200
            
            # Search for CVEs
            search_response = client.get("/search?query=CVE-2025")
            assert search_response.status_code == 200
            search_data = search_response.json()
            
            if search_data["results"]:
                # Get details for first result
                cve_id = search_data["results"][0]["id"]
                details_response = client.get(f"/cve/{cve_id}")
                assert details_response.status_code == 200
                details_data = details_response.json()
                assert details_data["id"] == cve_id

if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 