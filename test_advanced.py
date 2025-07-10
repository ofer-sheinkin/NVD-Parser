import pytest
import json
import gzip
import io
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from src.main import app, get_available_years, download_nvd_feeds, CVE_DATA
from test_data import (
    SAMPLE_CVE_DATA, MULTI_DESC_CVE, MULTI_CWE_CVE, MULTI_REF_CVE,
    COMPLEX_CPE_CVE, MALFORMED_CVE_DATA, EMPTY_CVE_DATA,
    YEAR_2023_CVE, YEAR_2022_CVE
)

client = TestClient(app)

class TestAdvancedDataProcessing:
    """Advanced data processing tests using various test data scenarios"""
    
    def setup_method(self):
        """Setup test data before each test"""
        global CVE_DATA
        CVE_DATA = []
    
    def test_multiple_descriptions(self):
        """Test handling of CVEs with multiple descriptions"""
        global CVE_DATA
        CVE_DATA = MULTI_DESC_CVE["CVE_Items"].copy()
        
        response = client.get("/search?query=CVE-2025-0002")
        assert response.status_code == 200
        data = response.json()
        assert len(data["results"]) == 1
        
        result = data["results"][0]
        assert "First description" in result["description"]
        assert "Second description" in result["description"]
    
    def test_multiple_cwes(self):
        """Test handling of CVEs with multiple CWEs"""
        global CVE_DATA
        CVE_DATA = MULTI_CWE_CVE["CVE_Items"].copy()
        
        response = client.get("/search?query=CVE-2025-0003")
        assert response.status_code == 200
        data = response.json()
        assert len(data["results"]) == 1
        
        result = data["results"][0]
        assert "CWE-79" in result["cwe"]
        assert "CWE-287" in result["cwe"]
        # Should not include NVD-CWE-Other
        assert "NVD-CWE-Other" not in result["cwe"]
    
    def test_multiple_references(self):
        """Test handling of CVEs with multiple references"""
        global CVE_DATA
        CVE_DATA = MULTI_REF_CVE["CVE_Items"].copy()
        
        response = client.get("/search?query=CVE-2025-0004")
        assert response.status_code == 200
        data = response.json()
        assert len(data["results"]) == 1
        
        result = data["results"][0]
        assert len(result["references"]) == 2
        assert "https://example1.com/vuln" in result["references"]
        assert "https://example2.com/vuln" in result["references"]
    
    def test_complex_cpe_configuration(self):
        """Test handling of complex CPE configurations"""
        global CVE_DATA
        CVE_DATA = COMPLEX_CPE_CVE["CVE_Items"].copy()
        
        response = client.get("/search?query=CVE-2025-0005")
        assert response.status_code == 200
        data = response.json()
        assert len(data["results"]) == 1
        
        result = data["results"][0]
        # Should only include vulnerable CPEs
        assert len(result["cpes"]) == 1
        assert "cpe:2.3:a:vendor:product:1.0" in result["cpes"][0]
    
    def test_malformed_cve_data(self):
        """Test handling of malformed CVE data"""
        global CVE_DATA
        CVE_DATA = MALFORMED_CVE_DATA["CVE_Items"].copy()
        
        # Should handle missing fields gracefully
        response = client.get("/search?query=CVE-2025-0006")
        assert response.status_code == 200
        data = response.json()
        # Should still return results even with missing fields
        assert "results" in data
    
    def test_empty_cve_data(self):
        """Test handling of empty CVE data"""
        global CVE_DATA
        CVE_DATA = EMPTY_CVE_DATA["CVE_Items"].copy()
        
        response = client.get("/search?query=test")
        assert response.status_code == 200
        data = response.json()
        assert len(data["results"]) == 0

class TestYearFiltering:
    """Test year-based filtering functionality"""
    
    def setup_method(self):
        """Setup test data before each test"""
        global CVE_DATA
        # Combine multiple years of data
        CVE_DATA = (
            SAMPLE_CVE_DATA["CVE_Items"] +
            YEAR_2023_CVE["CVE_Items"] +
            YEAR_2022_CVE["CVE_Items"]
        )
    
    def test_year_filter_2025(self):
        """Test filtering by year 2025"""
        response = client.get("/search?query=test&year=2025")
        assert response.status_code == 200
        data = response.json()
        
        for result in data["results"]:
            assert result["id"].startswith("CVE-2025-")
    
    def test_year_filter_2024(self):
        """Test filtering by year 2024"""
        response = client.get("/search?query=test&year=2024")
        assert response.status_code == 200
        data = response.json()
        
        for result in data["results"]:
            assert result["id"].startswith("CVE-2024-")
    
    def test_year_filter_2023(self):
        """Test filtering by year 2023"""
        response = client.get("/search?query=test&year=2023")
        assert response.status_code == 200
        data = response.json()
        
        for result in data["results"]:
            assert result["id"].startswith("CVE-2023-")
    
    def test_year_filter_2022(self):
        """Test filtering by year 2022"""
        response = client.get("/search?query=test&year=2022")
        assert response.status_code == 200
        data = response.json()
        
        for result in data["results"]:
            assert result["id"].startswith("CVE-2022-")

class TestSearchFunctionality:
    """Test advanced search functionality"""
    
    def setup_method(self):
        """Setup test data before each test"""
        global CVE_DATA
        CVE_DATA = SAMPLE_CVE_DATA["CVE_Items"].copy()
    
    def test_case_insensitive_search(self):
        """Test case insensitive search"""
        # Test uppercase
        response = client.get("/search?query=CVE-2025-0001")
        assert response.status_code == 200
        data = response.json()
        assert len(data["results"]) == 1
        
        # Test lowercase
        response = client.get("/search?query=cve-2025-0001")
        assert response.status_code == 200
        data = response.json()
        assert len(data["results"]) == 1
    
    def test_partial_id_search(self):
        """Test partial CVE ID search"""
        response = client.get("/search?query=2025-0001")
        assert response.status_code == 200
        data = response.json()
        assert len(data["results"]) == 1
        assert data["results"][0]["id"] == "CVE-2025-0001"
    
    def test_keyword_search_in_description(self):
        """Test keyword search in description"""
        response = client.get("/search?query=SQL injection")
        assert response.status_code == 200
        data = response.json()
        assert len(data["results"]) == 1
        assert "SQL injection" in data["results"][0]["description"]
    
    def test_keyword_search_in_description_partial(self):
        """Test partial keyword search in description"""
        response = client.get("/search?query=SQL")
        assert response.status_code == 200
        data = response.json()
        assert len(data["results"]) == 1
    
    def test_search_limit(self):
        """Test that search results are limited to 50"""
        # Create more than 50 test items
        global CVE_DATA
        CVE_DATA = []
        for i in range(60):
            cve_item = SAMPLE_CVE_DATA["CVE_Items"][0].copy()
            cve_item["cve"]["CVE_data_meta"]["ID"] = f"CVE-2025-{i:04d}"
            CVE_DATA.append(cve_item)
        
        response = client.get("/search?query=test")
        assert response.status_code == 200
        data = response.json()
        assert len(data["results"]) <= 50

class TestCveDetails:
    """Test CVE details endpoint with various data scenarios"""
    
    def setup_method(self):
        """Setup test data before each test"""
        global CVE_DATA
        CVE_DATA = SAMPLE_CVE_DATA["CVE_Items"].copy()
    
    def test_cve_details_complete(self):
        """Test complete CVE details response"""
        response = client.get("/cve/CVE-2025-0001")
        assert response.status_code == 200
        data = response.json()
        
        # Check all required fields
        required_fields = [
            "id", "publishedDate", "lastModifiedDate", "descriptions",
            "cwe", "references", "cpes", "cvss_v3", "cvss_v2", "impact"
        ]
        for field in required_fields:
            assert field in data
        
        # Check specific values
        assert data["id"] == "CVE-2025-0001"
        assert len(data["descriptions"]) == 1
        assert "Test vulnerability description" in data["descriptions"][0]
        assert len(data["cwe"]) == 1
        assert "CWE-79" in data["cwe"]
        assert len(data["references"]) == 1
        assert data["references"][0]["url"] == "https://example.com/vuln"
    
    def test_cve_details_multiple_descriptions(self):
        """Test CVE details with multiple descriptions"""
        global CVE_DATA
        CVE_DATA = MULTI_DESC_CVE["CVE_Items"].copy()
        
        response = client.get("/cve/CVE-2025-0002")
        assert response.status_code == 200
        data = response.json()
        
        assert len(data["descriptions"]) == 2
        assert "First description" in data["descriptions"]
        assert "Second description" in data["descriptions"]
    
    def test_cve_details_multiple_cwes(self):
        """Test CVE details with multiple CWEs"""
        global CVE_DATA
        CVE_DATA = MULTI_CWE_CVE["CVE_Items"].copy()
        
        response = client.get("/cve/CVE-2025-0003")
        assert response.status_code == 200
        data = response.json()
        
        assert len(data["cwe"]) == 2
        assert "CWE-79" in data["cwe"]
        assert "CWE-287" in data["cwe"]
    
    def test_cve_details_multiple_references(self):
        """Test CVE details with multiple references"""
        global CVE_DATA
        CVE_DATA = MULTI_REF_CVE["CVE_Items"].copy()
        
        response = client.get("/cve/CVE-2025-0004")
        assert response.status_code == 200
        data = response.json()
        
        assert len(data["references"]) == 2
        assert data["references"][0]["url"] == "https://example1.com/vuln"
        assert data["references"][1]["url"] == "https://example2.com/vuln"
        assert "Vendor Advisory" in data["references"][0]["tags"]
        assert "Patch" in data["references"][1]["tags"]
    
    def test_cve_details_complex_cpe(self):
        """Test CVE details with complex CPE configuration"""
        global CVE_DATA
        CVE_DATA = COMPLEX_CPE_CVE["CVE_Items"].copy()
        
        response = client.get("/cve/CVE-2025-0005")
        assert response.status_code == 200
        data = response.json()
        
        assert len(data["cpes"]) == 1
        cpe = data["cpes"][0]
        assert cpe["uri"] == "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*:*"
        assert cpe["version_start"] == "1.0"
        assert cpe["version_end"] == "1.5"
        assert cpe["vulnerable"] == True

class TestLoadDataScenarios:
    """Test various data loading scenarios"""
    
    @patch('main.download_nvd_feeds')
    def test_load_latest_year(self, mock_download):
        """Test loading latest year data"""
        response = client.post("/load?mode=latest")
        assert response.status_code == 200
        data = response.json()
        assert "loaded_years" in data
        assert "cve_count" in data
        mock_download.assert_called_once()
    
    @patch('main.download_nvd_feeds')
    def test_load_all_years(self, mock_download):
        """Test loading all years data"""
        response = client.post("/load?mode=all")
        assert response.status_code == 200
        data = response.json()
        assert "loaded_years" in data
        assert "cve_count" in data
        mock_download.assert_called_once()
    
    @patch('main.download_nvd_feeds')
    def test_load_specific_years(self, mock_download):
        """Test loading specific years"""
        response = client.post("/load?mode=years&years=2023&years=2024")
        assert response.status_code == 200
        data = response.json()
        assert "loaded_years" in data
        assert "cve_count" in data
        mock_download.assert_called_once()
    
    @patch('main.download_nvd_feeds')
    def test_load_year_range(self, mock_download):
        """Test loading year range"""
        response = client.post("/load?mode=years&years=2020-2022")
        assert response.status_code == 200
        data = response.json()
        assert "loaded_years" in data
        assert "cve_count" in data
        mock_download.assert_called_once()
    
    def test_load_invalid_mode(self):
        """Test loading with invalid mode"""
        response = client.post("/load?mode=invalid")
        assert response.status_code == 200
        data = response.json()
        assert "error" in data
    
    def test_load_invalid_year_format(self):
        """Test loading with invalid year format"""
        response = client.post("/load?mode=years&years=invalid")
        assert response.status_code == 200
        data = response.json()
        assert "error" in data
    
    def test_load_mixed_year_formats(self):
        """Test loading with mixed year formats"""
        response = client.post("/load?mode=years&years=2023&years=2020-2022")
        assert response.status_code == 200
        data = response.json()
        assert "loaded_years" in data
        assert "cve_count" in data

class TestErrorScenarios:
    """Test various error scenarios"""
    
    def test_search_empty_query(self):
        """Test search with empty query"""
        response = client.get("/search?query=")
        assert response.status_code == 200
        data = response.json()
        assert "results" in data
        assert len(data["results"]) == 0
    
    def test_search_special_characters(self):
        """Test search with special characters"""
        response = client.get("/search?query=test@#$%")
        assert response.status_code == 200
        data = response.json()
        assert "results" in data
    
    def test_cve_details_not_found(self):
        """Test CVE details for non-existent CVE"""
        response = client.get("/cve/CVE-2025-9999")
        assert response.status_code == 200
        data = response.json()
        assert "error" in data
        assert data["error"] == "CVE not found"
    
    def test_cve_details_invalid_format(self):
        """Test CVE details with invalid CVE format"""
        response = client.get("/cve/INVALID-FORMAT")
        assert response.status_code == 200
        data = response.json()
        assert "error" in data

# Performance tests
class TestPerformance:
    """Test performance aspects"""
    
    def test_search_performance_large_dataset(self):
        """Test search performance with large dataset"""
        # Create a large dataset
        global CVE_DATA
        CVE_DATA = []
        for i in range(1000):
            cve_item = SAMPLE_CVE_DATA["CVE_Items"][0].copy()
            cve_item["cve"]["CVE_data_meta"]["ID"] = f"CVE-2025-{i:04d}"
            CVE_DATA.append(cve_item)
        
        # Test search performance
        import time
        start_time = time.time()
        response = client.get("/search?query=CVE-2025-0001")
        end_time = time.time()
        
        assert response.status_code == 200
        # Should complete within reasonable time (adjust threshold as needed)
        assert end_time - start_time < 1.0  # 1 second threshold

if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 