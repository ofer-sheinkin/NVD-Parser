# NVD Parser Test Suite

This directory contains a comprehensive test suite for the NVD Parser application, designed to ensure reliability, functionality, and performance of the CVE data processing and API endpoints.

## Test Structure

### Test Files

- **`test_main.py`** - Core test suite covering basic functionality
- **`test_advanced.py`** - Advanced tests with complex scenarios and edge cases
- **`test_data.py`** - Test data module with various CVE data samples
- **`run_tests.py`** - Test runner script for easy test execution
- **`pytest.ini`** - Pytest configuration file

### Test Categories

#### 1. Unit Tests (`TestHelperFunctions`, `TestDataProcessing`, `TestErrorHandling`)
- **Helper Functions**: Test utility functions like `get_available_years()` and `download_nvd_feeds()`
- **Data Processing**: Test CVE data parsing, CWE extraction, CVSS score handling
- **Error Handling**: Test graceful handling of malformed data and edge cases

#### 2. API Endpoint Tests (`TestAPIEndpoints`)
- **Root Endpoint**: Basic API availability
- **Load Endpoints**: Data loading with different modes (latest, all, specific years)
- **Search Endpoints**: CVE search functionality with various query types
- **CVE Details**: Individual CVE information retrieval
- **UI Endpoint**: Web interface availability

#### 3. Integration Tests (`TestIntegration`)
- **Full Workflow**: Complete end-to-end testing
- **Data Flow**: Test data loading, searching, and retrieval pipeline

#### 4. Advanced Tests (`test_advanced.py`)
- **Complex Data Scenarios**: Multiple descriptions, CWEs, references
- **Year Filtering**: Year-based search and filtering
- **Search Functionality**: Case sensitivity, partial matching, limits
- **Performance**: Large dataset handling and response times

## Test Data

The `test_data.py` module provides various CVE data samples:

- **`SAMPLE_CVE_DATA`**: Basic CVE with CVSS v3 and v2 scores
- **`MULTI_DESC_CVE`**: CVE with multiple descriptions
- **`MULTI_CWE_CVE`**: CVE with multiple CWEs (including filtered ones)
- **`MULTI_REF_CVE`**: CVE with multiple references and tags
- **`COMPLEX_CPE_CVE`**: CVE with complex CPE configurations
- **`MALFORMED_CVE_DATA`**: Intentionally malformed data for error testing
- **`EMPTY_CVE_DATA`**: Empty dataset for edge case testing
- **`YEAR_*_CVE`**: Year-specific test data

## Running Tests

### Prerequisites

Install test dependencies:
```bash
pip install -r requirements.txt
```

### Basic Test Execution

Run all tests:
```bash
python -m pytest
```

Run with verbose output:
```bash
python -m pytest -v
```

### Using the Test Runner

The `run_tests.py` script provides convenient test execution options:

```bash
# Run all tests
python run_tests.py

# Run only unit tests
python run_tests.py --type unit

# Run only integration tests
python run_tests.py --type integration

# Run tests with coverage
python run_tests.py --type coverage

# Run with verbose output
python run_tests.py --verbose

# Generate HTML coverage report
python run_tests.py --type coverage --html
```

### Running Specific Test Classes

```bash
# Run only helper function tests
python -m pytest test_main.py::TestHelperFunctions

# Run only API endpoint tests
python -m pytest test_main.py::TestAPIEndpoints

# Run only advanced data processing tests
python -m pytest test_advanced.py::TestAdvancedDataProcessing
```

### Running Specific Test Methods

```bash
# Run a specific test method
python -m pytest test_main.py::TestAPIEndpoints::test_read_root

# Run tests matching a pattern
python -m pytest -k "search"
```

## Test Coverage

The test suite includes coverage reporting:

```bash
# Run with coverage
python -m pytest --cov=main --cov-report=term-missing

# Generate HTML coverage report
python -m pytest --cov=main --cov-report=html:htmlcov
```

Coverage reports will show:
- **Terminal Report**: Missing lines in terminal output
- **HTML Report**: Detailed coverage in `htmlcov/index.html`
- **XML Report**: Coverage data for CI/CD integration

## Test Scenarios Covered

### Data Loading
- ✅ Latest year loading
- ✅ All years loading
- ✅ Specific years loading
- ✅ Year range loading
- ✅ Invalid mode handling
- ✅ Invalid year format handling
- ✅ Mixed year format handling

### Search Functionality
- ✅ CVE ID search (exact and partial)
- ✅ Keyword search in descriptions
- ✅ Case insensitive search
- ✅ Year filtering
- ✅ Empty query handling
- ✅ Special character handling
- ✅ Result limit enforcement (50 items)

### CVE Details
- ✅ Complete CVE information retrieval
- ✅ Multiple descriptions handling
- ✅ Multiple CWEs handling
- ✅ Multiple references with tags
- ✅ Complex CPE configurations
- ✅ Non-existent CVE handling
- ✅ Invalid CVE format handling

### Data Processing
- ✅ CVE ID extraction
- ✅ Description extraction (single and multiple)
- ✅ CWE extraction and filtering
- ✅ Reference extraction with metadata
- ✅ CPE extraction and filtering
- ✅ CVSS score extraction (v2 and v3)
- ✅ Severity classification

### Error Handling
- ✅ Malformed CVE data
- ✅ Missing required fields
- ✅ Empty datasets
- ✅ Network failures (mocked)
- ✅ Invalid input formats

### Performance
- ✅ Large dataset handling (1000+ CVEs)
- ✅ Search performance benchmarks
- ✅ Response time validation

## Mocking Strategy

The test suite uses comprehensive mocking to avoid external dependencies:

- **Network Requests**: All HTTP requests to NVD are mocked
- **File Operations**: Gzip decompression is mocked with test data
- **Time-dependent Functions**: Current year calculations are controlled

## Continuous Integration

The test suite is designed for CI/CD integration:

```yaml
# Example GitHub Actions workflow
- name: Run Tests
  run: |
    pip install -r requirements.txt
    python -m pytest --cov=main --cov-report=xml
    python -m pytest --cov=main --cov-report=html:htmlcov
```

## Test Maintenance

### Adding New Tests

1. **Unit Tests**: Add to appropriate test class in `test_main.py`
2. **Integration Tests**: Add to `TestIntegration` class
3. **Advanced Tests**: Add to appropriate class in `test_advanced.py`
4. **Test Data**: Add new data samples to `test_data.py`

### Test Data Guidelines

- Use realistic CVE data structures
- Include edge cases and error conditions
- Maintain consistency with NVD data format
- Document any special test data requirements

### Best Practices

- **Isolation**: Each test should be independent
- **Setup/Teardown**: Use `setup_method()` for test data preparation
- **Descriptive Names**: Use clear, descriptive test method names
- **Documentation**: Include docstrings explaining test purpose
- **Assertions**: Use specific assertions with meaningful messages

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all dependencies are installed
2. **Mock Issues**: Check that external calls are properly mocked
3. **Data State**: Ensure global `CVE_DATA` is properly reset between tests
4. **Performance Failures**: Adjust performance thresholds based on system capabilities

### Debug Mode

Run tests with debug output:
```bash
python -m pytest -v -s --tb=long
```

### Test Isolation

Run tests in isolation to identify problematic tests:
```bash
python -m pytest --maxfail=1
```

## Contributing

When adding new features to the NVD Parser:

1. **Write Tests First**: Follow TDD principles
2. **Cover Edge Cases**: Include tests for error conditions
3. **Update Test Data**: Add relevant test data samples
4. **Maintain Coverage**: Ensure new code is covered by tests
5. **Document Changes**: Update this README if test structure changes

## Test Metrics

The test suite provides several metrics:

- **Coverage Percentage**: Code coverage by tests
- **Test Count**: Total number of test methods
- **Execution Time**: Time to run all tests
- **Success Rate**: Percentage of passing tests

Monitor these metrics to ensure test quality and application reliability. 

## PostgreSQL Integration

To store CVE data in PostgreSQL:

1. Install PostgreSQL and create a database (default: `nvd`).
2. Create the CVE table with the following SQL:

```sql
CREATE TABLE cves (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(32) UNIQUE NOT NULL,
    description TEXT,
    published_date TIMESTAMP,
    severity VARCHAR(16),
    cvss3 NUMERIC,
    cwe VARCHAR(32),
    references TEXT[],
    cpes TEXT[],
    exploitability VARCHAR(64)
);
```

3. Set environment variables for DB connection (or use defaults):
   - `POSTGRES_DB` (default: nvd)
   - `POSTGRES_USER` (default: postgres)
   - `POSTGRES_PASSWORD` (default: password)
   - `POSTGRES_HOST` (default: localhost)
   - `POSTGRES_PORT` (default: 5432)

4. On loading CVE data, records will be inserted/updated in the database automatically.

--- 