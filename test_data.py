"""
Test data for NVD Parser tests
Contains various CVE data samples for comprehensive testing
"""

# Sample CVE data with different scenarios
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
                            "value": "Test vulnerability description with SQL injection"
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
                            "value": "Another test vulnerability with buffer overflow"
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

# CVE with multiple descriptions
MULTI_DESC_CVE = {
    "CVE_Items": [
        {
            "cve": {
                "CVE_data_meta": {
                    "ID": "CVE-2025-0002"
                },
                "description": {
                    "description_data": [
                        {
                            "value": "First description"
                        },
                        {
                            "value": "Second description"
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
                    "reference_data": []
                }
            },
            "configurations": {
                "nodes": []
            },
            "impact": {},
            "publishedDate": "2025-01-01T00:00:00Z",
            "lastModifiedDate": "2025-01-01T00:00:00Z"
        }
    ]
}

# CVE with multiple CWEs
MULTI_CWE_CVE = {
    "CVE_Items": [
        {
            "cve": {
                "CVE_data_meta": {
                    "ID": "CVE-2025-0003"
                },
                "description": {
                    "description_data": [
                        {
                            "value": "Vulnerability with multiple CWEs"
                        }
                    ]
                },
                "problemtype": {
                    "problemtype_data": [
                        {
                            "description": [
                                {
                                    "value": "CWE-79"
                                },
                                {
                                    "value": "CWE-287"
                                },
                                {
                                    "value": "NVD-CWE-Other"
                                }
                            ]
                        }
                    ]
                },
                "references": {
                    "reference_data": []
                }
            },
            "configurations": {
                "nodes": []
            },
            "impact": {},
            "publishedDate": "2025-01-01T00:00:00Z",
            "lastModifiedDate": "2025-01-01T00:00:00Z"
        }
    ]
}

# CVE with multiple references
MULTI_REF_CVE = {
    "CVE_Items": [
        {
            "cve": {
                "CVE_data_meta": {
                    "ID": "CVE-2025-0004"
                },
                "description": {
                    "description_data": [
                        {
                            "value": "Vulnerability with multiple references"
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
                            "url": "https://example1.com/vuln",
                            "name": "First Reference",
                            "tags": ["Vendor Advisory"]
                        },
                        {
                            "url": "https://example2.com/vuln",
                            "name": "Second Reference",
                            "tags": ["Patch", "Third Party Advisory"]
                        }
                    ]
                }
            },
            "configurations": {
                "nodes": []
            },
            "impact": {},
            "publishedDate": "2025-01-01T00:00:00Z",
            "lastModifiedDate": "2025-01-01T00:00:00Z"
        }
    ]
}

# CVE with complex CPE configuration
COMPLEX_CPE_CVE = {
    "CVE_Items": [
        {
            "cve": {
                "CVE_data_meta": {
                    "ID": "CVE-2025-0005"
                },
                "description": {
                    "description_data": [
                        {
                            "value": "Vulnerability with complex CPE configuration"
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
                    "reference_data": []
                }
            },
            "configurations": {
                "nodes": [
                    {
                        "cpe_match": [
                            {
                                "vulnerable": True,
                                "cpe23Uri": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "1.0",
                                "versionEndIncluding": "1.5"
                            },
                            {
                                "vulnerable": False,
                                "cpe23Uri": "cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*:*"
                            }
                        ]
                    }
                ]
            },
            "impact": {},
            "publishedDate": "2025-01-01T00:00:00Z",
            "lastModifiedDate": "2025-01-01T00:00:00Z"
        }
    ]
}

# Malformed CVE data for error testing
MALFORMED_CVE_DATA = {
    "CVE_Items": [
        {
            "cve": {
                "CVE_data_meta": {
                    "ID": "CVE-2025-0006"
                }
                # Missing description and other fields
            }
        },
        {
            # Missing cve field entirely
            "configurations": {},
            "impact": {}
        },
        {
            "cve": {
                "CVE_data_meta": {
                    "ID": "CVE-2025-0007"
                },
                "description": {
                    "description_data": []  # Empty descriptions
                },
                "problemtype": {
                    "problemtype_data": []
                },
                "references": {
                    "reference_data": []
                }
            },
            "configurations": {
                "nodes": []
            },
            "impact": {}
        }
    ]
}

# Empty CVE data
EMPTY_CVE_DATA = {
    "CVE_Items": []
}

# Test data for different years
YEAR_2023_CVE = {
    "CVE_Items": [
        {
            "cve": {
                "CVE_data_meta": {
                    "ID": "CVE-2023-0001"
                },
                "description": {
                    "description_data": [
                        {
                            "value": "2023 vulnerability"
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
                    "reference_data": []
                }
            },
            "configurations": {
                "nodes": []
            },
            "impact": {},
            "publishedDate": "2023-01-01T00:00:00Z",
            "lastModifiedDate": "2023-01-01T00:00:00Z"
        }
    ]
}

YEAR_2022_CVE = {
    "CVE_Items": [
        {
            "cve": {
                "CVE_data_meta": {
                    "ID": "CVE-2022-0001"
                },
                "description": {
                    "description_data": [
                        {
                            "value": "2022 vulnerability"
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
                    "reference_data": []
                }
            },
            "configurations": {
                "nodes": []
            },
            "impact": {},
            "publishedDate": "2022-01-01T00:00:00Z",
            "lastModifiedDate": "2022-01-01T00:00:00Z"
        }
    ]
} 