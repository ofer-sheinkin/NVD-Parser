#!/usr/bin/env python3
"""
NVD Parser Application Entry Point
"""
import argparse
import uvicorn

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NVD Parser Application")
    parser.add_argument("--port", type=int, default=8001, help="Port to run the server on (default: 8001)")
    args = parser.parse_args()
    
    uvicorn.run("src.main:app", host="0.0.0.0", port=args.port) 