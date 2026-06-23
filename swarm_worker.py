#!/usr/bin/env python3
"""
Antigravity IDA Bridge — Swarm Worker (Optimized)
===================================================
Batch AI analysis of unnamed functions using Gemini.

Fixes (v5.2):
- Shared BridgeClient (connection pooling, no TCP exhaustion)
- Exponential backoff for LLM rate limits (429)
- Replaced print() with logging
"""

import os
import json
import time
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

from core.client import BridgeClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s")

API_KEY = os.environ.get("GEMINI_API_KEY", "")
MODEL_NAME = os.environ.get("GEMINI_MODEL", "gemini-3.1-pro-preview")


class FunctionAnalysis(BaseModel):
    suggested_name: str = Field(
        description="Descriptive CamelCase/snake_case name. No 'sub_'")
    comment: str = Field(
        description="Concise technical explanation of the logic")


def analyze_with_backoff(client, ea: str, pseudocode: str, retries: int = 4):
    """LLM call with exponential backoff for rate limit protection."""
    prompt = f"Analyze this C/C++ pseudocode at {ea}:\n```cpp\n{pseudocode}\n```\nSuggest a meaningful name and comment."

    for attempt in range(retries):
        try:
            response = client.models.generate_content(
                model=MODEL_NAME,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=FunctionAnalysis,
                    temperature=0.2,
                ),
            )
            return json.loads(response.text)
        except Exception as e:
            err_str = str(e).lower()
            if "429" in err_str or "quota" in err_str or "exhausted" in err_str:
                wait_time = 2 ** attempt
                logging.warning(
                    f"[Rate Limit] Retrying {ea} in {wait_time}s...")
                time.sleep(wait_time)
            else:
                logging.error(f"Gemini API error for {ea}: {e}")
                break
    return None


def process_batch(bridge: BridgeClient, functions: list, max_workers: int = 5):
    if not API_KEY:
        logging.error("GEMINI_API_KEY is not set!")
        return

    genai_client = genai.Client(api_key=API_KEY)
    logging.info(
        f"Processing {
            len(functions)} functions with {max_workers} threads...")
    mutations = []

    def worker(func_info):
        ea, name = func_info["ea"], func_info["name"]
        ps_res = bridge.pseudocode(ea)
        if "error" in ps_res:
            logging.error(f"Decompile failed {ea}: {ps_res['error']}")
            return None

        code = ps_res.get("pseudocode", "")
        if not code or len(code) < 10:
            return None

        analysis = analyze_with_backoff(genai_client, ea, code)
        if analysis and analysis.get(
                "suggested_name") and not analysis["suggested_name"].startswith("sub_"):
            return {
                "ea": ea, "old_name": name,
                "new_name": analysis["suggested_name"],
                "comment": analysis.get("comment", "")
            }
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(worker, f): f for f in functions}
        for future in as_completed(futures):
            res = future.result()
            if res:
                mutations.extend([
                    {"op": "rename-func", "ea": res["ea"], "name": res["new_name"]},
                    {"op": "comment-func", "ea": res["ea"], "comment": res["comment"]}
                ])
                logging.info(f"[+] {res['old_name']} -> {res['new_name']}")

    if mutations:
        logging.info(f"Applying {len(mutations)} mutations atomically...")
        res = bridge.batch(mutations)
        if "error" in res:
            logging.error(f"Batch failed: {res['error']}")
        else:
            bridge.wait_analysis()
            logging.info("Done.")


def main():
    parser = argparse.ArgumentParser(description="Antigravity Swarm Worker")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--workers", type=int, default=3)
    args = parser.parse_args()

    bridge = BridgeClient()
    res = bridge.functions()
    if "error" in res:
        logging.error(f"Bridge error: {res['error']}")
        return

    unnamed = [
        f for f in res.get(
            "functions",
            []) if f["name"].startswith("sub_")]
    if unnamed:
        process_batch(bridge, unnamed[:args.limit], max_workers=args.workers)
    else:
        logging.info("No unnamed functions found.")


if __name__ == "__main__":
    main()
