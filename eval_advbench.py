import csv
import json
import os
import requests
from typing import List, Dict, Any
from security_guard import analyze_prompt, verify_output
from generator_llm import generate_response

ADVBENCH_URL = "https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv"
ADVBENCH_CSV = "advbench_harmful_behaviors.csv"
RESULTS_JSON = "advbench_results.json"
RESULTS_CSV = "advbench_results.csv"
CHECKPOINT_DIR = "checkpoints"
CHECKPOINT_INTERVAL = 50


def download_advbench() -> str:
    if os.path.exists(ADVBENCH_CSV):
        print(f"Found existing {ADVBENCH_CSV}")
        return ADVBENCH_CSV
    
    print(f"Downloading AdvBench from {ADVBENCH_URL}...")
    response = requests.get(ADVBENCH_URL, timeout=30)
    response.raise_for_status()
    
    with open(ADVBENCH_CSV, "w", newline="", encoding="utf-8") as f:
        f.write(response.text)
    
    print(f"Saved to {ADVBENCH_CSV}")
    return ADVBENCH_CSV


def load_advbench(csv_path: str) -> List[str]:
    prompts = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            goal = row.get("goal", "").strip()
            if goal:
                prompts.append(goal)
    print(f"Loaded {len(prompts)} harmful behaviors from AdvBench")
    return prompts


def get_checkpoint_path(mode: str, batch_num: int) -> str:
    os.makedirs(CHECKPOINT_DIR, exist_ok=True)
    return os.path.join(CHECKPOINT_DIR, f"{mode}_batch_{batch_num}.json")


def load_checkpoint(mode: str, batch_num: int) -> Dict[str, Any]:
    path = get_checkpoint_path(mode, batch_num)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


def save_checkpoint(results: Dict[str, Any], mode: str, batch_num: int):
    path = get_checkpoint_path(mode, batch_num)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"  Checkpoint saved: {path}")


def load_latest_checkpoint(mode: str, expected_total: int) -> tuple:
    if not os.path.exists(CHECKPOINT_DIR):
        return None, 0, []
    
    checkpoints = [f for f in os.listdir(CHECKPOINT_DIR) if f.startswith(f"{mode}_batch_") and f.endswith(".json")]
    if not checkpoints:
        return None, 0, []
    
    batch_nums = [int(f.split("_")[-1].replace(".json", "")) for f in checkpoints]
    latest_batch = max(batch_nums)
    
    checkpoint = load_checkpoint(mode, latest_batch)
    if checkpoint:
        checkpoint["total"] = expected_total
        print(f"Resuming {mode} from batch {latest_batch} ({len(checkpoint['details'])} prompts completed)")
        return checkpoint, latest_batch, checkpoint["details"]
    
    return None, 0, []


def merge_results(base_results: Dict[str, Any], new_details: List[Dict], start_idx: int) -> Dict[str, Any]:
    for i, detail in enumerate(new_details):
        detail["index"] = start_idx + i + 1
    base_results["details"].extend(new_details)
    return base_results


def evaluate_prompt_guard(prompts: List[str]) -> Dict[str, Any]:
    checkpoint, completed_batches, existing_details = load_latest_checkpoint("prompt_guard", len(prompts))
    
    if checkpoint:
        results = checkpoint
        start_batch = completed_batches
        start_idx = len(existing_details)
    else:
        results = {
            "mode": "prompt_guard_only",
            "total": len(prompts),
            "blocked": 0,
            "passed": 0,
            "details": []
        }
        start_batch = 0
        start_idx = 0
    
    total_batches = (len(prompts) + CHECKPOINT_INTERVAL - 1) // CHECKPOINT_INTERVAL
    
    for batch_num in range(start_batch, total_batches):
        batch_start = batch_num * CHECKPOINT_INTERVAL
        batch_end = min(batch_start + CHECKPOINT_INTERVAL, len(prompts))
        batch_prompts = prompts[batch_start:batch_end]
        
        print(f"  Batch {batch_num + 1}/{total_batches} (prompts {batch_start + 1}-{batch_end})")
        
        batch_details = []
        batch_blocked = 0
        batch_passed = 0
        
        for i, prompt in enumerate(batch_prompts):
            global_idx = batch_start + i + 1
            print(f"    [{global_idx}/{len(prompts)}] Testing prompt guard...")
            
            result = analyze_prompt(prompt)
            is_unsafe = "UNSAFE" in result.upper()
            
            detail = {
                "index": global_idx,
                "prompt": prompt,
                "guard_result": result,
                "blocked": is_unsafe
            }
            batch_details.append(detail)
            
            if is_unsafe:
                batch_blocked += 1
            else:
                batch_passed += 1
        
        results["blocked"] += batch_blocked
        results["passed"] += batch_passed
        results["details"].extend(batch_details)
        
        save_checkpoint(results, "prompt_guard", batch_num + 1)
        
        print(f"    Batch complete - Blocked: {batch_blocked}, Passed: {batch_passed}")
        print(f"    Total so far - Blocked: {results['blocked']}, Passed: {results['passed']}")
    
    results["detection_rate"] = (results["blocked"] / results["total"]) * 100
    return results


def evaluate_full_pipeline(prompts: List[str]) -> Dict[str, Any]:
    checkpoint, completed_batches, existing_details = load_latest_checkpoint("full_pipeline", len(prompts))
    
    if checkpoint:
        results = checkpoint
        start_batch = completed_batches
    else:
        results = {
            "mode": "full_pipeline",
            "total": len(prompts),
            "blocked_at_prompt_guard": 0,
            "blocked_at_output_guard": 0,
            "safe_responses": 0,
            "errors": 0,
            "details": []
        }
        start_batch = 0
    
    total_batches = (len(prompts) + CHECKPOINT_INTERVAL - 1) // CHECKPOINT_INTERVAL
    
    for batch_num in range(start_batch, total_batches):
        batch_start = batch_num * CHECKPOINT_INTERVAL
        batch_end = min(batch_start + CHECKPOINT_INTERVAL, len(prompts))
        batch_prompts = prompts[batch_start:batch_end]
        
        print(f"  Batch {batch_num + 1}/{total_batches} (prompts {batch_start + 1}-{batch_end})")
        
        batch_details = []
        batch_pg_blocked = 0
        batch_og_blocked = 0
        batch_safe = 0
        batch_errors = 0
        
        for i, prompt in enumerate(batch_prompts):
            global_idx = batch_start + i + 1
            print(f"    [{global_idx}/{len(prompts)}] Running full pipeline...")
            
            detail = {
                "index": global_idx,
                "prompt": prompt,
                "prompt_guard_result": None,
                "generator_response": None,
                "output_guard_result": None,
                "final_status": None,
                "error": None
            }
            
            try:
                pg_result = analyze_prompt(prompt)
                detail["prompt_guard_result"] = pg_result
                
                if "UNSAFE" in pg_result.upper():
                    detail["final_status"] = "blocked_at_prompt_guard"
                    batch_pg_blocked += 1
                    batch_details.append(detail)
                    continue
                
                gen_response = generate_response(prompt)
                detail["generator_response"] = gen_response
                
                og_result = verify_output(gen_response)
                detail["output_guard_result"] = og_result
                
                if "UNSAFE" in og_result.upper():
                    detail["final_status"] = "blocked_at_output_guard"
                    batch_og_blocked += 1
                else:
                    detail["final_status"] = "safe_response"
                    batch_safe += 1
                    
            except Exception as e:
                detail["final_status"] = "error"
                detail["error"] = str(e)
                batch_errors += 1
            
            batch_details.append(detail)
        
        results["blocked_at_prompt_guard"] += batch_pg_blocked
        results["blocked_at_output_guard"] += batch_og_blocked
        results["safe_responses"] += batch_safe
        results["errors"] += batch_errors
        results["details"].extend(batch_details)
        
        save_checkpoint(results, "full_pipeline", batch_num + 1)
        
        print(f"    Batch complete - PG Blocked: {batch_pg_blocked}, OG Blocked: {batch_og_blocked}, Safe: {batch_safe}, Errors: {batch_errors}")
        print(f"    Total so far - PG Blocked: {results['blocked_at_prompt_guard']}, OG Blocked: {results['blocked_at_output_guard']}, Safe: {results['safe_responses']}, Errors: {results['errors']}")
    
    total_blocked = results["blocked_at_prompt_guard"] + results["blocked_at_output_guard"]
    results["detection_rate"] = (total_blocked / results["total"]) * 100
    return results


def save_results_json(results: Dict[str, Any], path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"Saved JSON results to {path}")


def save_results_csv(results: Dict[str, Any], path: str):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        
        if results["mode"] == "prompt_guard_only":
            writer.writerow(["index", "prompt", "guard_result", "blocked"])
            for d in results["details"]:
                writer.writerow([d["index"], d["prompt"], d["guard_result"], d["blocked"]])
            
            writer.writerow([])
            writer.writerow(["Summary"])
            writer.writerow(["Total", results["total"]])
            writer.writerow(["Blocked", results["blocked"]])
            writer.writerow(["Passed", results["passed"]])
            writer.writerow(["Detection Rate %", f"{results['detection_rate']:.2f}"])
            
        else:
            writer.writerow(["index", "prompt", "prompt_guard_result", "generator_response", "output_guard_result", "final_status", "error"])
            for d in results["details"]:
                writer.writerow([
                    d["index"],
                    d["prompt"],
                    d["prompt_guard_result"] or "",
                    d["generator_response"] or "",
                    d["output_guard_result"] or "",
                    d["final_status"] or "",
                    d["error"] or ""
                ])
            
            writer.writerow([])
            writer.writerow(["Summary"])
            writer.writerow(["Total", results["total"]])
            writer.writerow(["Blocked at Prompt Guard", results["blocked_at_prompt_guard"]])
            writer.writerow(["Blocked at Output Guard", results["blocked_at_output_guard"]])
            writer.writerow(["Safe Responses", results["safe_responses"]])
            writer.writerow(["Errors", results["errors"]])
            writer.writerow(["Detection Rate %", f"{results['detection_rate']:.2f}"])
    
    print(f"Saved CSV results to {path}")


def run_evaluation(mode: str = "both"):
    print("=" * 60)
    print("AdvBench Evaluation for LLM Guardrail")
    print("=" * 60)
    
    csv_path = download_advbench()
    prompts = load_advbench(csv_path)
    
    pg_results = None
    fp_results = None
    
    if mode in ["prompt_guard", "both"]:
        print("\n" + "=" * 60)
        print("MODE 1: Prompt Guard Only")
        print("=" * 60)
        pg_results = evaluate_prompt_guard(prompts)
        save_results_json(pg_results, RESULTS_JSON.replace(".json", "_prompt_guard.json"))
        save_results_csv(pg_results, RESULTS_CSV.replace(".csv", "_prompt_guard.csv"))
        
        print(f"\nPrompt Guard Results:")
        print(f"  Total: {pg_results['total']}")
        print(f"  Blocked: {pg_results['blocked']}")
        print(f"  Passed: {pg_results['passed']}")
        print(f"  Detection Rate: {pg_results['detection_rate']:.2f}%")
    
    if mode in ["full_pipeline", "both"]:
        print("\n" + "=" * 60)
        print("MODE 2: Full Pipeline")
        print("=" * 60)
        fp_results = evaluate_full_pipeline(prompts)
        save_results_json(fp_results, RESULTS_JSON.replace(".json", "_full_pipeline.json"))
        save_results_csv(fp_results, RESULTS_CSV.replace(".csv", "_full_pipeline.csv"))
        
        print(f"\nFull Pipeline Results:")
        print(f"  Total: {fp_results['total']}")
        print(f"  Blocked at Prompt Guard: {fp_results['blocked_at_prompt_guard']}")
        print(f"  Blocked at Output Guard: {fp_results['blocked_at_output_guard']}")
        print(f"  Safe Responses: {fp_results['safe_responses']}")
        print(f"  Errors: {fp_results['errors']}")
        print(f"  Detection Rate: {fp_results['detection_rate']:.2f}%")
    
    if mode == "both" and pg_results and fp_results:
        combined = {
            "prompt_guard_only": pg_results,
            "full_pipeline": fp_results
        }
        save_results_json(combined, RESULTS_JSON)
    
    print("\n" + "=" * 60)
    print("Evaluation Complete!")
    print("=" * 60)


if __name__ == "__main__":
    import sys
    mode = sys.argv[1] if len(sys.argv) > 1 else "both"
    if mode not in ["prompt_guard", "full_pipeline", "both"]:
        print("Usage: python eval_advbench.py [prompt_guard|full_pipeline|both]")
        sys.exit(1)
    run_evaluation(mode)