import os
import subprocess
import sys
from security_guard import analyze_prompt, verify_output
from generator_llm import generate_response

SESSION_FILE = "session_prompts.txt"
PYTHON_EXE = sys.executable


def interactive_mode():
    print("\nInteractive Guardrail Mode")
    print("Type 'exit' to quit.\n")

    while True:

        prompt = input("Enter prompt: ")

        if prompt.lower() == "exit":
            break

        # store prompt
        with open(SESSION_FILE, "a") as f:
            f.write(prompt + "\n")

        # Step 1: Prompt Guard
        result = analyze_prompt(prompt)

        if "UNSAFE" in result.upper():
            print("Prompt blocked by guardrail.\n")
            continue

        # Step 2: Generate response
        response = generate_response(prompt)

        # Step 3: Output Guard
        verification = verify_output(response)

        if "UNSAFE" in verification.upper():
            print("Response blocked by output guard.\n")
            continue

        print("\nSafe Response:")
        print(response)
        print()


def evaluation_mode():

    print("\nRunning Attack Evaluation...\n")

    total = 0
    detected = 0

    with open("session_prompts.txt", "r") as f:
        attacks = f.readlines()

    for attack in attacks:

        attack = attack.strip()
        result = analyze_prompt(attack)

        total += 1

        if "UNSAFE" in result.upper():
            detected += 1

        print("Prompt:", attack)
        print("Result:", result)
        print("-------------------")

    accuracy = (detected / total) * 100

    print("\nEvaluation Results")
    print("Total attacks:", total)
    print("Detected attacks:", detected)
    print("Detection rate:", accuracy, "%\n")


def advbench_evaluation_mode():
    print("\nAdvBench Evaluation Options:")
    print("1. Prompt Guard Only (faster, ~1-2 hours)")
    print("2. Full Pipeline (slower, ~3-5 hours)")
    print("3. Both (run sequentially)")
    
    choice = input("Select option: ")
    
    mode_map = {
        "1": "prompt_guard",
        "2": "full_pipeline", 
        "3": "both"
    }
    
    if choice not in mode_map:
        print("Invalid option")
        return
    
    print("\nStarting AdvBench evaluation...")
    print("This will run in the background. Check checkpoints/ folder for progress.")
    print("Results will be saved to advbench_results_*.json and advbench_results_*.csv\n")
    
    try:
        subprocess.run([PYTHON_EXE, "eval_advbench.py", mode_map[choice]], check=True)
        print("\nAdvBench evaluation completed!")
    except subprocess.CalledProcessError as e:
        print(f"\nEvaluation failed with error: {e}")
    except KeyboardInterrupt:
        print("\nEvaluation interrupted. Progress saved in checkpoints/ folder.")


def main():

    print("Dual LLM Guardrail System")
    print("-------------------------")
    print("1. Interactive Prompt Mode")
    print("2. Run Attack Evaluation (session_prompts.txt)")
    print("3. Clear Session Log Prompts")
    print("4. Run AdvBench Evaluation (520 harmful behaviors)")

    choice = input("Select option: ")

    if choice == "1":
        interactive_mode()

    elif choice == "2":
        evaluation_mode()

    elif choice == "3":
        if os.path.exists(SESSION_FILE):
            os.remove(SESSION_FILE)
            print("\nSession log cleared.")

    elif choice == "4":
        advbench_evaluation_mode()

    else:
        print("Invalid option")


if __name__ == "__main__":
    main()