import os
from security_guard import analyze_prompt, verify_output
from generator_llm import generate_response

SESSION_FILE = "session_prompts.txt"


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


def main():

    print("Dual LLM Guardrail System")
    print("-------------------------")
    print("1. Interactive Prompt Mode")
    print("2. Run Attack Evaluation")
    print("3. Clear Session Log Prompts")

    choice = input("Select option: ")

    if choice == "1":
        interactive_mode()

    elif choice == "2":
        evaluation_mode()

    elif choice == "3":
        if os.path.exists(SESSION_FILE):
            os.delete(SESSION_FILE)
            print("\nSession log cleared.")

    else:
        print("Invalid option")


if __name__ == "__main__":
    main()