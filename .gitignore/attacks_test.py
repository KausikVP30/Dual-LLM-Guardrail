from security_guard import analyze_prompt

total = 0
detected = 0

with open("attacks.txt", "r") as f:
    attacks = f.readlines()

for attack in attacks:
    attack = attack.strip()

    result = analyze_prompt(attack)

    total += 1

    if "UNSAFE" in result.upper():
        detected += 1

    print("Prompt:", attack)
    print("Result:", result)
    print("--------------------")

accuracy = (detected / total) * 100

print("\nEvaluation Results")
print("Total attacks:", total)
print("Detected attacks:", detected)
print("Detection rate:", accuracy, "%")