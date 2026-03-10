from generator_llm import generate_response

prompt = input("Ask something: ")

response = generate_response(prompt)

print("\nModel Response:")
print(response)