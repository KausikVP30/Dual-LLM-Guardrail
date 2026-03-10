import ollama

def generate_response(prompt):

    system_prompt = """
You are a helpful AI assistant.
Answer the user's question clearly and accurately.
Do not produce harmful or illegal instructions.
"""

    response = ollama.chat(
        model="llama3",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
    )

    return response["message"]["content"]