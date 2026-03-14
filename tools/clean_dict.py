import nltk
from nltk.corpus import wordnet
from better_profanity import profanity

# Initial setup - downloads the dictionary database locally
nltk.download("wordnet")
nltk.download("omw-1.4")


def clean_file(input_filename, output_filename):
    clean_words = []

    try:
        with open(input_filename, "r") as f:
            # Read every line and remove extra spaces
            original_words = [line.strip() for line in f if line.strip()]

        print(f"Processing {len(original_words)} words...")

        for word in original_words:
            # Check 1: Is it offensive?
            if profanity.contains_profanity(word):
                continue  # Skip it

            # Check 2: Does it have a definition?
            # wordnet.synsets(word) returns an empty list if the word isn't found
            if not wordnet.synsets(word):
                continue  # Skip it

            # If it passed both checks, add it to our list
            clean_words.append(word)

        # Write the survivors to a new file
        with open(output_filename, "w") as f:
            for word in clean_words:
                f.write(word + "\n")

        print(
            f"Done! Saved {len(clean_words)} valid, safe words to '{output_filename}'."
        )
        print(f"Removed {len(original_words) - len(clean_words)} words.")

    except FileNotFoundError:
        print("Error: The input file was not found.")


# Run the process
clean_file("words.txt", "cleaned_dictionary_words.txt")
