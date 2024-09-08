import hashlib
import bitarray
from tabulate import tabulate
import time

# Constants
K = 15  # Number of hash functions
BIT_ARRAY_SIZE = 1000  # Size of the Bit Array
DATASETS = [
    ("Dataset1", 8, 100),
    ("Dataset2", 10, 100),
    ("Dataset3", 12, 100),
]

# File paths
ROCKYOU_FILE_PATH = "rockyou.txt"
BETA_FILES = ["Beta1.txt", "Beta2.txt", "Beta3.txt"]

# ANSI color codes
RED = '\033[101m'  # Red color
ENDC = '\033[0m'   # End color

# Functions g and h
def g(input_string):
    return hashlib.md5(input_string.encode()).hexdigest()

def h(input_string):
    return hashlib.sha256(input_string.encode()).hexdigest()

# Extract passwords from the rockyou.txt file
def extract_passwords(file_path, length, count):
    passwords = []
    with open(file_path, 'r', encoding='latin-1') as file:
        for line in file:
            password = line.strip()
            if len(password) == length:
                passwords.append(password)
            if len(passwords) >= count:
                break
    return sorted(passwords)[:count]

def create_datasets():
    datasets = []
    for dataset_name, length, count in DATASETS:
        passwords = extract_passwords(ROCKYOU_FILE_PATH, length, count)
        datasets.append((dataset_name, passwords))
    return datasets

datasets = create_datasets()

# Bloom Filter Implementation
def get_bigrams(password):
    return [password[i:i+2] for i in range(len(password) - 1)]

def get_hashes(bigram):
    return [int(g(bigram + str(i))[:4], 16) % BIT_ARRAY_SIZE for i in range(K)] + \
           [int(h(bigram + str(i))[:4], 16) % BIT_ARRAY_SIZE for i in range(K)]

def create_bloom_filter(password):
    bit_array = bitarray.bitarray(BIT_ARRAY_SIZE)
    bit_array.setall(0)
    bigrams = get_bigrams(password)
    for bigram in bigrams:
        for hash_value in get_hashes(bigram):
            bit_array[hash_value] = 1
    return bit_array

def create_beta_files(datasets):
    for (dataset_name, passwords), beta_file in zip(datasets, BETA_FILES):
        with open(beta_file, 'w') as file:
            for password in passwords:
                bloom_filter = create_bloom_filter(password)
                file.write(f"{password}\t{bloom_filter.to01()}\n")

create_beta_files(datasets)

# Jaccard Similarity Calculation
def jaccard_similarity(filter1, filter2):
    intersection = (filter1 & filter2).count()
    union = (filter1 | filter2).count()
    return intersection / union

# Threshold justification (empirical value based on experiments or domain knowledge)
THRESHOLD = 0.3

# Reading Beta Files and Checking Similarity
def read_beta_files(beta_files):
    filters = []
    for file_path in beta_files:
        with open(file_path, 'r') as file:
            for line in file:
                parts = line.strip().split('\t')
                if len(parts) == 2:
                    password = parts[0]
                    bit_array_str = parts[1]
                    if all(c in '01' for c in bit_array_str):
                        try:
                            bit_array = bitarray.bitarray(bit_array_str)
                            filters.append((password, bit_array))
                        except ValueError as e:
                            print(f"Error parsing bit array for password {password}: {e}")
                    else:
                        print(f"Invalid characters found in bit array for password {password}: {bit_array_str}")
                else:
                    print(f"Skipping invalid line: {line.strip()}")
    return filters

def check_password_similarity_from_files(p1, p2, beta_files):
    filters = read_beta_files(beta_files)
    
    p1_found = False
    p2_found = False
    p1_filter = None
    p2_filter = None
    
    # Check for both passwords in all filters
    for password, bloom_filter in filters:
        if password == p1:
            p1_found = True
            p1_filter = bloom_filter
        if password == p2:
            p2_found = True
            p2_filter = bloom_filter
        
        # Exit loop early if both are found
        if p1_found and p2_found:
            break
    
    # Check if each password was found
    if not p1_found and not p2_found:
        print(f"Passwords '{p1}' and '{p2}' not found in the datasets.")
        return False, 0.0
    elif not p1_found:
        print(f"Password '{p1}' not found in the datasets.")
        return False, 0.0
    elif not p2_found:
        print(f"Password '{p2}' not found in the datasets.")
        return False, 0.0
    
    # Calculate similarity if both passwords are found
    similarity = jaccard_similarity(p1_filter, p2_filter)
    return similarity >= THRESHOLD, similarity

def main():
    dataset_filters = {beta_file: read_beta_files([beta_file]) for beta_file in BETA_FILES}
    
    # Allow user to enter another password for comparison
    print()
    user_password = input("Enter any password of your choice: ")
    user_bloom_filter = create_bloom_filter(user_password)
    
    found_similar = False
    similarity_results_by_dataset = {dataset_name: [] for dataset_name, _, _ in DATASETS}
    comparison_times = {}
    
    for (dataset_name, _, _), beta_file in zip(DATASETS, BETA_FILES):
        start_time = time.time()
        filters = dataset_filters[beta_file]
        for password, bloom_filter in filters:
            similarity = jaccard_similarity(user_bloom_filter, bloom_filter)
            similarity_results_by_dataset[dataset_name].append((password, similarity))
            if similarity >= THRESHOLD:
                found_similar = True
        end_time = time.time()
        comparison_times[dataset_name] = end_time - start_time
    
    if found_similar:
        print("The password is common and rejected. The similar passwords and their similarity scores are displayed in the table below:")
    else:
        print(f"The password '{user_password}' is not common and is acceptable. There are no similar passwords as displayed in the table below:")
    
    print()
    
    for dataset_name in similarity_results_by_dataset:
        results = similarity_results_by_dataset[dataset_name]
        
        # Highlight similar passwords in red
        for i, (password, similarity) in enumerate(results):
            if similarity >= THRESHOLD:
                results[i] = (f"{RED}{password}{ENDC}", f"{similarity:.3f}")
            else:
                results[i] = (password, f"{similarity:.3f}")
        
        headers = ["Password", "Similarity", "Password", "Similarity", "Password", "Similarity"]
        formatted_results = []
        for i in range(0, len(results), 3):
            row = []
            for j in range(3):
                if i + j < len(results):
                    row.extend([results[i + j][0], results[i + j][1]])
                else:
                    row.extend(["", ""])
            formatted_results.append(row)
        
        print(f"{dataset_name}:")
        print(f"Comparison of the user password with {dataset_name} took {comparison_times[dataset_name]:.4f} seconds")
        print(tabulate(formatted_results, headers, tablefmt="grid"))
        print()

    # Get user input for password1 and password2
    print("Check if the two passwords from any datasets are similar or not:")
    password1 = input("Enter password 1 from any dataset: ")
    password2 = input("Enter password 2 from any dataset: ")
    
    # Check if both passwords are in the datasets
    p1_found = False
    p2_found = False
    for beta_file in BETA_FILES:
        filters = dataset_filters[beta_file]
        for password, _ in filters:
            if password == password1:
                p1_found = True
            if password == password2:
                p2_found = True
            if p1_found and p2_found:
                break
        if p1_found and p2_found:
            break
    
    # Print error message if both passwords are not found
    if not p1_found and not p2_found:
        print(f"Passwords '{password1}' and '{password2}' not found in the datasets.")
    else:
        # Print individual error messages if one password is not found
        if not p1_found:
            print(f"Password '{password1}' not found in the datasets.")
        if not p2_found:
            print(f"Password '{password2}' not found in the datasets.")
        
        # Check if both passwords are found before proceeding with similarity check
        if p1_found and p2_found:
            similarity_check, similarity_score = check_password_similarity_from_files(password1, password2, BETA_FILES)
            
            if similarity_check:
                print(f"Passwords '{password1}' and '{password2}' are similar with a similarity score of {similarity_score:.3f}")
            else:
                print(f"Passwords '{password1}' and '{password2}' are not similar.")

if __name__ == "__main__":
    main()

