import json
import numpy as np
import csv

# Function to split data into subsets and calculate the averages
def split_and_calculate_averages(data, sample_sizes):
    averages = {}
    for size in sample_sizes:
        averages[size] = np.mean(data[:size])  # Calculate the average for the first 'size' data points
    return averages

# Load data from JSON file
def load_data_from_json(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data

# Write results to a CSV file
def write_to_csv(data, file_path):
    with open(file_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Sample Size', 'Average Authentication Time'])
        for sample_size, average in data.items():
            writer.writerow([sample_size, average])

def main():
    # Load the data from the JSON file
    auth_processing_times = load_data_from_json('auth_processing_times.json')
    
    # Ensure the data is a list of values (this step depends on your JSON structure)
    if isinstance(auth_processing_times, dict):
        auth_processing_times = auth_processing_times.get('data', [])
    
    # Define the sample sizes
    sample_sizes = [10, 50, 100, 200, 300, 400, 500]
    
    # Split the data and calculate the averages
    averages = split_and_calculate_averages(auth_processing_times, sample_sizes)
    
    # Write the results to CSV
    write_to_csv(averages, 'averages_authentication_times.csv')
    print("CSV file has been created with the averages.")

# Run the main function
if __name__ == "__main__":
    main()
