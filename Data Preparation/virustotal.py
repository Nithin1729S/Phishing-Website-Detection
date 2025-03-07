import os
import random
from datetime import datetime
import dotenv
import pandas as pd
import requests
import time

def check_url_virustotal(url, default_label):
    endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": os.getenv("VIRUS_TOTAL_API_KEY")}  
    try:
        response = requests.post(endpoint, headers=headers, data={"url": url})
        if response.status_code != 200:
            return default_label  
        analysis_id = response.json()["data"]["id"]
        result_endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        result_response = requests.get(result_endpoint, headers=headers)
        if result_response.status_code != 200:
            return default_label 
        result_data = result_response.json()["data"]["attributes"]["results"]
        malicious_count = sum(1 for scan in result_data.values() if scan["category"] == "malicious")
        return "bad" if malicious_count > 0 else "good"
    except Exception:
        return default_label 

def load_progress():
    if os.path.exists("progress.txt"):
        with open("progress.txt", "r") as f:
            return int(f.read().strip())
    return 0

def save_progress(index):
    with open("progress.txt", "w") as f:
        f.write(str(index))

def generate_classification_report(df, total_samples=500):
    random.seed(42)
    available_indices = list(df.index)  
    random.shuffle(available_indices) 
    selected_indices = available_indices[:total_samples]

    start_index = load_progress()
    mis_match_count = 0  

    with open('virustotal_classification_report_1.txt', 'a') as report_file, open('mismatches.txt', 'a') as mismatch_file:
        for serial, index in enumerate(selected_indices[start_index:], start=start_index + 1):  
            entry = df.loc[index]
            original_label = entry['Label']
            updated_label = check_url_virustotal(entry['URL'], original_label) 
            analysis_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            match_status = "Match" if original_label == updated_label else "Not Match"

            if match_status == "Not Match":
                mis_match_count += 1
                mismatch_file.write(f"{serial} | {index} | {entry['URL']} | Original: {original_label} -> New: {updated_label} | {analysis_timestamp}\n")
                mismatch_file.flush()  

            df.at[index, 'Label'] = updated_label  
            report_file.write(f"{serial:<5} | {index:<10} | {entry['URL'][:40]:<40} | {original_label:<15} | {updated_label:<20} | {match_status:<12} | {analysis_timestamp}\n")
            report_file.flush()  

            print(f"[{serial}/{total_samples}] Checked URL: {entry['URL']}")
            print(f"Original Label: {original_label} -> Updated Label: {updated_label} | {match_status}")
            print(f"Analysis Timestamp: {analysis_timestamp}\n")

            df.to_csv("phishing_site_urls_dataset.csv", index=False)  
            save_progress(serial)  

            if serial < total_samples:
                time.sleep(60)  

        report_file.write("-" * 150 + "\n")
        print(f"Completed {total_samples} checks.")
        print(f"Total mismatches stored: {mis_match_count}")

def main():
    dotenv.load_dotenv() 
    df = pd.read_csv("phishing_site_urls_dataset.csv")  
    generate_classification_report(df, total_samples=500)  

if __name__ == "__main__":
    main()
