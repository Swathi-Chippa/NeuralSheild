import pandas as pd

# Load phishing website dataset
phishing_data = pd.read_csv("datasets/phishing.csv")

print("Phishing Dataset:")
print(phishing_data.head())
print("Shape:", phishing_data.shape)

print("\n-------------------\n")

# Load email dataset
email_data = pd.read_csv("datasets/emails.csv")

print("Email Dataset:")
print(email_data.head())
print("Shape:", email_data.shape)
print(phishing_data.columns)