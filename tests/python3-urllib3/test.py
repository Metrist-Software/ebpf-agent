
import requests                                 # To use request package in current program
response = requests.get("https://www.google.com/")
print(response.status_code)
