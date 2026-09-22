import json 

filename = "secret-logs.json"
#function to parse JSON file
def parse_read(filename):
    with open(filename, "r") as file:
        data = json.load(file)
        return data
logs = parse_read(filename)
user = logs["username"]
passw = logs["password"]
print(f"username:{user}", f"\npassword:{passw}")
