import requests, time, os, argparse, re 

# Parser
msg = "This is a python script to upload files to scan in PolySwarm and Show the scan results\
    - use /usr/bin/python3 binary to start executing the script"

# Initialize parser
parser = argparse.ArgumentParser(description = msg)

parser.add_argument("-f", "--file", help = "path of the file to be uploaded")
parser.add_argument("-sha256", "--sha256", help = "sha256 value to be entered")
# parser.add_argument("-o", "--output", help = "Output the results")

args = parser.parse_args()

# Main functions start.
def print_dict(val):
    for i in val:
        if isinstance(val[i], dict):
            print_dict(val[i])

        elif isinstance(val[i], list):
            print_list(val[i])
                
        else:
            print(f"{i}: {val[i]}")
            # return f"{i}, {val[i]}"


def print_list(val):
    for i in val:
        if isinstance(i, dict):
            print_dict(i)

        elif isinstance(i, list):
            print_list(i)

        else:
            print(f"\nDICTIONARY: {i}\n")
            # return f"\nDICTIONARY,{i}\n"

def pulling_dict(val):
    for i in val:
        if isinstance(val[i], dict):
            pulling_dict(val[i])

        elif isinstance(val[i], list):
            pulling_list(val[i])
                
        else:
            # print(f"{i}, {val[i]}")
            # return (f"{i}, {val[i]}")
            writer.write(f'{i}, \"{val[i]}\"\n')

def pulling_list(val):
    for i in val:
        if isinstance(i, dict):
            pulling_dict(i)

        elif isinstance(i, list):
            pulling_list(i)

        else:
            # print(f"\nDICTIONARY,{i}\n")
            # return (f"\nDICTIONARY,{i}\n")
            writer.write(f"{i} \n")

try_again = 1
post_result = 0
sha256 = 0

if(not args.sha256):
    print("Trying to upload file...")
    while try_again <= 3:
        f = open(args.file, 'rb')
        files = {'file': f}

        url = "https://portal-backend.k.polyswarm.network/api/v1/submission"


        r = requests.post(url, files=files)

        print("Uploading file...")

        print(f"Status code: {r.status_code} ")

        if(r.status_code == 200):

            print("Successfully Uploaded file...")
            post_result = r.json()
            break

        else:
            print(f"Failed to upload... Trying again ({try_again}/3)")
            try_again+=1

        # with open('json_dump/post_result.json', 'w') as write:
        #     json.dump(r.json(), write)

    sha256 = post_result["result"]["sha256"]

else:
    def hash_is_sha256(hash) -> bool:
        return len(hash) == 64

    if not hash_is_sha256(args.sha256):
        print("\nThe given hash is not a sha256 hash. Please enter a valid 256 hash")
        exit()
    else:
        print("Valid hash has been supplied so skipping file upload.")
        sha256 = args.sha256


# sha256 value of a RAT file
# sha256 = "c73fd1810d771974cff5f436a14f76cb3cbeb442baf97f3553ba99cf118bc337"

url = f"https://portal-backend.k.polyswarm.network/api/v1/submission/hash/sha256/{sha256}"

print("\nFeeding file's SHA256 hash to PolySwarm...")

r = requests.get(url)

print(f"Status code: {r.status_code}")

if(r.status_code == 200):

    print("\nFetching results...\n")

hash_result = r.json()["result"]["assertions"]

def print_results():

    for i in hash_result:
        print(f"    Vendor: {i['author_name']} | Malicous: {i['verdict']}")

    print("\nPolySwarm Attributes:")
    print(f"    Polyscore: {r.json()['result']['polyscore']}\n")

    print("Artifact Attributes:")
    print(f"    File Name: {r.json()['result']['filename']}")
    print(f"    File Type: {r.json()['result']['type']}")
    print(f"    File Size: {r.json()['result']['size']} Bytes")
    print(f"    Sha256   : {r.json()['result']['sha256']}")
    print(f"    MD5      : {r.json()['result']['md5']}")
    print(f"    Mime Type: {r.json()['result']['mimetype']}")

print_results()

# with open('json_dump/hash_result.json', 'w') as write:
#     json.dump(r.json(), write)
if input("\nWould you like to print the full ouput (Y/N): ").lower() == 'y':
    print_dict(r.json())

if input("\nWould you like to save the rough ouput to a csv file? (Y/N): ").lower() == 'y':

    try: 

        with open(f"{r.json()['result']['filename']}_polyswarm_output.csv", 'w') as write:

            write.write("file name, type, size, PolyScore, SHA256, MD5, MIME-TYPE")

            write.write(f"\n{r.json()['result']['filename']},{r.json()['result']['type']},{r.json()['result']['size']},{r.json()['result']['polyscore']},{r.json()['result']['sha256']},{r.json()['result']['md5']},{r.json()['result']['mimetype']}")

            write.write("\n\nvendor,verdict")

            for i in hash_result:
                write.write(f"\n{i['author_name']},{i['verdict']}")
        print(f"File saved to {os.getcwd()}/{r.json()['result']['filename']}_polyswarm_output.csv\n")

    except:

        print("!!! Something went wrong when writing to the file.")

else:
    print("File not saved.\n")

if input("\nWould you like to save the full ouput to a csv file? (Y/N): ").lower() == 'y':

    try:
        # with open(f"{r.json()['result']['filename']}_polyswarm_full_output.csv", 'w') as f:
        #     f.write(f"{pulling_dict(r.json())}")
        writer = open('full_output.csv', 'w')
        pulling_dict(r.json())
        writer.close()
        print(f"File saved to {os.getcwd()}/{r.json()['result']['filename']}_polyswarm_output.csv\n")

    except:
        print("!!! Something went wrong when writing to the file.")

else:
    print("File not saved.\n")


if input("Would you like to search for results of a specific vendor? (Y/N): ").lower() == 'y':
    while 1:
        search = input("\nEnter the name of the vendor (Enter 0 to stop specific vendor search): ").lower()
        if search == '0':
            break
        check = 1
        for i in hash_result:

            if re.findall(f"{search}", str(i['author_name']).lower()):

                print('\n')
                print_dict(i)

                check = 0
                break
        if check == 1:
            print(f"No such vendor was found in the name {search}")

