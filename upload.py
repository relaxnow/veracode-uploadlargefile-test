import os
import sys
import requests
import configparser
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

def parse_veracode_credentials(file_path: str) -> dict:
    config = configparser.ConfigParser()
    config.read(file_path)

    if 'default' not in config:
        raise ValueError(f"Section 'default' not found in the credentials file: {file_path}")

    credentials = {
        'veracode_api_key_id': config['default'].get('veracode_api_key_id'),
        'veracode_api_key_secret': config['default'].get('veracode_api_key_secret')
    }
    
    if not credentials['veracode_api_key_id'] or not credentials['veracode_api_key_secret']:
        raise ValueError("Credentials file is missing required API key ID or secret")

    return credentials

def main(file_path: str, app_id: str):
    if not app_id.isdigit():
        raise ValueError("App ID must be numeric")
        
    credentials_file = os.path.expanduser('~/.veracode/credentials')
    if not os.path.exists(credentials_file):
        print(f"Credentials file does not exist: {credentials_file}")
        sys.exit(1)

    try:
        credentials = parse_veracode_credentials(credentials_file)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    if not os.path.exists(file_path):
        print(f"File does not exist: {file_path}")
        sys.exit(1)

    print(f"Veracode API Key ID: {credentials.get('veracode_api_key_id')}")

    try:
        file_size = os.path.getsize(file_path)
        base_filename = os.path.basename(file_path)
        with open(file_path, 'rb') as file:
            headers = {
                'Content-Type': 'binary/octet-stream',
                'Content-Length': str(file_size)
            }
            resp = requests.post(
                'https://analysiscenter.veracode.com/api/5.0/uploadlargefile.do',
                headers=headers,
                params={'app_id': app_id, 'filename': base_filename},
                data=file,
                auth=RequestsAuthPluginVeracodeHMAC(
                    credentials['veracode_api_key_id'],
                    credentials['veracode_api_key_secret']
                )
            )
    except Exception as err:
        print(f'Error occurred: {err}')
        sys.exit(1)
    else:
        print(f'Req Headers: {resp.request.headers}')
        print(f'Resp Code: {resp.status_code}\nResp Text: {resp.text}')

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <file_path> <app_id>")
        sys.exit(1)

    file_path = sys.argv[1]
    app_id = sys.argv[2]
    
    try:
        main(file_path, app_id)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
