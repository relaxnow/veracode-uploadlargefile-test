import os
import sys
import requests
import configparser
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

def parse_veracode_credentials(file_path: str) -> dict:
    config = configparser.ConfigParser()
    config.read(file_path)

    credentials = {}
    if 'default' in config:
        credentials['veracode_api_key_id'] = config['default'].get('veracode_api_key_id', None)
        credentials['veracode_api_key_secret'] = config['default'].get('veracode_api_key_secret', None)

    return credentials

def main(file_path: str, app_id: str):
    credentials_file = os.path.expanduser('~/.veracode/credentials')
    if not os.path.exists(credentials_file):
        print(f"Credentials file does not exist: {credentials_file}")
        return

    credentials = parse_veracode_credentials(credentials_file)
    if credentials:
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
    else:
        print("Failed to parse Veracode credentials")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <file_path> <app_id>")
        sys.exit(1)

    file_path = sys.argv[1]
    app_id = sys.argv[2]
    main(file_path, app_id)
