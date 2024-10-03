import os
import ast
import uuid
import json
import requests

jamf_server = os.environ.get('jamf_server')
jamf_check_username = os.environ.get('jamf_check_username')
jamf_check_password = os.environ.get('jamf_check_password')
uuid_namespace = os.environ.get('uuid_namespace')
keyData = ast.literal_eval(os.environ.get('keyData'))
expected_signing_info = os.environ.get('expected_signing_info')

def get_jamf_check_token():

    print('Getting Jamf bearer token for client computer check')
    jamf_query_url = jamf_server + "/api/v1/auth/token"
    headers = {'Accept': 'application/json', }
    response = requests.post(url=jamf_query_url, headers=headers, auth=(jamf_check_username, jamf_check_password))
    response_json = response.json()

    return response_json['token']


def invalidate_jamf_check_token(jamf_check_token):

    jamf_query_url = jamf_server + "/api/v1/auth/invalidate-token"
    headers = {'Accept': '*/*', 'Authorization': 'Bearer ' + jamf_check_token}
    response = requests.post(url=jamf_query_url, headers=headers)

    if response.status_code == 204:
        print('Client computer verification completed')
    else:
        print('Error invalidating Jamf bearer token.')

def jamf_check(serialNumber):

    print('Verifying client computer is managed by our Jamf server')
    # fetch Jamf Pro (ex-universal) api token
    jamf_check_token = get_jamf_check_token()

    # fetch sample Jamf Pro api call
    headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + jamf_check_token}
    jamf_query_string = "/api/v1/computers-inventory?section=DISK_ENCRYPTION&page=0&page-size=100&sort=id&filter=hardware.serialNumber==" + serialNumber
    response = requests.get(url=jamf_server + jamf_query_string, headers=headers)
    response_json = response.json()

    # invalidating token
    invalidate_jamf_check_token(jamf_check_token)
    return (response_json['totalCount'])
    
def jamf_return_token_info(received_token_key):
    
    computed_token_key = str(uuid.uuid5(uuid.NAMESPACE_DNS, uuid_namespace + received_token_key))
    print ('The computed API Token Key is ' + computed_token_key)
    
    if computed_token_key in keyData:
        jamf_api_username = keyData[computed_token_key]['username']
        jamf_api_password = keyData[computed_token_key]['password']
    else:
        jamf_api_username = ""
        jamf_api_password = ""
        
    if jamf_api_username != "" and jamf_api_password != "" :
        print('Granting Jamf bearer token')
        jamf_query_url = jamf_server + "/api/v1/auth/token"
        headers = {'Accept': 'application/json', }
        response = requests.post(url=jamf_query_url, headers=headers, auth=(jamf_api_username, jamf_api_password))
        print(response.json())
        return response.json()
    else:
        return "Error"

def lambda_handler(event, context):
    
    decodedEvent = json.loads(event['body'])
    received_serial_number = str(decodedEvent['serialNumber'])
    received_signing_info = str(decodedEvent['signature'])
    received_token_key = str(decodedEvent['apiTokenKey'])
    print('Received request from computer with serial number ' + received_serial_number + ',signing info ' + received_signing_info + ' and API token key ' + received_token_key)
    qualified_computer = jamf_check(received_serial_number)
    final_jamf_token = jamf_return_token_info(received_token_key)
    if qualified_computer == 1 and received_signing_info == expected_signing_info and final_jamf_token != "Error" :
        return {
            'statusCode': 200,
            'body': json.dumps(final_jamf_token)
        }
    else:
        return {
            'statusCode': 401,
            'body': "Error"
        }
    
