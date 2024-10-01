import os
import json
import requests

jamf_server = os.environ.get('jamf_server')
jamf_api_password = os.environ.get('jamf_api_password')
jamf_api_username = os.environ.get('jamf_api_username')


expected_signing_info = os.environ.get('expected_signing_info')
stage2_url = '{"stage2URL": "' + os.environ.get('stage2_url') +'"}'

def get_jamf_token():

    print('Getting Jamf bearer token for client computer check')
    jamf_query_url = jamf_server + "/api/v1/auth/token"
    headers = {'Accept': 'application/json', }
    response = requests.post(url=jamf_query_url, headers=headers, auth=(jamf_api_username, jamf_api_password))
    response_json = response.json()

    return response_json['token']


def invalidate_jamf_token(uapi_token):

    jamf_query_url = jamf_server + "/api/v1/auth/invalidate-token"
    headers = {'Accept': '*/*', 'Authorization': 'Bearer ' + uapi_token}
    response = requests.post(url=jamf_query_url, headers=headers)

    if response.status_code == 204:
        print('Client computer verification completed')
    else:
        print('Error invalidating Jamf bearer token.')

def jamfCheck(serialNumber):

    print('Verifying client computer is managed by our Jamf server')
    # fetch Jamf Pro (ex-universal) api token
    jamf_token = get_jamf_token()

    # fetch sample Jamf Pro api call
    headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + jamf_token}
    jamf_query_string = "/api/v1/computers-inventory?section=DISK_ENCRYPTION&page=0&page-size=100&sort=id&filter=hardware.serialNumber==" + serialNumber
    response = requests.get(url=jamf_server + jamf_query_string, headers=headers)
    response_json = response.json()

    # invalidating token
    invalidate_jamf_token(jamf_token)
    return (response_json['totalCount'])

def lambda_handler(event, context):
    decodedEvent = json.loads(event['body'])
    received_serial_number = str(decodedEvent['serialNumber'])
    received_signing_info = str(decodedEvent['signature'])
    print('Received request from computer with serial number ' + received_serial_number + ' and signing info ' + received_signing_info)
    qualified_computer = jamfCheck(received_serial_number)
    if qualified_computer == 1 and received_signing_info == expected_signing_info:
        return {
            'statusCode': 200,
            'body': stage2_url
        }
    else :
        return {
            'statusCode': 401
        }
