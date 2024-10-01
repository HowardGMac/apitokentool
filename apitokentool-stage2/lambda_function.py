import os
import ast
import uuid
import json
import requests


jamf_server = os.environ.get('jamf_server')
keyData = ast.literal_eval(os.environ.get('keyData'))

def lambda_handler(event, context):
    decodedEvent = json.loads(event['body'])
    received_token_key = str(decodedEvent['apiTokenKey'])
    print('Received request from computer with API Token Key ' + received_token_key)
    computed_token_key = str(uuid.uuid5(uuid.NAMESPACE_DNS, 'laits.utexas.edu/' + received_token_key))
    print ('The computed API Token Key is ' + computed_token_key)
    if computed_token_key in keyData:
        jamf_api_username = keyData[computed_token_key]['username']
        jamf_api_password = keyData[computed_token_key]['password']
    else:
        jamf_api_username = ""
        jamf_api_password = ""
    #print(jamf_api_username + ':' + jamf_api_password)
    if jamf_api_username != "" and jamf_api_password != "":
        print('Getting Jamf bearer token')
        jamf_query_url = jamf_server + "/api/v1/auth/token"
        headers = {'Accept': 'application/json', }
        response = requests.post(url=jamf_query_url, headers=headers, auth=(jamf_api_username, jamf_api_password))
        response_json = response.json()
        #print(response_json)
        return {
            'statusCode': 200,
            'body': json.dumps(response_json)
        }
    else :
        return {
            'statusCode': 404
        }
